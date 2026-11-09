from datetime import datetime, timezone
import json
import socket

from hexbytes import HexBytes
import pytest

import alerts
import blacklist
import counterparty_checker as checker
from nonce_monitor import get_btc_window, NonceStats


@pytest.mark.parametrize("timestamp,start,end,elapsed,remaining", [
    ("2026-01-01T00:00:00", "00:00:00", "00:05:00", 0, 300),
    ("2026-01-01T00:04:59", "00:00:00", "00:05:00", 299, 1),
    ("2026-01-01T00:05:00", "00:05:00", "00:10:00", 0, 300),
    ("2026-01-01T23:59:59.500", "23:55:00", "00:00:00", 299.5, 0.5),
])
def test_btc_window(timestamp, start, end, elapsed, remaining):
    ts = datetime.fromisoformat(timestamp).replace(tzinfo=timezone.utc).timestamp()
    assert get_btc_window(ts) == {
        "window_start": start, "window_end": end,
        "elapsed_secs": elapsed, "remaining_secs": remaining,
        "pct_elapsed": round(elapsed / 300 * 100, 1),
    }


def test_stats(capsys):
    stats = NonceStats()
    stats.print_summary()
    assert capsys.readouterr().out == ""
    events = [
        {"caller": caller, "timestamp": stamp, "window": {"remaining_secs": remaining}}
        for caller, stamp, remaining in [
            ("0xAb", "2026-01-01T00:00:00", 10),
            ("0xAb", "2026-01-01T00:01:00", 100),
            ("0xCd", "2026-01-01T01:00:00", 200),
        ]
    ]
    for event in events:
        stats.add(event)
    assert stats.events == events
    assert stats.by_address == {"0xAb": events[:2], "0xCd": events[2:]}
    assert stats.hourly_counts == {"2026-01-01T00": 2, "2026-01-01T01": 1}
    assert stats.window_timing == [10, 100, 200]
    stats.print_summary()
    assert "3 events captured" in capsys.readouterr().out


def test_blacklist(tmp_path, monkeypatch):
    events = tmp_path / "events.jsonl"
    manual = tmp_path / "manual.txt"
    monkeypatch.setattr(blacklist, "NONCE_EVENTS_FILE", events)
    monkeypatch.setattr(blacklist, "MANUAL_BLACKLIST_FILE", manual)
    bl = blacklist.Blacklist()
    assert bl.count == 0
    events.write_text('{"caller": "0xAbCd"}\ninvalid json\n\n{"caller": "0xDeF"}\n')
    manual.write_text("# comment\n\n  0xABCD  \n0xFfF\n")
    bl.refresh()
    assert bl.count == 3
    assert bl.is_blacklisted("  0xaBcD  ")
    assert not bl.is_blacklisted("0x000")
    copy = bl.addresses
    copy.clear()
    assert bl.count == 3
    manual.write_text("0x111\n")
    monkeypatch.setattr(bl, "_last_refresh", 0)
    assert bl.is_blacklisted("0x111")
    assert not bl.is_blacklisted("0xFFF")


@pytest.mark.parametrize("topic_type", [bytes, HexBytes])
@pytest.mark.parametrize("hex_data", [False, True])
def test_parse_order_filled(topic_type, hex_data):
    data = b"".join(n.to_bytes(32, "big") for n in [0, 123, 456, 789, 10])
    log = {
        "topics": [topic_type(bytes(32)), topic_type(bytes(32)),
                   topic_type(bytes.fromhex("00" * 12 + "11" * 20)),
                   topic_type(bytes.fromhex("00" * 12 + "22" * 20))],
        "data": "0x" + data.hex() if hex_data else data,
    }
    assert checker.parse_order_filled_log(log) == {
        "maker": "0x" + "11" * 20, "taker": "0x" + "22" * 20,
        "maker_asset_id": "0x0", "taker_asset_id": "0x7b",
        "maker_amount": 456, "taker_amount": 789, "fee": 10,
    }
    log["data"] = "0x00" if hex_data else b"\x00"
    assert checker.parse_order_filled_log(log) == {
        "maker": "0x" + "11" * 20, "taker": "0x" + "22" * 20,
    }
    assert checker.parse_order_filled_log({"topics": []}) is None


@pytest.mark.parametrize("ours,expected", [("0xAB", "0xCd"), ("0xcd", "0xAb"), ("0x00", None)])
def test_counterparty(ours, expected):
    assert checker.get_counterparty({"maker": "0xAb", "taker": "0xCd"}, ours) == expected


def test_make_alert():
    alert = alerts.make_alert(alerts.NONCE_INCREMENT, alerts.INFO, "test", {"caller": "0xAb"})
    assert alert["version"] == 1
    assert datetime.fromisoformat(alert.pop("timestamp")).tzinfo is not None
    assert alert == {
        "version": 1, "code": alerts.NONCE_INCREMENT, "severity": alerts.INFO,
        "source": "test", "data": {"caller": "0xAb"},
    }


def test_alert_bus(tmp_path, capsys, caplog):
    path = tmp_path / "alerts.jsonl"
    bus = alerts.AlertBus(file_path=str(path), stdout=True)
    received = []

    def broken(alert):
        raise ValueError("subscriber failed")

    bus.subscribe(broken)
    bus.subscribe(received.append)
    first = bus.emit(alerts.NONCE_INCREMENT, alerts.INFO, "test", {})
    assert received == [first]
    assert "subscriber failed" in caplog.text
    bus.unsubscribe(received.append)
    second = bus.emit(alerts.SUSPICIOUS_TIMING, alerts.WARNING, "test", {})
    assert received == [first]
    assert [json.loads(line) for line in path.read_text().splitlines()] == [first, second]
    assert [json.loads(line) for line in capsys.readouterr().out.splitlines()] == [first, second]


def test_network_guard():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="Network access forbidden"):
            sock.connect(("127.0.0.1", 9))
