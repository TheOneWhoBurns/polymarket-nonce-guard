import asyncio
import json

import pytest

import alerts
import nonce_monitor


def test_event_classification(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(nonce_monitor, "EVENTS_FILE", path)
    emitted = []
    monkeypatch.setattr(alerts, "emit", lambda **alert: emitted.append(alert))
    stats = nonce_monitor.NonceStats()
    for remaining in (30, 60, 29):
        nonce_monitor.log_event({
            "caller": "0xAbCd", "timestamp": "2026-01-01T00:00:00Z",
            "tx_hash": "0x1234", "window": {
                "window_start": "00:00:00", "window_end": "00:05:00",
                "remaining_secs": remaining,
            },
        }, stats)
    assert [a["code"] for a in emitted] == [
        alerts.NEW_EXPLOITER, alerts.NONCE_INCREMENT, alerts.SUSPICIOUS_TIMING,
    ]
    assert [a["severity"] for a in emitted] == [alerts.INFO, alerts.INFO, alerts.WARNING]
    assert len([json.loads(line) for line in path.read_text().splitlines()]) == 3


def test_no_rpc_connected(monkeypatch, capsys):
    class FakeWeb3:
        HTTPProvider = staticmethod(lambda *args, **kwargs: None)

        def __init__(self, provider):
            pass

        def is_connected(self):
            return False

    monkeypatch.setattr(nonce_monitor, "Web3", FakeWeb3)
    with pytest.raises(SystemExit) as exc:
        asyncio.run(nonce_monitor.main())
    assert exc.value.code == 1
    assert "Could not connect to any Polygon RPC" in capsys.readouterr().out
