import asyncio
import json

from hexbytes import HexBytes
import pytest
from web3.datastructures import AttributeDict

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
            self.middleware_onion = self

        def inject(self, middleware, layer=None):
            pass

        def is_connected(self):
            return False

    monkeypatch.setattr(nonce_monitor, "Web3", FakeWeb3)
    with pytest.raises(SystemExit) as exc:
        asyncio.run(nonce_monitor.main())
    assert exc.value.code == 1
    assert "Could not connect to any Polygon RPC" in capsys.readouterr().out


CALLER = "0x1111111111111111111111111111111111111111"
TX_HASH = "0x" + "ab" * 32


def make_tx(to=nonce_monitor.CTF_EXCHANGE, data="0x627cdcb9"):
    """A transaction shaped the way web3 returns it: AttributeDict with HexBytes fields."""
    return AttributeDict({
        "from": CALLER, "to": to, "input": HexBytes(data),
        "hash": HexBytes(TX_HASH), "gasPrice": 30_500_000_000,
    })


def test_find_nonce_events_in_a_web3_block():
    # 2026-01-01T00:04:30Z, 30 seconds before the end of a 5-minute window.
    block = AttributeDict({"timestamp": 1767225870, "transactions": [
        make_tx(),
        make_tx(to="0x2222222222222222222222222222222222222222"),  # another contract
        make_tx(data="0xa9059cbb" + "00" * 64),  # another method on the exchange
        make_tx(to=None, data="0x6080"),  # contract creation
        HexBytes(TX_HASH),  # what a block holds without full_transactions
    ]})

    assert nonce_monitor.find_nonce_events(block, 123) == [{
        "timestamp": "2026-01-01T00:04:30+00:00",
        "caller": CALLER,
        "tx_hash": TX_HASH,
        "block": 123,
        "gas_price_gwei": 30.5,
        "window": nonce_monitor.get_btc_window(1767225870),
        "source": "confirmed",
    }]


def test_find_nonce_events_accepts_plain_dicts_and_extra_calldata():
    tx = {"from": CALLER, "to": nonce_monitor.CTF_EXCHANGE.lower(),
          "input": "0x627cdcb9" + "00" * 4, "hash": TX_HASH, "gasPrice": 0}

    events = nonce_monitor.find_nonce_events({"timestamp": 1767225870, "transactions": [tx]}, 7)

    assert [(e["caller"], e["tx_hash"], e["block"]) for e in events] == [(CALLER, TX_HASH, 7)]


@pytest.mark.parametrize("value,expected", [
    (HexBytes("0x627cdcb9"), "0x627cdcb9"), (b"\x00\xff", "0x00ff"), (b"", "0x"),
    ("0xabc", "0xabc"), (None, "0x"),
])
def test_to_hex(value, expected):
    assert nonce_monitor.to_hex(value) == expected
