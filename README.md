![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white) ![Polygon](https://img.shields.io/badge/Polygon-PoS-8247E5?logo=polygon&logoColor=white) [![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE) [![CI](https://github.com/TheOneWhoBurns/polymarket-nonce-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/TheOneWhoBurns/polymarket-nonce-guard/actions/workflows/ci.yml)

# Polymarket Nonce Guard 🛡️

Detect and defend against the **nonce race exploit** on Polymarket's CTF Exchange.

## The Exploit

Exploiters on Polymarket call `incrementNonce()` on the [CTF Exchange contract](https://polygonscan.com/address/0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E) to invalidate their losing orders before the operator can settle them. This means:

- They place bets on both sides of a market
- When the outcome becomes clear, they cancel the losing side via `incrementNonce()`
- The winning side settles normally → risk-free profit
- **You** end up holding shares that were supposed to be matched but never settle ("ghost fills")

First publicly disclosed [Feb 19, 2026 by @itslirrato on X](https://x.com/itslirrato).

## Tools

### `nonce_monitor.py` — Real-time incrementNonce watcher
Polls Polygon blocks every 2s, filters for `incrementNonce()` calls (method sig `0x627cdcb9`) to the CTF Exchange. Logs every event with timing relative to BTC 5-min market windows.

```bash
python nonce_monitor.py
```

Output: `data/nonce_events.jsonl` — append-only log of every detected call with caller address, tx hash, block, gas price, and market window timing.

### `blacklist.py` — Exploiter address database
Loads known exploiter addresses from `nonce_events.jsonl` + a manual `data/blacklist_manual.txt`. Refreshes on lookup when at least 60s have elapsed. Every address that has ever called `incrementNonce()` is treated as an exploiter, although the call is also a legitimate cancel-all, so expect false positives.

```python
from blacklist import Blacklist
bl = Blacklist()
bl.is_blacklisted("0x1234...")  # True/False
```

### `counterparty_checker.py` — On-chain fill analysis
Fetches CTF Exchange OrderFilled logs by block and parses maker/taker addresses from settled orders.

```python
from counterparty_checker import get_fills_for_address, get_counterparty

our_address = "0x1111111111111111111111111111111111111111"
block_number = 12345678  # replace with the block to inspect
for fill in get_fills_for_address(block_number, our_address):
    counterparty = get_counterparty(fill, our_address)
    print(counterparty)
```

### `manipulation_detector.py` — Orderbook anomaly detector
Reference code for monitoring orderbook changes against BTC price movements. It requires `config`, `market`, and `price_feed` from a private trading bot; these are not included, and this file is not runnable standalone.

### `alerts.py` — Alert format and dispatcher
Provides `make_alert`, `AlertBus`, and a lazy default bus via `emit`. The nonce monitor emits `NEW_EXPLOITER`, `NONCE_INCREMENT`, or `SUSPICIOUS_TIMING` alerts to `data/alerts.jsonl`. Optional outputs include stdout, in-process callbacks, a Unix socket, and an HTTP webhook. The watchdog writes its own separate alert file.

```python
from alerts import AlertBus

bus = AlertBus(file=False, stdout=True)
bus.subscribe(lambda alert: print(alert["code"]))
bus.emit(code="NONCE_INCREMENT", severity="info", source="example", data={})
```

### `blacklist_watchdog.py` — Blacklisted counterparty watcher
Polls on-chain fills for a configured proxy wallet and writes alerts when a counterparty is blacklisted. Run standalone in alert-only mode:

```bash
python blacklist_watchdog.py --proxy-address 0x1111111111111111111111111111111111111111 --no-sell
```

Replace the fake address with your proxy wallet. `--proxy-address` takes precedence over `POLYMARKET_PROXY_ADDRESS`:

```bash
export POLYMARKET_PROXY_ADDRESS=0x1111111111111111111111111111111111111111
python blacklist_watchdog.py --no-sell
```

An address is required and must be `0x` followed by 40 hexadecimal characters. Without `--no-sell`, the watchdog attempts emergency sells and requires the private `market.PolymarketClient` module. `--dry-run` skips order placement but still initializes that client and reads the order book. Thus only `--no-sell` works standalone; it still needs Polygon RPC access.

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.10+ and web3.py 6 or newer. The on-chain tools require a Polygon RPC endpoint. Default: `https://polygon-bor-rpc.publicnode.com`

### What runs standalone

| Tool | Standalone? |
| --- | --- |
| `nonce_monitor.py`, `blacklist.py`, `counterparty_checker.py`, `alerts.py` | Yes |
| `blacklist_watchdog.py --no-sell` | Yes (alerts only) |
| `blacklist_watchdog.py` with selling or `--dry-run` | No, needs a private `market` module |
| `manipulation_detector.py` | No, needs private `config`, `market` and `price_feed` modules |

## Configuration

The only environment variable read directly by this repository is `POLYMARKET_PROXY_ADDRESS`, used by the watchdog when `--proxy-address` is absent. Other settings are constants near the top of each file:

- `nonce_monitor.py`: `CTF_EXCHANGE`, `INCREMENT_NONCE_SIG`, `HTTP_RPCS`, `POLL_INTERVAL`, `DATA_DIR`, `EVENTS_FILE`.
- `blacklist.py`: `NONCE_EVENTS_FILE`, `MANUAL_BLACKLIST_FILE`, `REFRESH_INTERVAL`.
- `counterparty_checker.py`: `POLYGON_RPC`, `CTF_EXCHANGE`, `ORDER_FILLED_TOPIC`.
- `alerts.py`: `ALERTS_FILE`, `SOCKET_PATH`, `ALERT_VERSION`; output options are also `AlertBus` constructor arguments.
- `blacklist_watchdog.py`: `POLL_INTERVAL`, `MAX_BLOCKS_PER_POLL`, `SELL_AGGRESSION`, `DATA_DIR`, `ALERTS_FILE`, `STATE_FILE`.
- `manipulation_detector.py` (private bot required): `POLL_INTERVAL`, `ALERT_COOLDOWN`, `HISTORY_SIZE`, `PRICE_JUMP_THRESHOLD`, `BTC_MOVE_THRESHOLD_PCT`, `DEPTH_DROP_PCT`, `DEPTH_DROP_WINDOW`, `DIVERGENCE_THRESHOLD`, `VOLUME_VANISH_THRESHOLD`, `COUNTER_TRADE_SIZE`, `COUNTER_TRADE_EDGE`, `DATA_DIR`, `ALERT_LOG`.

## Data

Default files written under `data/`:

- `nonce_events.jsonl` — nonce monitor events.
- `alerts.jsonl` — default alert bus output.
- `blacklist_alerts.jsonl` — watchdog alerts and sell results.
- `watchdog_state.json` — watchdog progress across restarts.
- `blacklist_watchdog.log`, `.log.1`, `.log.2` — watchdog logs (the active log is opened on import).
- `manipulation_alerts.jsonl` — private-bot detector alerts.
- `manipulation_detector.log`, `.log.1`, `.log.2`, `.log.3` — private-bot detector logs.

`data/blacklist_manual.txt` is an optional user-maintained input, one address per line; blank lines and lines beginning with `#` are ignored. Runtime files are ignored by Git. Optional alert bus outputs can write elsewhere.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest
```

Tests are offline: RPC behavior is faked, file outputs use temporary directories, and a fixture blocks non-Unix socket connections. CI runs lint and tests on Python 3.10–3.13.

Because nothing in CI talks to a chain, behaviour against live Polygon data is only checked by hand. The tests cover the parsing, filtering and classification logic using the object types web3 returns.

## How to Defend Your Bot

1. **Run `nonce_monitor.py`** alongside your trading bot to build a blacklist
2. **After each fill**, use `counterparty_checker.py` to identify who you traded with
3. **If blacklisted**, immediately sell your position (take small spread loss vs total ghost fill loss)
4. **Report repeat offenders** to Polymarket with on-chain evidence — they have CFTC regulatory pressure to act

## Key Insight

`incrementNonce()` is a **nuclear option** — it invalidates ALL pending orders from the caller's address, not just one. The CLOB API's cancel endpoint is surgical (cancels specific orders). Exploiters who use `incrementNonce` are leaving clear on-chain fingerprints.

## License

[MIT](./LICENSE)
