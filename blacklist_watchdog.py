#!/usr/bin/env python3
"""
blacklist_watchdog.py — Standalone guardian process for the BTC 5-min bot.

Watches on-chain OrderFilled events for our proxy wallet. If a fill's counterparty
is on the blacklist (nonce exploiters), immediately places a market sell to exit
and writes an alert to data/blacklist_alerts.jsonl.

Selling, including --dry-run order-book reads, requires market.PolymarketClient
from a private trading bot. Only --no-sell works standalone.
Runs independently — does NOT modify live_trader.py.

Usage:
    python blacklist_watchdog.py --proxy-address 0x1111111111111111111111111111111111111111 --no-sell
"""
import argparse
import json
import logging
import logging.handlers
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# This tool was written to live in a subdirectory of the private trading bot.
parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))

from blacklist import get_blacklist
from counterparty_checker import (
    get_fills_for_address,
    get_counterparty,
    get_latest_block,
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
ALERTS_FILE = os.path.join(DATA_DIR, "blacklist_alerts.jsonl")
STATE_FILE = os.path.join(DATA_DIR, "watchdog_state.json")

# Polling config
POLL_INTERVAL = 2  # seconds between block checks
MAX_BLOCKS_PER_POLL = 20  # catch up at most N blocks per iteration
SELL_AGGRESSION = 0.95  # sell at 95% of best bid for fast fill

# ─── Logging ──────────────────────────────────────────────────────────────────
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("watchdog")
logger.setLevel(logging.INFO)

sh = logging.StreamHandler()
sh.setFormatter(fmt)
logger.addHandler(sh)

fh = logging.handlers.RotatingFileHandler(
    os.path.join(DATA_DIR, "blacklist_watchdog.log"), maxBytes=5_000_000, backupCount=2
)
fh.setFormatter(fmt)
logger.addHandler(fh)


# ─── CLOB sell client (lazy init) ────────────────────────────────────────────
_clob_client = None


def _get_clob_client():
    """Lazy-init a PolymarketClient for selling."""
    global _clob_client
    if _clob_client is None:
        from market import PolymarketClient
        _clob_client = PolymarketClient()
        logger.info("CLOB client initialized for emergency sells")
    return _clob_client


def emergency_sell(token_id: str, shares: float, dry_run: bool = False) -> dict:
    """
    Place an aggressive limit sell to exit a position immediately.
    Returns dict with sell details.
    """
    client = _get_clob_client()

    # Get current best bid for this token
    try:
        book = client.clob.get_order_book(token_id)
        bids = getattr(book, "bids", []) or []
        best_bid = float(bids[-1].price) if bids else 0
    except Exception as e:
        logger.error(f"Failed to get orderbook for {token_id[:16]}...: {e}")
        return {"success": False, "error": str(e)}

    if best_bid < 0.02:
        logger.warning(f"No viable bid for {token_id[:16]}... (best_bid={best_bid})")
        return {"success": False, "error": "no_bid", "best_bid": best_bid}

    sell_price = round(max(best_bid * SELL_AGGRESSION, 0.01), 2)
    sell_size = round(shares, 1)

    if sell_size < 0.1:
        return {"success": False, "error": "size_too_small", "shares": shares}

    if dry_run:
        logger.info(f"  [DRY RUN] Would sell {sell_size} @ {sell_price} (bid={best_bid})")
        return {"success": True, "dry_run": True, "price": sell_price, "size": sell_size}

    logger.info(f"  🚨 EMERGENCY SELL: {sell_size} shares @ {sell_price} (bid={best_bid})")
    order_id = client.place_limit_sell(token_id, sell_price, sell_size)

    if not order_id:
        # Retry more aggressively
        sell_price2 = round(max(best_bid * 0.85, 0.01), 2)
        logger.info(f"  🚨 RETRY SELL @ {sell_price2}")
        order_id = client.place_limit_sell(token_id, sell_price2, sell_size)

    if order_id:
        # Wait for fill
        time.sleep(3)
        fill = client.get_order_fill(order_id)
        filled = float(fill.get("size_matched", 0)) if fill else 0
        if filled < 0.1:
            # Cancel and try panic price
            client.cancel_order(order_id)
            panic_price = round(max(best_bid * 0.75, 0.01), 2)
            logger.info(f"  🚨 PANIC SELL @ {panic_price}")
            order_id2 = client.place_limit_sell(token_id, panic_price, sell_size)
            if order_id2:
                time.sleep(3)
                fill2 = client.get_order_fill(order_id2)
                filled = float(fill2.get("size_matched", 0)) if fill2 else 0
                if filled < 0.1:
                    client.cancel_order(order_id2)

        return {
            "success": filled >= 0.1,
            "order_id": order_id,
            "price": sell_price,
            "size": sell_size,
            "filled": filled,
        }

    return {"success": False, "error": "order_failed"}


def write_alert(fill: dict, counterparty: str, sell_result: dict | None = None):
    """Append alert to blacklist_alerts.jsonl."""
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "counterparty": counterparty,
        "tx_hash": fill.get("tx_hash", ""),
        "block": fill.get("block", 0),
        "maker": fill.get("maker", ""),
        "taker": fill.get("taker", ""),
        "maker_asset_id": fill.get("maker_asset_id", ""),
        "taker_asset_id": fill.get("taker_asset_id", ""),
        "maker_amount": fill.get("maker_amount", 0),
        "taker_amount": fill.get("taker_amount", 0),
        "sell_result": sell_result,
    }
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    logger.info(f"  Alert written to {ALERTS_FILE}")


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def resolve_proxy_address(cli_address: str | None, env_address: str | None) -> str:
    address = cli_address if cli_address is not None else env_address
    if not address:
        raise ValueError("Supply --proxy-address or POLYMARKET_PROXY_ADDRESS")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
        raise ValueError("Proxy address must be 0x followed by 40 hexadecimal characters")
    return address


def run(proxy_address: str, dry_run: bool = False, no_sell: bool = False):
    if not no_sell:
        try:
            _get_clob_client()
        except ImportError as exc:
            sys.exit(
                f"Cannot import {exc.name or 'market.PolymarketClient'}: {exc}. "
                "Selling and --dry-run require market.PolymarketClient from a private "
                "trading bot, which is not part of this repository. Run with --no-sell."
            )
    bl = get_blacklist()
    logger.info(
        f"Blacklist watchdog started | proxy={proxy_address} | "
        f"blacklist={bl.count} addresses | dry_run={dry_run} | no_sell={no_sell}"
    )

    state = load_state()
    last_block = state.get("last_block", 0)

    if last_block == 0:
        # Start from current block
        try:
            last_block = get_latest_block()
            logger.info(f"Starting from current block {last_block}")
        except Exception as e:
            logger.error(f"Cannot get latest block: {e}")
            return

    fills_checked = 0
    alerts_triggered = 0

    while True:
        try:
            current_block = get_latest_block()

            if current_block <= last_block:
                time.sleep(POLL_INTERVAL)
                continue

            # Process blocks in batches
            from_block = last_block + 1
            to_block = min(current_block, from_block + MAX_BLOCKS_PER_POLL - 1)

            for block_num in range(from_block, to_block + 1):
                fills = get_fills_for_address(block_num, proxy_address)

                for fill in fills:
                    fills_checked += 1
                    counterparty = get_counterparty(fill, proxy_address)
                    if not counterparty:
                        continue

                    is_bad = bl.is_blacklisted(counterparty)

                    if fills_checked % 50 == 1 or is_bad:
                        logger.info(
                            f"Fill #{fills_checked} block={block_num} "
                            f"counterparty={counterparty[:12]}... "
                            f"blacklisted={is_bad}"
                        )

                    if is_bad:
                        alerts_triggered += 1
                        logger.warning(
                            f"  🚨 BLACKLISTED COUNTERPARTY DETECTED! "
                            f"{counterparty} in tx {fill.get('tx_hash', '?')}"
                        )

                        # Determine which token we received (to sell it)
                        our = proxy_address.lower()
                        if fill["taker"].lower() == our:
                            # We're the taker — we received maker's asset
                            token_to_sell = fill.get("maker_asset_id", "")
                            shares = fill.get("maker_amount", 0) / 1_000_000  # CTF uses 6 decimals
                        else:
                            # We're the maker — we received taker's asset
                            token_to_sell = fill.get("taker_asset_id", "")
                            shares = fill.get("taker_amount", 0) / 1_000_000

                        sell_result = None
                        if not no_sell and token_to_sell and shares > 0:
                            # Convert hex token_id to decimal string for CLOB
                            token_id_dec = str(int(token_to_sell, 16))
                            logger.info(
                                f"  Token to sell: {token_id_dec[:20]}... | "
                                f"shares: {shares:.2f}"
                            )
                            sell_result = emergency_sell(
                                token_id_dec, shares, dry_run=dry_run
                            )
                            logger.info(f"  Sell result: {sell_result}")

                        write_alert(fill, counterparty, sell_result)

            last_block = to_block
            save_state({"last_block": last_block, "fills_checked": fills_checked, "alerts": alerts_triggered})

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            save_state({"last_block": last_block, "fills_checked": fills_checked, "alerts": alerts_triggered})
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
            time.sleep(10)


def main():
    parser = argparse.ArgumentParser(description="Blacklist watchdog for BTC 5-min bot")
    parser.add_argument("--dry-run", action="store_true", help="Log sells but don't execute")
    parser.add_argument("--no-sell", action="store_true", help="Only alert, don't sell")
    parser.add_argument("--proxy-address", help="Proxy wallet address (or POLYMARKET_PROXY_ADDRESS)")
    args = parser.parse_args()
    try:
        proxy_address = resolve_proxy_address(args.proxy_address, os.environ.get("POLYMARKET_PROXY_ADDRESS"))
    except ValueError as exc:
        parser.error(str(exc))
    run(proxy_address, dry_run=args.dry_run, no_sell=args.no_sell)


if __name__ == "__main__":
    main()
