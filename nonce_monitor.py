#!/usr/bin/env python3
"""
nonce_monitor.py — Real-time incrementNonce() monitor for Polymarket CTF Exchange on Polygon.

Watches for incrementNonce() calls (0x627cdcb9) on the CTF Exchange contract,
logs caller, timing relative to BTC 5-min windows, and tracks statistics.

Runs standalone alongside manipulation_detector.py.
"""

import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from web3 import Web3

# ─── Config ───────────────────────────────────────────────────────────────────
CTF_EXCHANGE = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
INCREMENT_NONCE_SIG = "0x627cdcb9"

# Free Polygon RPCs (polling fallback)
HTTP_RPCS = [
    "https://polygon-bor-rpc.publicnode.com",
    "https://rpc.ankr.com/polygon",
    "https://1rpc.io/matic",
    "https://polygon.llamarpc.com",
    "https://polygon-rpc.com",
]

# Polling interval in seconds
POLL_INTERVAL = 2

# Data directory
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
EVENTS_FILE = DATA_DIR / "nonce_events.jsonl"

# ─── BTC 5-min window helpers ────────────────────────────────────────────────
def get_btc_window(ts: float) -> dict:
    """Calculate current BTC 5-min market window from a unix timestamp."""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    # Windows are aligned to 5-min marks from midnight UTC
    total_seconds = dt.hour * 3600 + dt.minute * 60 + dt.second
    window_start_secs = (total_seconds // 300) * 300
    window_end_secs = window_start_secs + 300
    
    window_start = dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(seconds=window_start_secs)
    window_end = dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(seconds=window_end_secs)
    
    remaining = (window_end - dt).total_seconds()
    elapsed = (dt - window_start).total_seconds()
    
    return {
        "window_start": window_start.strftime("%H:%M:%S"),
        "window_end": window_end.strftime("%H:%M:%S"),
        "remaining_secs": round(remaining, 1),
        "elapsed_secs": round(elapsed, 1),
        "pct_elapsed": round(elapsed / 300 * 100, 1),
    }

# ─── Statistics tracker ──────────────────────────────────────────────────────
class NonceStats:
    def __init__(self):
        self.events: list[dict] = []
        self.by_address: defaultdict[str, list] = defaultdict(list)
        self.hourly_counts: defaultdict[str, int] = defaultdict(int)
        self.window_timing: list[float] = []  # seconds remaining when nonce was called
    
    def add(self, event: dict):
        self.events.append(event)
        addr = event["caller"]
        self.by_address[addr].append(event)
        hour_key = event["timestamp"][:13]  # YYYY-MM-DDTHH
        self.hourly_counts[hour_key] += 1
        self.window_timing.append(event["window"]["remaining_secs"])
    
    def print_summary(self):
        total = len(self.events)
        if total == 0:
            return
        
        print("\n" + "=" * 70)
        print(f"📊 NONCE MONITOR STATS — {total} events captured")
        print("=" * 70)
        
        # Top callers
        sorted_addrs = sorted(self.by_address.items(), key=lambda x: -len(x[1]))
        print("\n🏆 Top incrementNonce callers:")
        for addr, evts in sorted_addrs[:15]:
            avg_remaining = sum(e["window"]["remaining_secs"] for e in evts) / len(evts)
            print(f"  {addr}: {len(evts)} calls (avg {avg_remaining:.0f}s before window end)")
        
        # Timing distribution
        near_expiry = sum(1 for r in self.window_timing if r < 30)
        mid_window = sum(1 for r in self.window_timing if 30 <= r < 150)
        early_window = sum(1 for r in self.window_timing if r >= 150)
        print(f"\n⏱  Timing distribution:")
        print(f"  Last 30s of window:  {near_expiry} ({near_expiry/total*100:.0f}%)")
        print(f"  Mid window (30-150s): {mid_window} ({mid_window/total*100:.0f}%)")
        print(f"  Early window (150s+): {early_window} ({early_window/total*100:.0f}%)")
        
        # Hourly
        if self.hourly_counts:
            print(f"\n📅 Hourly counts:")
            for hour, count in sorted(self.hourly_counts.items())[-12:]:
                print(f"  {hour}: {count}")
        
        print("=" * 70 + "\n")


# ─── Event logging ───────────────────────────────────────────────────────────
def log_event(event: dict, stats: NonceStats):
    """Log a nonce event to console, file, and emit universal alert signal."""
    stats.add(event)
    
    w = event["window"]
    gas_gwei = event.get("gas_price_gwei", "?")
    caller_short = event["caller"][:8] + "..." + event["caller"][-4:]
    
    symbol = "🔴" if w["remaining_secs"] < 30 else "🟡" if w["remaining_secs"] < 60 else "🟢"
    
    print(f"{symbol} incrementNonce | {event['timestamp']} | {caller_short} | "
          f"window {w['window_start']}-{w['window_end']} | {w['remaining_secs']}s left | "
          f"{gas_gwei} gwei | tx: {event['tx_hash'][:18]}...")
    
    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    # Emit universal alert signal
    try:
        from alerts import emit as signal_emit, NONCE_INCREMENT, SUSPICIOUS_TIMING, NEW_EXPLOITER, INFO, WARNING
        is_late = w["remaining_secs"] < 30
        is_new = len(stats.by_address.get(event["caller"], [])) <= 1
        
        code = SUSPICIOUS_TIMING if is_late else (NEW_EXPLOITER if is_new else NONCE_INCREMENT)
        severity = WARNING if is_late else INFO
        
        signal_emit(
            code=code,
            severity=severity,
            source="nonce_monitor",
            data={
                "caller": event["caller"],
                "tx_hash": event["tx_hash"],
                "block": event.get("block"),
                "market_window": {
                    "window_id": f"btc-updown-5m-{w['window_start']}",
                    "seconds_remaining": w["remaining_secs"],
                    "pct_elapsed": w.get("pct_elapsed", 0),
                },
                "action": "CANCEL" if is_late else "HOLD",
            },
        )
    except Exception:
        pass  # alerts module optional


# ─── Block polling monitor ──────────────────────────────────────────────────
async def poll_blocks(w3: Web3, stats: NonceStats):
    """Poll recent blocks for incrementNonce transactions."""
    target = CTF_EXCHANGE.lower()
    last_block = w3.eth.block_number
    print(f"📡 Starting block poller from block {last_block}")
    
    while True:
        try:
            current = w3.eth.block_number
            if current <= last_block:
                await asyncio.sleep(POLL_INTERVAL)
                continue
            
            for bn in range(last_block + 1, current + 1):
                try:
                    block = w3.eth.get_block(bn, full_transactions=True)
                except Exception:
                    continue
                
                block_time = block.get("timestamp", int(time.time()))
                
                for tx in block.get("transactions", []):
                    if not isinstance(tx, dict):
                        continue
                    to_addr = (tx.get("to") or "").lower()
                    inp = (tx.get("input") or "0x")
                    
                    if to_addr == target and inp.startswith(INCREMENT_NONCE_SIG):
                        ts = datetime.fromtimestamp(block_time, tz=timezone.utc)
                        event = {
                            "timestamp": ts.isoformat(),
                            "caller": tx["from"],
                            "tx_hash": tx["hash"].hex() if isinstance(tx["hash"], bytes) else tx["hash"],
                            "block": bn,
                            "gas_price_gwei": round(tx.get("gasPrice", 0) / 1e9, 2),
                            "window": get_btc_window(block_time),
                            "source": "confirmed",
                        }
                        log_event(event, stats)
            
            last_block = current
        
        except Exception as e:
            print(f"⚠️  Poll error: {e}")
        
        await asyncio.sleep(POLL_INTERVAL)


# ─── Periodic stats printer ─────────────────────────────────────────────────
async def print_stats_periodically(stats: NonceStats):
    """Print summary stats every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        stats.print_summary()


# ─── Main ────────────────────────────────────────────────────────────────────
async def main():
    print("=" * 70)
    print("🔍 Polymarket CTF Exchange — incrementNonce Monitor")
    print(f"   Contract: {CTF_EXCHANGE}")
    print(f"   Method:   {INCREMENT_NONCE_SIG} (incrementNonce)")
    print(f"   Output:   {EVENTS_FILE}")
    print("=" * 70)
    
    # Connect via HTTP (polling mode — free WSS endpoints are unreliable)
    w3 = None
    for rpc in HTTP_RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
            if w3.is_connected():
                print(f"✅ Connected to {rpc}")
                print(f"   Chain ID: {w3.eth.chain_id}, Block: {w3.eth.block_number}")
                break
        except Exception as e:
            print(f"❌ Failed {rpc}: {e}")
            w3 = None
    
    if not w3:
        print("💀 Could not connect to any Polygon RPC. Exiting.")
        sys.exit(1)
    
    # Load existing events for stats continuity
    stats = NonceStats()
    if EVENTS_FILE.exists():
        count = 0
        for line in open(EVENTS_FILE):
            try:
                ev = json.loads(line.strip())
                stats.add(ev)
                count += 1
            except Exception:
                pass
        if count:
            print(f"📂 Loaded {count} existing events from {EVENTS_FILE.name}")
    
    print(f"\n🚀 Monitoring... polling every {POLL_INTERVAL}s for incrementNonce calls\n")
    
    await asyncio.gather(
        poll_blocks(w3, stats),
        print_stats_periodically(stats),
    )


if __name__ == "__main__":
    # Unbuffered output
    import functools
    print = functools.partial(print, flush=True)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Monitor stopped.")
