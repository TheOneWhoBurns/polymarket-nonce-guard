#!/usr/bin/env python3
"""
Real-time Polymarket BTC 5-min market manipulation detector.

Kept as reference: config, market, and price_feed come from a private trading
bot and are not part of this repository. This file is not runnable standalone.

Detects order-book manipulation (mass cancellations, liquidity pulls, price spoofing)
by comparing orderbook state changes against actual BTC price movements.

Usage:
    python manipulation_detector.py              # monitor only
    python manipulation_detector.py --trade      # monitor + counter-trade
    python manipulation_detector.py --verbose    # extra logging
"""

import argparse
import asyncio
import json
import logging
import logging.handlers
import os
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from config import BINANCE_WS as BINANCE_WS
    from market import PolymarketClient, Window, current_window_timestamp, next_window_timestamp
    from price_feed import BinanceFeed
except ImportError as exc:
    msg = (
        f"Cannot import {exc.name or 'a required symbol'}: {exc}. "
        "The config, market, and price_feed modules come from a private trading bot "
        "and are not part of this repository. This file is kept as reference "
        "and is not runnable standalone."
    )
    if __name__ == "__main__":
        sys.exit(msg)
    raise ImportError(msg) from exc

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
POLL_INTERVAL = 2.0          # orderbook poll frequency (seconds)
ALERT_COOLDOWN = 15.0        # min seconds between alerts of same type
HISTORY_SIZE = 60             # keep last N orderbook snapshots (~2 min at 2s)

# Thresholds
PRICE_JUMP_THRESHOLD = 0.10       # mid-price move > 10c without BTC move
BTC_MOVE_THRESHOLD_PCT = 0.05     # 0.05% BTC move considered "significant"
DEPTH_DROP_PCT = 0.40             # 40% depth disappears in one tick
DEPTH_DROP_WINDOW = 3             # compare depth over last N snapshots
DIVERGENCE_THRESHOLD = 0.15       # orderbook mid vs implied fair value divergence
VOLUME_VANISH_THRESHOLD = 50.0    # >$50 of volume vanishes in one tick

# Counter-trade
COUNTER_TRADE_SIZE = 5.0          # USDC per counter-trade
COUNTER_TRADE_EDGE = 0.08         # only trade if manipulation moved price > 8c from fair

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
ALERT_LOG = os.path.join(DATA_DIR, "manipulation_alerts.jsonl")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
root = logging.getLogger()
root.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setFormatter(fmt)
root.addHandler(sh)
fh = logging.handlers.RotatingFileHandler(
    os.path.join(DATA_DIR, "manipulation_detector.log"), maxBytes=5_000_000, backupCount=3
)
fh.setFormatter(fmt)
root.addHandler(fh)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("websockets").setLevel(logging.WARNING)
logger = logging.getLogger("manip")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class BookSnapshot:
    ts: float
    bid_up: float
    ask_up: float
    bid_down: float
    ask_down: float
    depth_up_bids: float    # total bid volume on UP token
    depth_up_asks: float    # total ask volume on UP token
    depth_down_bids: float
    depth_down_asks: float
    btc_price: float

    @property
    def mid_up(self) -> float:
        if self.bid_up and self.ask_up:
            return (self.bid_up + self.ask_up) / 2
        return self.bid_up or self.ask_up or 0

    @property
    def mid_down(self) -> float:
        if self.bid_down and self.ask_down:
            return (self.bid_down + self.ask_down) / 2
        return self.bid_down or self.ask_down or 0

    @property
    def total_depth(self) -> float:
        return self.depth_up_bids + self.depth_up_asks + self.depth_down_bids + self.depth_down_asks


@dataclass
class Alert:
    ts: float
    alert_type: str
    severity: str       # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class ManipulationDetector:
    def __init__(self, client: PolymarketClient, feed: BinanceFeed, trade_enabled: bool = False):
        self.client = client
        self.feed = feed
        self.trade_enabled = trade_enabled
        self.history: deque[BookSnapshot] = deque(maxlen=HISTORY_SIZE)
        self.alerts: list[Alert] = []
        self.last_alert_time: dict[str, float] = {}
        self.window: Window | None = None
        self.start_price: float | None = None
        self.alert_count = 0
        self.trade_count = 0

    def _get_full_book(self, window: Window) -> BookSnapshot | None:
        """Get orderbook with full depth info."""
        btc = self.feed.get_price()
        if btc is None:
            return None
        try:
            book_up = self.client.clob.get_order_book(window.token_id_up)
            book_down = self.client.clob.get_order_book(window.token_id_down)

            bids_up = getattr(book_up, "bids", []) or []
            asks_up = getattr(book_up, "asks", []) or []
            bids_down = getattr(book_down, "bids", []) or []
            asks_down = getattr(book_down, "asks", []) or []

            def sum_volume(orders):
                return sum(float(o.size) for o in orders) if orders else 0.0

            bid_up = float(bids_up[-1].price) if bids_up else 0
            ask_up = float(asks_up[0].price) if asks_up else 0
            bid_down = float(bids_down[-1].price) if bids_down else 0
            ask_down = float(asks_down[0].price) if asks_down else 0

            return BookSnapshot(
                ts=time.time(),
                bid_up=bid_up, ask_up=ask_up,
                bid_down=bid_down, ask_down=ask_down,
                depth_up_bids=sum_volume(bids_up),
                depth_up_asks=sum_volume(asks_up),
                depth_down_bids=sum_volume(bids_down),
                depth_down_asks=sum_volume(asks_down),
                btc_price=btc,
            )
        except Exception as e:
            logger.warning(f"Book fetch failed: {e}")
            return None

    def _can_alert(self, alert_type: str) -> bool:
        last = self.last_alert_time.get(alert_type, 0)
        return time.time() - last >= ALERT_COOLDOWN

    def _fire_alert(self, alert: Alert):
        if not self._can_alert(alert.alert_type):
            return
        self.last_alert_time[alert.alert_type] = alert.ts
        self.alert_count += 1
        self.alerts.append(alert)

        icon = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}
        logger.warning(
            f"{icon.get(alert.severity, '⚠️')} [{alert.severity}] {alert.alert_type}: {alert.message}"
        )
        if alert.data:
            logger.info(f"   Data: {json.dumps(alert.data, default=str)}")

        # Append to JSONL log
        try:
            with open(ALERT_LOG, "a") as f:
                f.write(json.dumps({
                    "ts": datetime.fromtimestamp(alert.ts, tz=timezone.utc).isoformat(),
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "data": alert.data,
                }) + "\n")
        except Exception:
            pass

    def analyze(self, snap: BookSnapshot):
        """Run all detectors on the new snapshot."""
        if len(self.history) < 2:
            return

        prev = self.history[-1]

        # 1) PRICE JUMP without BTC movement
        self._check_price_jump(snap, prev)

        # 2) DEPTH DROP (liquidity pulled)
        self._check_depth_drop(snap)

        # 3) VOLUME VANISH (orders cancelled)
        self._check_volume_vanish(snap, prev)

        # 4) PRICE DIVERGENCE from BTC-implied fair value
        self._check_divergence(snap)

        # 5) SPREAD BLOW-OUT
        self._check_spread(snap, prev)

    def _check_price_jump(self, snap: BookSnapshot, prev: BookSnapshot):
        """Detect large price moves without corresponding BTC movement."""
        btc_pct = abs(snap.btc_price - prev.btc_price) / prev.btc_price * 100 if prev.btc_price else 0

        for label, mid_now, mid_prev in [
            ("UP", snap.mid_up, prev.mid_up),
            ("DOWN", snap.mid_down, prev.mid_down),
        ]:
            if not mid_now or not mid_prev:
                continue
            delta = abs(mid_now - mid_prev)
            if delta >= PRICE_JUMP_THRESHOLD and btc_pct < BTC_MOVE_THRESHOLD_PCT:
                direction = "↑" if mid_now > mid_prev else "↓"
                severity = "CRITICAL" if delta >= 0.20 else "HIGH" if delta >= 0.15 else "MEDIUM"
                self._fire_alert(Alert(
                    ts=snap.ts,
                    alert_type=f"PRICE_JUMP_{label}",
                    severity=severity,
                    message=(
                        f"{label} mid {direction} ${mid_prev:.3f} → ${mid_now:.3f} "
                        f"(Δ={delta:.3f}) but BTC only moved {btc_pct:.4f}%"
                    ),
                    data={
                        "token": label, "mid_prev": mid_prev, "mid_now": mid_now,
                        "delta": delta, "btc_pct_move": btc_pct,
                        "btc": snap.btc_price, "direction": direction,
                    },
                ))
                # Counter-trade opportunity
                if self.trade_enabled and delta >= COUNTER_TRADE_EDGE:
                    self._counter_trade(snap, label, mid_now, mid_prev)

    def _check_depth_drop(self, snap: BookSnapshot):
        """Detect sudden liquidity disappearance."""
        if len(self.history) < DEPTH_DROP_WINDOW:
            return
        ref = self.history[-DEPTH_DROP_WINDOW]
        if ref.total_depth < 1:
            return
        drop_pct = (ref.total_depth - snap.total_depth) / ref.total_depth
        if drop_pct >= DEPTH_DROP_PCT:
            severity = "CRITICAL" if drop_pct >= 0.70 else "HIGH" if drop_pct >= 0.55 else "MEDIUM"
            self._fire_alert(Alert(
                ts=snap.ts,
                alert_type="DEPTH_DROP",
                severity=severity,
                message=(
                    f"Orderbook depth dropped {drop_pct:.0%}: "
                    f"{ref.total_depth:.0f} → {snap.total_depth:.0f} shares "
                    f"(over {DEPTH_DROP_WINDOW * POLL_INTERVAL:.0f}s)"
                ),
                data={
                    "depth_before": ref.total_depth, "depth_after": snap.total_depth,
                    "drop_pct": drop_pct,
                },
            ))

    def _check_volume_vanish(self, snap: BookSnapshot, prev: BookSnapshot):
        """Detect large volume disappearing from one side."""
        for label, now_v, prev_v in [
            ("UP_BIDS", snap.depth_up_bids, prev.depth_up_bids),
            ("UP_ASKS", snap.depth_up_asks, prev.depth_up_asks),
            ("DOWN_BIDS", snap.depth_down_bids, prev.depth_down_bids),
            ("DOWN_ASKS", snap.depth_down_asks, prev.depth_down_asks),
        ]:
            vanished = prev_v - now_v
            if vanished >= VOLUME_VANISH_THRESHOLD:
                severity = "HIGH" if vanished >= 100 else "MEDIUM"
                self._fire_alert(Alert(
                    ts=snap.ts,
                    alert_type=f"VOLUME_VANISH_{label}",
                    severity=severity,
                    message=f"{label}: {vanished:.0f} shares vanished ({prev_v:.0f} → {now_v:.0f})",
                    data={"side": label, "before": prev_v, "after": now_v, "vanished": vanished},
                ))

    def _check_divergence(self, snap: BookSnapshot):
        """Check if orderbook prices diverge from what BTC price implies."""
        if not self.start_price or not snap.btc_price:
            return
        # Simple heuristic: if BTC is above start, UP should be > 0.50
        btc_delta_pct = (snap.btc_price - self.start_price) / self.start_price * 100
        # Rough mapping: each 0.01% BTC move ≈ some probability shift
        # If BTC is solidly up but UP token is cheap, something is wrong
        if btc_delta_pct > 0.03 and snap.mid_up and snap.mid_up < (0.50 - DIVERGENCE_THRESHOLD):
            self._fire_alert(Alert(
                ts=snap.ts,
                alert_type="DIVERGENCE_UP_CHEAP",
                severity="HIGH",
                message=(
                    f"BTC up {btc_delta_pct:+.4f}% but UP mid only ${snap.mid_up:.3f} — "
                    f"UP token underpriced vs BTC reality"
                ),
                data={"btc_delta_pct": btc_delta_pct, "mid_up": snap.mid_up, "btc": snap.btc_price},
            ))
        elif btc_delta_pct < -0.03 and snap.mid_down and snap.mid_down < (0.50 - DIVERGENCE_THRESHOLD):
            self._fire_alert(Alert(
                ts=snap.ts,
                alert_type="DIVERGENCE_DOWN_CHEAP",
                severity="HIGH",
                message=(
                    f"BTC down {btc_delta_pct:+.4f}% but DOWN mid only ${snap.mid_down:.3f} — "
                    f"DOWN token underpriced vs BTC reality"
                ),
                data={"btc_delta_pct": btc_delta_pct, "mid_down": snap.mid_down, "btc": snap.btc_price},
            ))

    def _check_spread(self, snap: BookSnapshot, prev: BookSnapshot):
        """Detect spread blowouts (market maker pulling quotes)."""
        for label, bid, ask, prev_bid, prev_ask in [
            ("UP", snap.bid_up, snap.ask_up, prev.bid_up, prev.ask_up),
            ("DOWN", snap.bid_down, snap.ask_down, prev.bid_down, prev.ask_down),
        ]:
            if not (bid and ask and prev_bid and prev_ask):
                continue
            spread_now = ask - bid
            spread_prev = prev_ask - prev_bid
            if spread_prev > 0:
                spread_expansion = spread_now / spread_prev
                if spread_expansion >= 3.0 and spread_now >= 0.10:
                    severity = "HIGH" if spread_expansion >= 5 else "MEDIUM"
                    self._fire_alert(Alert(
                        ts=snap.ts,
                        alert_type=f"SPREAD_BLOWOUT_{label}",
                        severity=severity,
                        message=(
                            f"{label} spread {spread_expansion:.1f}x wider: "
                            f"${spread_prev:.3f} → ${spread_now:.3f}"
                        ),
                        data={
                            "token": label, "spread_prev": spread_prev,
                            "spread_now": spread_now, "expansion": spread_expansion,
                        },
                    ))

    def _counter_trade(self, snap: BookSnapshot, token_label: str, mid_now: float, mid_prev: float):
        """Place a counter-trade against detected manipulation."""
        if not self.window:
            return
        # If price was artificially pushed DOWN, buy the token (it should revert up)
        # If price was artificially pushed UP, sell/short (buy the other side)
        if mid_now < mid_prev:
            # Token got cheaper — manipulation pushed it down → BUY
            if token_label == "UP":
                token_id = self.window.token_id_up
                buy_price = round(snap.ask_up if snap.ask_up else mid_now + 0.01, 2)
            else:
                token_id = self.window.token_id_down
                buy_price = round(snap.ask_down if snap.ask_down else mid_now + 0.01, 2)

            if buy_price <= 0.01 or buy_price >= 0.99:
                return

            size = round(COUNTER_TRADE_SIZE / buy_price, 1)
            if size < 1:
                return

            logger.info(
                f"  💰 COUNTER-TRADE: BUY {token_label} @ ${buy_price:.2f} x{size:.1f} "
                f"(manipulation pushed price down ${mid_prev:.3f}→${mid_now:.3f})"
            )
            order_id = self.client.place_limit_buy(token_id, buy_price, size)
            if order_id:
                self.trade_count += 1
                logger.info(f"  ✅ Counter-trade placed: {order_id}")
        else:
            # Token got more expensive — buy the OTHER side
            if token_label == "UP":
                token_id = self.window.token_id_down
                buy_price = round(snap.ask_down if snap.ask_down else snap.mid_down + 0.01, 2)
            else:
                token_id = self.window.token_id_up
                buy_price = round(snap.ask_up if snap.ask_up else snap.mid_up + 0.01, 2)

            if buy_price <= 0.01 or buy_price >= 0.99:
                return

            size = round(COUNTER_TRADE_SIZE / buy_price, 1)
            if size < 1:
                return

            other = "DOWN" if token_label == "UP" else "UP"
            logger.info(
                f"  💰 COUNTER-TRADE: BUY {other} @ ${buy_price:.2f} x{size:.1f} "
                f"(manipulation inflated {token_label} ${mid_prev:.3f}→${mid_now:.3f})"
            )
            order_id = self.client.place_limit_buy(token_id, buy_price, size)
            if order_id:
                self.trade_count += 1
                logger.info(f"  ✅ Counter-trade placed: {order_id}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
async def run(args):
    feed = BinanceFeed()
    client = PolymarketClient()
    detector = ManipulationDetector(client, feed, trade_enabled=args.trade)

    feed_task = asyncio.create_task(feed.start())

    logger.info("⏳ Waiting for Binance price feed...")
    for _ in range(30):
        if feed.get_price() is not None:
            break
        await asyncio.sleep(1)
    else:
        logger.error("❌ Could not connect to Binance feed")
        feed.stop()
        return

    logger.info(f"✅ BTC price: ${feed.get_price():.2f}")
    logger.info(f"🔍 Manipulation detector started | trade={'ON' if args.trade else 'OFF'}")
    logger.info(f"   Poll interval: {POLL_INTERVAL}s | Price jump threshold: ${PRICE_JUMP_THRESHOLD}")
    logger.info(f"   Depth drop threshold: {DEPTH_DROP_PCT:.0%} | Volume vanish: {VOLUME_VANISH_THRESHOLD} shares")

    window = None
    last_status = 0

    try:
        while True:
            # Get or refresh window
            if window is None or window.is_expired:
                ts = current_window_timestamp()
                w = client.fetch_window(ts)
                if w and w.is_active:
                    window = w
                    detector.window = w
                    btc = feed.get_price()
                    detector.start_price = btc
                    detector.history.clear()
                    logger.info(f"📊 Window {w.slug} | S0=${btc:.2f} | tau={w.tau:.0f}s")
                else:
                    # Try next window
                    nxt = next_window_timestamp()
                    wait = nxt - time.time()
                    if wait > 0:
                        if time.time() - last_status > 30:
                            logger.info(f"⏳ Next window in {wait:.0f}s")
                            last_status = time.time()
                        await asyncio.sleep(min(wait + 1, 10))
                    else:
                        await asyncio.sleep(5)
                    continue

            # Poll orderbook
            snap = detector._get_full_book(window)
            if snap is None:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            # Run analysis
            detector.analyze(snap)
            detector.history.append(snap)

            # Status line every 30s
            now = time.time()
            if now - last_status >= 30:
                logger.info(
                    f"📈 BTC=${snap.btc_price:.2f} | UP mid=${snap.mid_up:.3f} DOWN mid=${snap.mid_down:.3f} "
                    f"| depth={snap.total_depth:.0f} | alerts={detector.alert_count} "
                    f"| trades={detector.trade_count} | tau={window.tau:.0f}s"
                )
                last_status = now

            if args.verbose:
                logger.debug(
                    f"  📖 UP: {snap.bid_up:.3f}/{snap.ask_up:.3f} ({snap.depth_up_bids:.0f}/{snap.depth_up_asks:.0f}) "
                    f"DOWN: {snap.bid_down:.3f}/{snap.ask_down:.3f} ({snap.depth_down_bids:.0f}/{snap.depth_down_asks:.0f})"
                )

            await asyncio.sleep(POLL_INTERVAL)

    except asyncio.CancelledError:
        pass
    finally:
        logger.info(f"=== DETECTOR STOPPED | {detector.alert_count} alerts | {detector.trade_count} counter-trades ===")
        feed.stop()
        feed_task.cancel()
        try:
            await feed_task
        except asyncio.CancelledError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Polymarket BTC 5-min manipulation detector")
    parser.add_argument("--trade", action="store_true", help="Enable counter-trading against manipulation")
    parser.add_argument("--verbose", action="store_true", help="Extra logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    loop = asyncio.new_event_loop()

    def shutdown(sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    signal.signal(signal.SIGINT, lambda s, f: shutdown(s, f))
    signal.signal(signal.SIGTERM, lambda s, f: shutdown(s, f))

    try:
        loop.run_until_complete(run(args))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
