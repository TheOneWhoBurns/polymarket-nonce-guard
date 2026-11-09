#!/usr/bin/env python3
"""
alerts.py — Universal alert signal for Polymarket Nonce Guard.

Provides a standardized alert format that any trading bot can consume.
Alerts are written to a well-known file and optionally broadcast via:
  - File (JSONL) — poll data/alerts.jsonl
  - Unix socket — connect to /tmp/nonce-guard.sock for real-time push
  - HTTP webhook — POST to any URL
  - stdout — pipe into your bot

INTEGRATION GUIDE:
==================

Option 1: Poll the alerts file
    import json
    with open("data/alerts.jsonl") as f:
        for line in f:
            alert = json.loads(line)
            if alert["code"] == "BLACKLISTED_COUNTERPARTY":
                sell(alert["token_id"])

Option 2: Listen on Unix socket
    import socket, json
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/tmp/nonce-guard.sock")
    for line in sock.makefile():
        alert = json.loads(line)
        handle(alert)

Option 3: Subscribe in-process
    from alerts import AlertBus
    bus = AlertBus()
    bus.subscribe(lambda alert: print(alert))

ALERT SCHEMA (v1):
==================
{
    "version": 1,
    "timestamp": "2026-02-21T18:45:00Z",
    "code": "NONCE_INCREMENT | BLACKLISTED_COUNTERPARTY | SUSPICIOUS_TIMING",
    "severity": "info | warning | critical",
    "source": "nonce_monitor | watchdog | manipulation_detector",
    "data": {
        "caller": "0x...",           # who triggered incrementNonce
        "tx_hash": "0x...",          # transaction hash
        "block": 12345678,           # block number
        "market_window": {           # optional: timing context
            "window_id": "btc-updown-5m-...",
            "seconds_remaining": 25,
            "pct_elapsed": 0.92
        },
        "counterparty": "0x...",     # for BLACKLISTED_COUNTERPARTY
        "token_id": "0x...",         # for BLACKLISTED_COUNTERPARTY
        "action": "SELL | CANCEL | HOLD"  # recommended action
    }
}

CODES:
======
NONCE_INCREMENT          — Someone called incrementNonce() (info/warning based on timing)
BLACKLISTED_COUNTERPARTY — Your fill matched a known exploiter (critical)
SUSPICIOUS_TIMING        — incrementNonce in last 30s of market window (warning)
NEW_EXPLOITER            — First-time caller detected (info)
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("nonce_guard.signal")

ALERT_VERSION = 1
ALERTS_FILE = os.path.join(os.path.dirname(__file__), "data", "alerts.jsonl")
SOCKET_PATH = "/tmp/nonce-guard.sock"

# Alert codes
NONCE_INCREMENT = "NONCE_INCREMENT"
BLACKLISTED_COUNTERPARTY = "BLACKLISTED_COUNTERPARTY"
SUSPICIOUS_TIMING = "SUSPICIOUS_TIMING"
NEW_EXPLOITER = "NEW_EXPLOITER"

# Severity levels
INFO = "info"
WARNING = "warning"
CRITICAL = "critical"


def make_alert(
    code: str,
    severity: str,
    source: str,
    data: dict,
) -> dict:
    """Create a standardized alert dict."""
    return {
        "version": ALERT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "code": code,
        "severity": severity,
        "source": source,
        "data": data,
    }


class AlertBus:
    """
    Central alert dispatcher. Write once, deliver everywhere.

    Usage:
        bus = AlertBus(file=True, socket=True, webhook="https://...")
        bus.emit(code="NONCE_INCREMENT", severity="warning", source="nonce_monitor", data={...})

    Subscribe for in-process callbacks:
        bus.subscribe(my_handler)  # my_handler(alert_dict) called on each emit
    """

    def __init__(
        self,
        file: bool = True,
        file_path: str = ALERTS_FILE,
        socket_enabled: bool = False,
        socket_path: str = SOCKET_PATH,
        webhook_url: Optional[str] = None,
        stdout: bool = False,
    ):
        self.file = file
        self.file_path = file_path
        self.socket_enabled = socket_enabled
        self.socket_path = socket_path
        self.webhook_url = webhook_url
        self.stdout = stdout
        self._subscribers: list[Callable] = []
        self._socket_clients: list[socket.socket] = []
        self._lock = threading.Lock()

        if file:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

        if socket_enabled:
            self._start_socket_server()

    def subscribe(self, callback: Callable):
        """Register an in-process callback for alerts."""
        with self._lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        with self._lock:
            self._subscribers = [s for s in self._subscribers if s != callback]

    def emit(self, code: str, severity: str, source: str, data: dict):
        """Emit an alert to all configured outputs."""
        alert = make_alert(code, severity, source, data)

        # File output
        if self.file:
            try:
                with open(self.file_path, "a") as f:
                    f.write(json.dumps(alert) + "\n")
            except Exception as e:
                logger.error(f"Failed to write alert to file: {e}")

        # Stdout
        if self.stdout:
            print(json.dumps(alert), flush=True)

        # In-process subscribers
        with self._lock:
            for cb in self._subscribers:
                try:
                    cb(alert)
                except Exception as e:
                    logger.error(f"Subscriber error: {e}")

        # Unix socket clients
        self._broadcast_socket(alert)

        # Webhook
        if self.webhook_url:
            self._send_webhook(alert)

        return alert

    def _start_socket_server(self):
        """Start Unix socket server in background thread."""
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        def _server():
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(self.socket_path)
            srv.listen(5)
            logger.info(f"Alert socket listening on {self.socket_path}")
            while True:
                try:
                    client, _ = srv.accept()
                    with self._lock:
                        self._socket_clients.append(client)
                    logger.info("New socket client connected")
                except Exception as e:
                    logger.error(f"Socket accept error: {e}")

        t = threading.Thread(target=_server, daemon=True)
        t.start()

    def _broadcast_socket(self, alert: dict):
        """Send alert to all connected socket clients."""
        if not self._socket_clients:
            return
        msg = (json.dumps(alert) + "\n").encode()
        dead = []
        with self._lock:
            for client in self._socket_clients:
                try:
                    client.sendall(msg)
                except Exception:
                    dead.append(client)
            for d in dead:
                self._socket_clients.remove(d)

    def _send_webhook(self, alert: dict):
        """POST alert to webhook URL."""
        try:
            import requests
            requests.post(
                self.webhook_url,
                json=alert,
                timeout=5,
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            logger.error(f"Webhook error: {e}")


# Convenience: module-level default bus (lazy init)
_default_bus: Optional[AlertBus] = None


def get_bus(**kwargs) -> AlertBus:
    """Get or create the default AlertBus singleton."""
    global _default_bus
    if _default_bus is None:
        _default_bus = AlertBus(**kwargs)
    return _default_bus


def emit(code: str, severity: str, source: str, data: dict) -> dict:
    """Emit an alert on the default bus."""
    return get_bus().emit(code, severity, source, data)
