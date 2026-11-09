import socket

import pytest


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    original_connect = socket.socket.connect

    def offline_connect(sock, address):
        if sock.family != socket.AF_UNIX:
            raise AssertionError(f"Network access forbidden in tests: {address}")
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", offline_connect)
