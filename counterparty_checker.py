"""
counterparty_checker.py — Extract counterparty addresses from CTF Exchange OrderFilled events.

OrderFilled event on CTF Exchange (0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E):
  topic0: 0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6
  topic1: orderHash (bytes32)
  topic2: maker (address, indexed, zero-padded to 32 bytes)
  topic3: taker (address, indexed, zero-padded to 32 bytes)
  data:   makerAssetId(uint256) | takerAssetId(uint256) | makerAmountFilled(uint256) |
          takerAmountFilled(uint256) | fee(uint256)
"""
import logging
from web3 import Web3

logger = logging.getLogger(__name__)

POLYGON_RPC = "https://polygon-bor-rpc.publicnode.com"
CTF_EXCHANGE = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
ORDER_FILLED_TOPIC = "0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6"

_w3: Web3 | None = None


def _get_w3() -> Web3:
    global _w3
    if _w3 is None:
        _w3 = Web3(Web3.HTTPProvider(POLYGON_RPC, request_kwargs={"timeout": 20}))
    return _w3


def parse_order_filled_log(log: dict) -> dict | None:
    """
    Parse a single OrderFilled log entry.
    Returns dict with maker, taker, maker_asset_id, taker_asset_id, maker_amount, taker_amount, fee.
    """
    topics = log.get("topics", [])
    if len(topics) < 4:
        return None

    maker = Web3.to_checksum_address("0x" + topics[2].hex()[-40:])
    taker = Web3.to_checksum_address("0x" + topics[3].hex()[-40:])

    data = log["data"]
    if isinstance(data, str):
        data = bytes.fromhex(data[2:] if data.startswith("0x") else data)

    if len(data) < 160:
        return {"maker": maker, "taker": taker}

    maker_asset_id = hex(int.from_bytes(data[0:32], "big"))
    taker_asset_id = hex(int.from_bytes(data[32:64], "big"))
    maker_amount = int.from_bytes(data[64:96], "big")
    taker_amount = int.from_bytes(data[96:128], "big")
    fee = int.from_bytes(data[128:160], "big")

    return {
        "maker": maker,
        "taker": taker,
        "maker_asset_id": maker_asset_id,
        "taker_asset_id": taker_asset_id,
        "maker_amount": maker_amount,
        "taker_amount": taker_amount,
        "fee": fee,
    }


def get_fills_in_block(block_number: int) -> list[dict]:
    """Get all OrderFilled events in a block from the CTF Exchange."""
    w3 = _get_w3()
    try:
        logs = w3.eth.get_logs({
            "fromBlock": block_number,
            "toBlock": block_number,
            "address": Web3.to_checksum_address(CTF_EXCHANGE),
            "topics": [ORDER_FILLED_TOPIC],
        })
    except Exception as e:
        logger.warning(f"get_logs failed for block {block_number}: {e}")
        return []

    results = []
    for log in logs:
        parsed = parse_order_filled_log(log)
        if parsed:
            parsed["tx_hash"] = "0x" + bytes(log["transactionHash"]).hex()
            parsed["block"] = block_number
            parsed["log_index"] = log.get("logIndex", 0)
            results.append(parsed)
    return results


def get_fills_for_address(block_number: int, address: str) -> list[dict]:
    """Get OrderFilled events involving a specific address (as maker or taker)."""
    addr = address.lower()
    all_fills = get_fills_in_block(block_number)
    return [f for f in all_fills if f["maker"].lower() == addr or f["taker"].lower() == addr]


def get_counterparty(fill: dict, our_address: str) -> str | None:
    """Given a parsed fill dict and our address, return the counterparty."""
    our = our_address.lower()
    if fill["maker"].lower() == our:
        return fill["taker"]
    elif fill["taker"].lower() == our:
        return fill["maker"]
    return None


def get_latest_block() -> int:
    return _get_w3().eth.block_number
