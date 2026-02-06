import base64
import hashlib
from dataclasses import dataclass
from typing import Optional, Literal, List
from solders.pubkey import Pubkey

EventType = Literal["OrderPlaced", "OrdersMatched", "OrderCancelled"]

# Precompute discriminators
# event:<EventName>
def _disc(name: str) -> bytes:
    return hashlib.sha256(f"event:{name}".encode()).digest()[:8]

DISC_PLACED = _disc("OrderPlaced")
DISC_MATCHED = _disc("OrdersMatched")
DISC_CANCELLED = _disc("OrderCancelled")

@dataclass
class DecodedEvent:
    event_type: EventType
    market: Pubkey
    order_pubkeys: List[Pubkey]

def decode_anchor_event(log_b64: str) -> Optional[DecodedEvent]:
    """
    Takes base64 string from a `Program data: <b64>` log line.
    Returns DecodedEvent if it matches one of the supported events.
    """
    try:
        data = base64.b64decode(log_b64)
    except Exception:
        return None

    if len(data) < 8:
        return None

    disc = data[:8]
    
    # 8 disc + 32 market + ...
    if len(data) < 40:
        return None

    try:
        # Market is always first field (8..40)
        market = Pubkey.from_bytes(data[8:40])

        if disc == DISC_PLACED:
            # OrderPlaced: market(32), order(32), owner(32)...
            if len(data) < 72: return None
            order = Pubkey.from_bytes(data[40:72])
            return DecodedEvent("OrderPlaced", market, [order])

        elif disc == DISC_CANCELLED:
            # OrderCancelled: market(32), order(32), owner(32)...
            if len(data) < 72: return None
            order = Pubkey.from_bytes(data[40:72])
            return DecodedEvent("OrderCancelled", market, [order])

        elif disc == DISC_MATCHED:
            # OrdersMatched: market(32), order_yes(32), order_no(32)...
            if len(data) < 104: return None
            order_yes = Pubkey.from_bytes(data[40:72])
            order_no = Pubkey.from_bytes(data[72:104])
            return DecodedEvent("OrdersMatched", market, [order_yes, order_no])

    except Exception:
        return None

    return None