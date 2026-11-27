# SPDX-License-Identifier: Apache-2.0
"""Canonical serialization and digests. One encoding for every contract type."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
from typing import Any

SCHEMA_VERSION = 2


def plain(obj: Any) -> Any:
    """Contract values to JSON-safe plain data. Anything outside the contract types is rejected, never guessed."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return plain(obj.value)
    if isinstance(obj, (tuple, list)):
        return [plain(x) for x in obj]
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise TypeError("contract dict keys must be str")
        return {k: plain(v) for k, v in obj.items()}
    if obj is None or isinstance(obj, (str, bool, int)):
        return obj
    raise TypeError(f"not a contract value: {type(obj).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(plain(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256_canonical(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


_FLOAT_TAG = "$float"
_HEX = frozenset("0123456789abcdef")


def float_tag(x: float) -> dict:
    """The typed, BIT-EXACT record of a float: the 8-byte IEEE-754 pattern (sign, exponent, payload: -0.0, subnormals, inf and every NaN survive) plus a human repr."""
    import struct

    return {_FLOAT_TAG: {"bits": struct.pack(">d", x).hex(), "repr": repr(x)}}


def is_float_tag(o: Any) -> bool:
    """ONLY the exact shape {"$float": {"bits": <16 lowercase hex>, "repr": <str>}} is a tag; every other dict (even one with a "$float" key) is plain data."""
    if not (isinstance(o, dict) and len(o) == 1 and _FLOAT_TAG in o):
        return False
    v = o[_FLOAT_TAG]
    return (isinstance(v, dict) and set(v) == {"bits", "repr"} and isinstance(v["bits"], str) and len(v["bits"]) == 16 and set(v["bits"]) <= _HEX and isinstance(v["repr"], str))


def tag_to_float(o: dict) -> float:
    import struct

    return struct.unpack(">d", bytes.fromhex(o[_FLOAT_TAG]["bits"]))[0]


def encode_call_values(obj: Any) -> Any:
    """A recorded CALL (witness args/kwargs, pre/post, pin inputs) to contract-safe plain data. The contract codec stays strict (a float is never guessed at a contract boundary); a float is
    recorded EXPLICITLY as the bit-exact tag. IDEMPOTENT: a valid tag is kept as it is (a stored record can be re-pinned or re-recorded); a dict that merely LOOKS like a tag (any other
    shape, e.g. {"$float": "1.5"}) is plain data. The exact tag shape is reserved. bool/int/str/None, lists and dicts pass through; a tuple becomes a list."""
    if isinstance(obj, float):
        return float_tag(obj)
    if is_float_tag(obj):
        return obj
    if isinstance(obj, dict):
        return {k: encode_call_values(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [encode_call_values(x) for x in obj]
    return obj


encode_pin_values = encode_call_values


def decode_call_values(obj: Any) -> Any:
    """Inverse of encode_call_values on JSON loaded from a record: a valid tag decodes to the SAME float bit for bit; everything else (including look-alike dicts) is untouched."""
    if is_float_tag(obj):
        return tag_to_float(obj)
    if isinstance(obj, dict):
        return {k: decode_call_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decode_call_values(x) for x in obj]
    return obj
