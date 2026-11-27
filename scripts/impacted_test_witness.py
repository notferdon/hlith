"""Canonical string encoding for independently replayable impacted-test witnesses."""

import json
from typing import Any

PREFIX = "impacted-test/v1 "
MAX_WITNESS_CHARS = 4096
_KEYS = ("nodeid", "base", "post", "replay")
_OUTCOMES = {"passed", "failed"}


def format_impacted_test_witness(nodeid: str, base: str, post: str, replay: list[str]) -> str:
    """Return a bounded, human-readable witness string, rejecting incomplete records."""
    if not isinstance(nodeid, str) or not nodeid or "\x00" in nodeid:
        raise ValueError("nodeid must be nonempty and contain no NUL")
    if not isinstance(base, str) or not isinstance(post, str) or base not in _OUTCOMES or post not in _OUTCOMES:
        raise ValueError("impacted-test outcomes must be passed or failed")
    if not isinstance(replay, list) or not replay or any(not isinstance(arg, str) for arg in replay):
        raise ValueError("replay must be a nonempty argv list of strings")
    payload = {"nodeid": nodeid, "base": base, "post": post, "replay": replay}
    witness = PREFIX + json.dumps(payload, ensure_ascii=False, separators=(", ", ": "))
    if len(witness) > MAX_WITNESS_CHARS:
        raise ValueError(f"impacted-test witness exceeds {MAX_WITNESS_CHARS} characters")
    return witness


def parse_impacted_test_witness(witness: str) -> dict[str, Any] | None:
    """Parse a v1 witness; return None for other witness kinds or malformed records."""
    if not isinstance(witness, str) or not witness.startswith(PREFIX) or len(witness) > MAX_WITNESS_CHARS:
        return None
    try:
        payload = json.loads(witness[len(PREFIX):])
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or tuple(payload) != _KEYS:
        return None
    nodeid, base, post, replay = (payload[key] for key in _KEYS)
    if (not isinstance(nodeid, str) or not nodeid or "\x00" in nodeid
            or not isinstance(base, str) or not isinstance(post, str)
            or base not in _OUTCOMES or post not in _OUTCOMES
            or not isinstance(replay, list) or not replay
            or any(not isinstance(arg, str) for arg in replay)):
        return None
    return payload
