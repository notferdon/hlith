# SPDX-License-Identifier: Apache-2.0
"""Falsifier of 078923c9 (review, case): "one callback identity is bounded to 200k value NODES in total". True as stated, but the
stated purpose is bounding the per-call WORK, and a node can be an arbitrarily large atom: _atexit_val counts a str/bytes/int as ONE
node and then repr()s it, the identity joins and sha256s the result, once PER referencing global. Measured by review on 078923c9
(RLIMIT_AS 3 GiB): 16 globals -> one 24 MB str: 21 nodes (bound 200000), 3.1 s; 40 globals: 45 nodes, 6.6 s. Fail-safe direction (a
timeout is UNVERIFIED, never HELD) but unbounded. Deterministic test, no wall clock: the identity of a callback whose referenced atoms
total hundreds of MB must be unmeasurable (size counted into the budget), while a modest callback stays measurable.
Test from review (hlith/review-atom-work cdc49b3b), kept verbatim; fix by review."""
from hlith import differential


def _callback(n_globals: int, atom_bytes: int):
    big = "a" * atom_bytes  # ONE object: allocated once, referenced by every global
    ns = {"__name__": "n7atom"}
    for i in range(n_globals):
        ns[f"G{i}"] = big
    src = "def cb():\n    return (" + ",".join(f"G{i}" for i in range(n_globals)) + ",)\n"
    exec(compile(src, "<n7atom>", "exec"), ns)
    return ns["cb"]


def test_many_references_to_a_huge_atom_are_unmeasurable_not_hashed_repeatedly():
    cb = _callback(40, 8 << 20)  # 320 MB of repr/hash work behind 41 nodes
    try:
        got = differential._atexit_identity(cb, (), {}, "/nonexistent")
    except differential._AtexitUnmeasurable:
        return  # the intended outcome once atom size counts toward the identity budget
    raise AssertionError(f"320 MB of atom work behind ~41 nodes was measured, not bounded (identity len {len(got)})")


def test_a_modest_callback_stays_measurable():
    cb = _callback(8, 100 << 10)
    got = differential._atexit_identity(cb, (), {}, "/nonexistent")
    assert got.startswith(("/", "<", "nonexistent")) or "cb" in got


def test_a_huge_int_and_huge_bytes_are_charged_by_size_too():
    ns = {"__name__": "n1atom2"}
    big_int = 1 << (8 * 20 * (1 << 20))  # a 20 MiB integer
    for i in range(12):
        ns[f"I{i}"] = big_int
        ns[f"B{i}"] = b"z" * (8 << 20)
    names = [f"I{i}" for i in range(12)] + [f"B{i}" for i in range(12)]
    exec(compile("def cb():\n    return (" + ",".join(names) + ",)\n", "<n1atom2>", "exec"), ns)
    try:
        differential._atexit_identity(ns["cb"], (), {}, "/nonexistent")
    except differential._AtexitUnmeasurable:
        return
    raise AssertionError("hundreds of MB of int/bytes atoms were measured, not bounded")
