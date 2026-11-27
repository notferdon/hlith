"""Closure-gap row 1 : a receiver-state REFUTED witness (a method witness) replays STANDALONE.

Recorded receiver replay receipt: (requests CaseInsensitiveDict.__setitem__) was REFUTED with replay=false,
"receiver construction (method witness)". The replay script now rebuilds the receiver from the recorded constructor
plan (ctor.<name> folded in by corder, self.<name> fields set afterwards) and compares its post-call state.
Negative controls: equal receiver states do not reproduce; a recording that claims a state difference the replay does
not observe does not reproduce; a receiver record without a usable kind / constructor plan is still refused.
"""
import json
import re

import pytest

from hlith import differential
from hlith.types import Verdict

# the requests R-receiver shape, reduced: __setitem__ keeps the original-case key (pre) vs the lowered key (post)
CID = ("class CID:\n    def __init__(self):\n        self._store = {}\n\n"
       "    def __setitem__(self, key, value):\n        self._store[key.lower()] = (KEY, value)\n")
# constructor arguments and an explicit field: replay must fold ctor.<name> by corder and set self.<name>
ACC = ("class Acc:\n    def __init__(self, base, scale=1):\n        self.base, self.scale, self.items = base, scale, []\n\n"
       "    def add(self, n):\n        self.items.append(self.base + n * self.scale{op})\n        return None\n")


def _trees(tmp_path, pre_src, post_src):
    for side, src in (("base", pre_src), ("post", post_src)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(src)
    return str(tmp_path / "base"), str(tmp_path / "post")


def _replay(w, base, post, confined=True):
    rep = differential.replay_witness(w, base, post, confined=confined)
    if confined and any(rep.get(s, {}).get("k") == "replay-error" for s in ("pre", "post")):
        pytest.skip(f"confined replay unavailable on this host: {rep.get('pre')}")
    return rep


def _cid_witness(pre_s="{_store={'σς': ('Σς', None)}}", post_s="{_store={'σς': ('σς', None)}}"):
    return {"module": "pkg.m", "qualname": "CID.__setitem__", "args": ["Σς", None], "kwargs": {}, "env": None,
            "inject": None, "receiver": {"cls": "CID", "cls_module": "pkg.m", "ctor": [[], {}], "kind": "instance",
                                         "corder": [], "accessor": None},
            "pre": {"k": "ret", "r": "None", "out": "", "g": "", "s": pre_s},
            "post": {"k": "ret", "r": "None", "out": "", "g": "", "s": post_s}}


def test_receiver_witness_replays_and_reproduces(tmp_path):
    base, post = _trees(tmp_path, CID.replace("KEY", "key"), CID.replace("KEY", "key.lower()"))
    rep = _replay(_cid_witness(), base, post)
    assert rep["replayable"] is True and rep["why"] is None, rep
    assert rep["confined"] is True
    assert rep["receiver_state_diverges"] is True, rep
    assert rep["reproduced"] is True, {k: v for k, v in rep.items() if k != "scripts"}
    assert "Σς" in rep["pre"]["recv"] and "Σς" not in rep["post"]["recv"], (rep["pre"], rep["post"])
    # still self-contained: no Hlith import in the per-side scripts
    assert not any(re.search(r"^\s*(?:import|from)\s+hlith\b", sc, re.M) for sc in rep["scripts"].values())


def test_negative_control_equal_receiver_state_does_not_reproduce(tmp_path):
    # both trees identical: the recording claims a receiver difference the code cannot produce
    base, post = _trees(tmp_path, CID.replace("KEY", "key"), CID.replace("KEY", "key"))
    rep = _replay(_cid_witness(), base, post)
    assert rep["replayable"] is True
    assert rep["receiver_state_diverges"] is False and rep["reproduced"] is False, rep


def test_negative_control_state_claim_not_satisfied_by_other_divergence(tmp_path):
    # post differs only in the RETURN value, the receiver state is the same: a recording that says the receiver
    # differs must not be credited by an unrelated divergence
    pre_src = CID.replace("KEY", "key")
    post_src = pre_src + "        return 1\n"
    base, post = _trees(tmp_path, pre_src, post_src)
    w = _cid_witness()
    w["post"]["r"] = "1"
    rep = _replay(w, base, post)
    assert rep["diverges"] is True, rep
    assert rep["receiver_state_diverges"] is False and rep["reproduced"] is False, rep


def test_ctor_fields_and_self_fields_are_rebuilt(tmp_path):
    base, post = _trees(tmp_path, ACC.format(op=""), ACC.format(op=" + 1"))
    w = {"module": "pkg.m", "qualname": "Acc.add", "args": [2], "kwargs": {"ctor.scale": 10, "self.base": 100},
         "receiver": {"cls": "Acc", "cls_module": "pkg.m", "ctor": [[7], {}], "kind": "instance",
                      "corder": ["base", "scale"], "accessor": None},
         "pre": {"k": "ret", "r": "None", "out": "", "s": "items=[120]"},
         "post": {"k": "ret", "r": "None", "out": "", "s": "items=[121]"}}
    rep = _replay(w, base, post)
    assert rep["reproduced"] is True, {k: v for k, v in rep.items() if k != "scripts"}
    # base 7 replaced by self.base=100 after construction, scale=10 by keyword (beyond the positional plan): 100+2*10
    assert "[120]" in rep["pre"]["recv"] and "[121]" in rep["post"]["recv"], (rep["pre"], rep["post"])


def test_ctor_field_overrides_a_positional_ctor_arg_by_corder(tmp_path):
    """review MUT-B: ctor.<name> for a name INSIDE the positional plan replaces that positional argument (corder index).
    Without the corder fold it would also go by keyword -> 'multiple values for base' on both sides -> not reproduced."""
    base, post = _trees(tmp_path, ACC.format(op=""), ACC.format(op=" + 1"))
    w = {"module": "pkg.m", "qualname": "Acc.add", "args": [2], "kwargs": {"ctor.base": 100},
         "receiver": {"cls": "Acc", "cls_module": "pkg.m", "ctor": [[7, 1], {}], "kind": "instance",
                      "corder": ["base", "scale"], "accessor": None},
         "pre": {"k": "ret", "r": "None", "out": "", "s": "items=[102]"},
         "post": {"k": "ret", "r": "None", "out": "", "s": "items=[103]"}}
    rep = _replay(w, base, post)
    assert rep["reproduced"] is True, {k: v for k, v in rep.items() if k != "scripts"}
    # positional 7 replaced by 100 (scale stays 1): 100 + 2 * 1
    assert "[102]" in rep["pre"]["recv"] and "[103]" in rep["post"]["recv"], (rep["pre"], rep["post"])


@pytest.mark.parametrize("rcv", [{"cls": "C"}, {"cls": "C", "kind": "instance"}, {"cls": "C", "kind": "instance", "ctor": "x"},
                                 {"kind": "instance", "ctor": [[], {}]}, {"cls": "C", "kind": "weird", "ctor": [[], {}]}])
def test_unusable_receiver_record_still_refused(rcv):
    rep = differential.replay_witness({"module": "pkg.m", "qualname": "C.m", "args": [], "kwargs": {}, "receiver": rcv,
                                       "pre": {"k": "ret", "r": "1"}, "post": {"k": "ret", "r": "2"}},
                                      "/nonexistent", "/nonexistent")
    assert rep["replayable"] is False and "receiver" in rep["why"] and rep["reproduced"] is False, rep


def test_end_to_end_receiver_refutation_witness_replays(tmp_path):
    """The differential's OWN recorded method witness (receiver dict incl. corder/accessor) replays and reproduces."""
    src = ("class Box:\n    def __init__(self):\n        self.v = 0\n\n    def put(self, n: int) -> None:\n"
           "        self.v = n{op}\n\n\ndef f(n: int) -> int:\n    return n\n")
    base, post = _trees(tmp_path, src.format(op=""), src.format(op=" * 2"))
    for side in (base, post):
        (tmp_path / side / "test_reach.py").write_text("import pkg.m as m\n\n\ndef test_r():\n    b = m.Box()\n    b.put(3)\n")
    (tmp_path / "proposer").mkdir()
    ob = differential.run_differential(base_root=base, post_root=post, module="pkg.m", function="Box.put",
                                       proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"),
                                       max_examples=20, max_seeds=300)
    wpath = tmp_path / "scratch" / "witness.json"
    assert ob.verdict is Verdict.REFUTED and wpath.is_file(), (ob.verdict, ob.stop_reason)
    w = json.loads(wpath.read_text())
    assert w.get("receiver") and {"corder", "accessor"} <= set(w["receiver"]), w.get("receiver")
    rep = _replay(w, base, post)
    assert rep["replayable"] is True and rep["reproduced"] is True, {k: v for k, v in rep.items() if k != "scripts"}
