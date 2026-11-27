# SPDX-License-Identifier: Apache-2.0
"""case (real case: requests resolve_proxies, the recorded case). Predeclared before the first run.

(a) POLARITY: an unannotated parameter is also fed opaque stub values whose truthiness is a user `__bool__`; their polarity
    is not observable. That must not poison a condition whose True AND False were both observed on clean values (stubs add
    no information, they remove none). A condition that never saw both polarities stays a gap.
(b) ENVIRONMENT AS AN INPUT THROUGH CALLEES: the target never reads os.environ itself, a repository callee does (and so does
    the stdlib proxy reader). The env keys those callees read join the env domain, so the branch they guard is entered.
Both are INPUT-construction fixes: no check is relaxed (a changed statement still has to be entered and its ablation live)."""
from hlith import differential
from hlith.types import Verdict

_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"


def _run(tmp_path, base, post, function="f"):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function=function,
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=200, max_examples=20,
        adequacy_gate=True)


_POL = "def f(a: int, flag) -> int:\n    if flag and a > 0:\n        return a + 1\n    return a\n"


def test_equivalent_edit_with_a_stub_fed_flag_is_still_decided_or_named(tmp_path):
    ob = _run(tmp_path, _POL, _POL.replace("return a + 1", "return 1 + a"))
    assert ob.verdict in (Verdict.HELD, Verdict.UNVERIFIED), (ob.verdict, ob.witness)  # never REFUTED: they are equal


def test_a_condition_that_never_took_both_polarities_is_still_a_gap(tmp_path):
    base = "def f(a: int, flag) -> int:\n    if flag and a > 5 and a < 3:\n        return a + 1\n    return a\n"
    ob = _run(tmp_path, base, base.replace("return a + 1", "return 1 + a"))
    assert ob.verdict is not Verdict.HELD, ob  # unsatisfiable: its True polarity is never seen, with or without stubs


_ENV = '''import os


def _proxy():
    return os.environ.get("HLITH_TEST_PROXY", "")


def f(url: str) -> dict:
    out = {}
    p = _proxy()
    if p:
        out["proxy"] = p
    return out
'''


def test_env_read_by_a_callee_is_an_input(tmp_path):
    ob = _run(tmp_path, _ENV, _ENV.replace('out["proxy"] = p', 'out.setdefault("proxy", p)'))
    assert ob.verdict is Verdict.HELD, (ob.verdict, ob.stop_reason)


def test_env_read_by_a_callee_exposes_a_divergence(tmp_path):
    ob = _run(tmp_path, _ENV, _ENV.replace('out["proxy"] = p', 'out["proxy"] = p.upper()'))
    assert ob.verdict is Verdict.REFUTED and "HLITH_TEST_PROXY" in (ob.witness or ""), ob


# ---- the polarity decision itself (unit): opaque observations carry no information, they neither count nor cancel -----------
def test_polarity_gap_decision_stays_strict():
    """Measured against real resolve_proxies, relaxing this let a divergent edit (P2) be HELD: it stays strict."""
    gap = differential._polarity_gap
    assert gap({"True", "False"}) is None
    assert gap({"True", "False", "opaque"}) == "opaque"  # real trust_env: ['False', 'True', 'opaque'] - still a gap
    assert gap({"opaque"}) == "opaque" and gap({"True", "opaque"}) == "opaque"
    assert gap({"True"}) == "False" and gap({"False"}) == "True" and gap(set()) == "False/True"


# ---- (b) the stdlib proxy readers are env inputs (real case: resolve_proxies -> get_environ_proxies -> getproxies) -------
_PX = '''from urllib.request import getproxies


def _env_proxy(scheme):
    return getproxies().get(scheme)


def f(url: str, trust_env: bool = True) -> dict:
    out = {}
    if trust_env:
        p = _env_proxy("http")
        if p:
            out["http"] = p
    return out
'''


def test_env_reads_follows_the_stdlib_proxy_readers():
    import ast

    tree = ast.parse(_PX)
    target = next(n for n in tree.body if getattr(n, "name", "") == "f")
    reads, keys = differential._env_reads(tree, target)
    assert reads and {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} <= keys, (reads, keys)


def test_proxy_read_through_the_stdlib_exposes_a_divergence(tmp_path):
    ob = _run(tmp_path, _PX, _PX.replace("    if trust_env:\n", "    if not trust_env:\n"))
    assert ob.verdict is Verdict.REFUTED, ob


def test_proxy_read_through_the_stdlib_equivalent_edit_is_held(tmp_path):
    ob = _run(tmp_path, _PX, _PX.replace('out["http"] = p', 'out.setdefault("http", p)'))
    assert ob.verdict is Verdict.HELD, (ob.verdict, ob.stop_reason)


def test_env_sweep_crosses_a_flipped_flag(tmp_path):
    """Real case P2 (`and` -> `or`): the divergence needs trust_env False TOGETHER with an environment proxy. The env sweep
    must cross env values with each parameter's own candidates (a bool flipped), not only with the 'rich' call."""
    ob = _run(tmp_path, _PX, _PX.replace("    if trust_env:\n", "    if trust_env or url:\n"))
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)


_PX_STUBBED = _PX.replace("def f(url: str, trust_env: bool = True) -> dict:", "def f(url: str, trust_env=True) -> dict:")


def test_env_sweep_crosses_a_flipped_flag_when_the_parameter_has_its_own_candidates(tmp_path):
    """Real case P2 again: an UNANNOTATED trust_env is fed stub candidates, so the candidate list is non-empty and never
    contains the flipped bool; the flip must still be crossed with the environment."""
    ob = _run(tmp_path, _PX_STUBBED, _PX_STUBBED.replace("    if trust_env:\n", "    if trust_env or url:\n"))
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)


_PX_WIDE = _PX.replace("def f(url: str, trust_env: bool = True) -> dict:",
                       "def f(a: str, b: str, c: str, d: str, url: str, trust_env=True) -> dict:")


def test_flag_flip_is_not_starved_by_earlier_parameters(tmp_path):
    """The priority calls were built parameter by parameter and cut at 13: a flag AFTER several other parameters never got
    its flip (real resolve_proxies: request, proxies, trust_env). Interleaved round-robin: every parameter gets one."""
    ob = _run(tmp_path, _PX_WIDE, _PX_WIDE.replace("    if trust_env:\n", "    if trust_env or url:\n"))
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)


_PX_URL = '''from urllib.request import getproxies


def f(url: str, trust_env=True) -> dict:
    out = {}
    if trust_env and url.startswith("http"):
        p = getproxies().get("http")
        if p:
            out["http"] = p
    return out
'''


def test_env_sweep_crosses_literal_calls_with_a_flipped_flag(tmp_path):
    """Real case P2 (resolve_proxies `and` -> `or`): the divergence needs trust_env False AND a URL that has a scheme AND an
    environment proxy. The rich call's URL has no scheme; the call that does must also be tried with the flag flipped."""
    post = _PX_URL.replace("if trust_env and url.startswith", "if trust_env or url.startswith")
    ob = _run(tmp_path, _PX_URL, post)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)


def test_diverse_alternates_are_spread_over_the_whole_list():
    d = differential._diverse_alts
    assert d([1, 2, 3], 12) == [1, 2, 3]
    big = list(range(100))
    out = d(big, 12)
    assert len(out) == 12 and out[0] == 0 and out[-1] >= 90 and out == sorted(out) and len(set(out)) == 12
    twelve = list(range(12))
    assert d(twelve, 12) == twelve and 8 in d(twelve, 12)  # real case: the 9th of 12 request candidates is kept
