"""Annotation-bounded exploration is a DISCLOSED design (design review/maintainer): the disclosure must survive the operator surfaces, which truncate the unexplored
text at 170 (CLI line), 200 and 400 (TUI) characters. It is therefore the FIRST item, with a fixed token, and names the annotated parameters."""

from pathlib import Path
from types import SimpleNamespace

from hlith import derive, differential
from hlith.obligation import guard_certificate as gc
from hlith.types import Verdict

TOKEN = "ANNOTATION-BOUNDED:"


def _run(tmp_path: Path, src: str, fn: str = "f"):
    base, post, prop = tmp_path / "base", tmp_path / "post", tmp_path / "prop"
    for d in (base, post):
        d.mkdir()
        (d / "m.py").write_text(src)
    prop.mkdir()
    (prop / "x").write_text("x")
    return differential.run_differential(
        base_root=str(base), post_root=str(post), import_root="", module="m", function=fn, proposer_paths=[str(prop)],
        scratch=str(tmp_path / "scratch"), extra_sys_path=[], max_examples=30, max_seeds=50, require_impacted_slice=False)


def test_the_unexplored_text_starts_with_the_token_and_names_the_annotated_parameters(tmp_path):
    ob = _run(tmp_path, "def f(n: int, s: str):\n    return len(s) + n\n")
    u = ob.evidence.unexplored or ""
    assert ob.verdict is Verdict.HELD and u.startswith(TOKEN + " parameter(s) n: int, s: str"), (ob.verdict, u[:300])
    assert "inputs violating declared annotations are not explored" in u  # the older sentence stays (pinned elsewhere)
    assert u.index(TOKEN) < 170  # visible in the one-line CLI view


def test_an_unannotated_target_says_so_instead_of_silence(tmp_path):
    ob = _run(tmp_path, "def f(x):\n    return x\n")
    assert (ob.evidence.unexplored or "").startswith(TOKEN + " the target has no annotated parameter"), ob.evidence.unexplored[:200]


def test_a_guard_removal_held_carries_the_token_first():
    mc, rg = SimpleNamespace(qualified_name="m.f"), {"line": 2}
    rcov = SimpleNamespace(triggering=5, agreeing=40, evidence="observed")
    from hlith.types import CheckProvenance

    dob = SimpleNamespace(provenance=CheckProvenance(checker_id="hlith.differential", checker_sha256="0" * 64, confined=True,
                                                     proposer_paths_readable=False, profile_sha256="1" * 64, exit_code=0))  # a HELD needs real provenance
    ob = derive._removal_obligation(mc, rg, rcov, gc.Cert(gc.PROVED, "ok"), dob, lambda c: None)
    assert ob.verdict is Verdict.HELD and ob.evidence.unexplored.startswith(TOKEN), ob.evidence.unexplored[:200]
