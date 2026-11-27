"""Public claims are asserted against the code they describe (finalisation plan: "key public claims are test-asserted, not hand-written prose").

Each test pins one sentence family of the shipped docs to its source anchor, so a code change that falsifies a doc claim (or a doc edit that overclaims)
fails here. Read-only: no confinement, no subprocess, no network."""

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = ["README.md", "LIMITATIONS.md", "SECURITY.md", "ARCHITECTURE.md", "CONTRIBUTING.md", "CHANGELOG.md", "docs/SUPPORTED_DOMAIN.md",
               "docs/REVIEW-QUICKSTART.md", "docs/AGENT-INTEGRATION.md", "docs/CLI.md", "docs/TUI.md", "docs/OPERATOR.md"]


def doc(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("> ", " "))


def test_exit_code_table_matches_the_engine_constants():
    from hlith import types
    row = {m.group(2): int(m.group(1)) for m in re.finditer(r"^\| `(\d+)` \| ([A-Z][A-Z-]+)", doc("README.md"), re.M)}
    assert row.get("REFUTED") == types.EXIT_REFUTED
    assert row.get("UNVERIFIED") == types.EXIT_UNVERIFIED
    assert row.get("NOT-DERIVED") == types.EXIT_NOT_DERIVED
    assert row.get("BOUNDARY") == types.EXIT_BOUNDARY
    assert row.get("LANDED") == types.EXIT_LANDED
    from hlith.contract.errors import EXIT_INTERNAL
    assert row.get("INTERNAL") == EXIT_INTERNAL
    src = (ROOT / "src/hlith/operator/check.py").read_text(encoding="utf-8")
    assert '"INTERNAL ERROR" if rc == EXIT_INTERNAL' in src and "hlith: internal error: the review engine failed (" in src


def test_check_is_headless_on_a_tty_and_docs_do_not_require_no_input():
    src = (ROOT / "src/hlith/operator/cli.py").read_text(encoding="utf-8")
    assert "if not REVIEW_ONLY and not no_input and sys.stdin.isatty() and sys.stdout.isatty():" in src
    for rel in PUBLIC_DOCS:
        text = doc(rel)
        assert not re.search(r"(Always|always) pass `--no-input`|without it on a TTY|so pass `--no-input`|use `--no-input` \(on a terminal", text), rel


@pytest.mark.parametrize("rel", ["README.md", "LIMITATIONS.md", "SECURITY.md", "docs/SUPPORTED_DOMAIN.md"])
def test_observation_boundary_sentence_is_quoted_verbatim(rel):
    from hlith import differential
    assert flat(differential._OBSERVATION_BOUNDARY) in flat(doc(rel)), rel


def test_certificate_scope_text_is_quoted_verbatim():
    from hlith.obligation import closure_gate
    assert flat(closure_gate.SCOPE) in flat(doc("docs/SUPPORTED_DOMAIN.md"))


def _landlock_source() -> ast.FunctionDef:
    tree = ast.parse((ROOT / "src/hlith/hostio/confine_exec.py").read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "landlock")


def test_landlock_floor_is_abi_6_as_documented():
    fn = _landlock_source()
    floors = [c.comparators[0].value for c in ast.walk(fn) if isinstance(c, ast.Compare) and isinstance(c.left, ast.Name) and c.left.id == "abi"
              and isinstance(c.ops[0], ast.Lt) and isinstance(c.comparators[0], ast.Constant)]
    assert 6 in floors and max(floors) == 6, floors
    for rel in ("README.md", "LIMITATIONS.md", "SECURITY.md"):
        assert re.search(r"ABI (6 or newer|≥ 6)", doc(rel)), rel


def test_no_pathname_socket_or_udp_landlock_right_is_requested_and_docs_do_not_claim_one():
    names = {n.id for n in ast.walk(_landlock_source()) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(_landlock_source()) if isinstance(n, ast.Attribute)}
    assert not {x for x in names if "RESOLVE_UNIX" in x or "UDP" in x}, names
    for rel in PUBLIC_DOCS:
        text = doc(rel)
        assert not re.search(r"ABI ?(9|10)\b", text), f"{rel}: ABI 9/10 is unverified here and must not be asserted"


def test_review_only_posture_matches_the_docs():
    from hlith.operator import product
    assert product.REVIEW_ONLY is True
    for rel in ("README.md", "LIMITATIONS.md", "SECURITY.md"):
        assert re.search(r"`apply`, `run`(,| and) `resume`", doc(rel)), rel


def test_replay_exit_codes_and_export_exit_rule_match_the_code():
    from hlith.operator import replay_cmd as r
    assert (r.EXIT_REPRODUCED, r.EXIT_NOT_REPRODUCED, r.EXIT_USAGE, r.EXIT_INTERNAL, r.EXIT_BOUNDARY, r.EXIT_NOT_REPLAYABLE) == (0, 1, 2, 3, 4, 12)
    assert "`replay` returns `0` (`REPRODUCED`), `1` (`NOT REPRODUCED`), `12` (`NOT REPLAYABLE`), `4` (`BOUNDARY`), `2` (`USAGE`), or `3` (`INTERNAL`)" in doc("docs/CLI.md")
    src = (ROOT / "src/hlith/operator/replay_cmd.py").read_text(encoding="utf-8")
    assert 'print(f"pytest witness NOT EXPORTED: {exc}", file=sys.stderr)' in src and "pytest witness: {written}" in src
    for rel in ("README.md", "LIMITATIONS.md", "docs/CLI.md", "docs/REVIEW-QUICKSTART.md"):
        text = doc(rel)
        assert "A refused export does not change replay's exit status" in text and "`pytest_export.status`" in text, rel
        assert not re.search(r"NOT EXPORTED`?,? \(?exit (1/)?12", text), f"{rel}: export refusal is not exit 12"
        assert "`legacy-witness:`" in text, rel
    assert 'raise NotExportable("legacy-witness:' in (ROOT / "src/hlith/contract/witness.py").read_text(encoding="utf-8")


def test_no_write_command_is_reachable_and_docs_say_so():
    from hlith.operator import cli
    from hlith.operator.tui import launch
    assert cli.ENGINE_COMMANDS == ()
    for name in ("run", "resume", "propose-deltas", "apply"):
        try:
            code = cli.main([name, "--help"])
        except SystemExit as e:
            code = e.code
        assert code == 2, name
    assert flat(launch.UNAVAILABLE_REASON) in flat(doc("docs/TUI.md")) and flat(launch.UNAVAILABLE_REASON) in flat(doc("LIMITATIONS.md"))
    for rel in PUBLIC_DOCS:
        text = doc(rel)
        assert not re.search(r"marker/token|forges? (the|Hlith's) (internal|host)|TUI's plan\+start", text), f"{rel}: describes the removed check authorisation"


def test_pytest_export_requires_expect(capsys):
    from hlith.operator.cli import main
    try:
        code = main(["replay", "run-000000000000", "--repo", str(ROOT), "--pytest-out", "/nonexistent/hlith_witness.py"])
    except SystemExit as e:
        code = e.code
    assert code == 2
    assert not Path("/nonexistent/hlith_witness.py").exists()
    assert "--expect" in capsys.readouterr().err
    assert "`--pytest-out` alone is a usage error" in doc("README.md")


OVERCLAIMS = {
    r"\bnever writes?\b(?! (into|to) (the|your) (checked )?repository; deliberate)": "absolute non-write claim (the boundary is the supported workflow)",
    r"independently replayable witness": "not every REFUTED is standalone-replayable",
    r"resisted by syntactic lint": "no such mechanism exists",
    r"\b(R1|F2|F4|T1|T2|R2 sealed|14 contract)\b(?! (identical|approved|guard|boolean))": "internal acceptance identifier in a public doc",
    r"safe to merge": "HELD is review evidence, not merge permission",
}


@pytest.mark.parametrize("rel", PUBLIC_DOCS)
def test_public_docs_carry_no_known_overclaim(rel):
    text = doc(rel)
    hits = [(why, m.group(0)) for pat, why in OVERCLAIMS.items() for m in re.finditer(pat, text) if not _negated(text, m.start())]
    assert not hits, f"{rel}: {hits}"


def _negated(text: str, at: int) -> bool:
    """A sentence that states the claim in order to deny it ("Do not claim 'safe to merge'") is not an overclaim."""
    start = max(text.rfind(".", 0, at), text.rfind("\n", 0, at)) + 1
    return bool(re.search(r"\b(not|never|no|don't|do not)\b", text[start:at], re.I))


@pytest.mark.parametrize("rel", ["README.md", "LIMITATIONS.md", "CHANGELOG.md"])
def test_external_observation_is_not_presented_as_an_accidental_regression(rel):
    """The only recorded external example is an intentional/requested contract change; do not present it as a regression rate."""
    text = doc(rel)
    assert re.search(r"(?:intentional|requested)[^.]*contract change|contract change[^.]*(?:intentional|requested)", text, re.I), rel
    assert not re.search(r"[Uu]nintended regressions found in real repositories( so far)?: 0\b", text), rel


def test_readme_does_not_present_a_requested_or_curated_change_as_a_real_regression():
    text = doc("README.md")
    assert "## Example: a real regression" not in text
    assert "catches behavior and contract changes your tests miss" in text
    assert "value=0" in text and "--expect pre" in text  # the recorded external contract-change observation and guard export
    assert not re.search(r"\brun-[0-9a-f]{12}\b", text), "README must not embed private run IDs users cannot replay"
    assert "examples/first-use" in text and (ROOT / "examples/first-use/README.md").is_file()
    assert "source .venv/bin/activate" in text and "uv run --frozen" in text


APPLY_INSTRUCTIONS = r"EXPLICIT APPLY|opens? Apply review|`y` (explicitly )?confirms? Apply|--confirm\b|apply token|hlith (apply|run|resume|propose-deltas) --"


@pytest.mark.parametrize("rel", PUBLIC_DOCS)
def test_no_public_doc_instructs_a_command_this_distribution_does_not_offer(rel):
    """Review-only: apply/run/resume/propose-deltas and TUI Apply are not offered, so no public doc may tell a reader how to use them."""
    hits = re.findall(APPLY_INSTRUCTIONS, doc(rel))
    assert not hits, f"{rel}: {hits}"


HOOK_SCRIPT = ROOT / "scripts/agent-hook/hlith-agent-hook.sh"


def test_agent_hook_strings_in_docs_are_the_scripts_own():
    """docs/AGENT-INTEGRATION.md quotes the hook's model-visible text; each quoted sentence must exist verbatim in the script it describes."""
    if not HOOK_SCRIPT.exists():
        pytest.skip("agent hook not in this tree (integrated from the P2.7 branch)")
    script = HOOK_SCRIPT.read_text(encoding="utf-8")
    section = doc("docs/AGENT-INTEGRATION.md").split("## Background hook for a coding agent", 1)[1].split("\n## ", 1)[0]
    quoted = [q.split(" Receipt: <path>")[0] for q in re.findall(r"`((?:hlith check|A REFUTED|Resolve it|BUT the)[^`]{30,})`", section)]
    assert len(quoted) == 9, quoted
    for q in quoted:
        assert q in script, q
    assert "hlith\" apply" not in script and " apply " not in script.split("Never runs", 1)[0]


LEGACY_RUNS = ("run-77aff76b095d", "run-40faf59c0291", "run-2564772809dc")  # recorded before the versioned witness record (P2.4 C5)


@pytest.mark.parametrize("rel", PUBLIC_DOCS)
def test_no_doc_tells_users_to_export_a_legacy_run(rel):
    for para in re.split(r"\n#+ ", doc(rel)):  # per heading section
        if any(r in para for r in LEGACY_RUNS) and "--pytest-out" in para:
            assert "legacy-witness:" in para and "refuses" in para, f"{rel}: export instruction on a legacy run: {para[:200]}"
