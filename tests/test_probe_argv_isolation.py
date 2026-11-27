"""review (case, rule S P7 at root 223c310d): the Layer 5 probe must not show the probe runner's own argv to target code.

Real case: idna.cli.main(argv=None) and jmespath's bin/jp main() parse sys.argv. The probe ran them as
[python, -I, -c, _RUNNER, <mkdtemp>/spec.json], so the target saw a per-call random temp path: the feedback step crashed on idna
('probe failed (exit 2): idna: encode failed for /state/hlith-probe-spec-.../spec.json') and two identical trees could give two
different outcomes (a false pin). Required: target code sees one side-independent argv with no arguments, and identical trees give
identical outcomes. Real confinement, real processes."""

from __future__ import annotations

import sys

from hlith import feedback as fb
from hlith.types import Verdict

MOD, FN = "m", "main"
ARGV_READER = "import sys\n\ndef main(argv=None):\n    return repr(sys.argv[1:] if argv is None else argv)\n"


def _tree(root):
    (root / "src").mkdir(parents=True)
    (root / "src" / "m.py").write_text(ARGV_READER)
    return root / "src"


def _kw():
    return {"python": sys.executable, "call_timeout": 5.0}


def test_target_sees_no_runner_arguments(tmp_path):
    obs = fb.observe(_tree(tmp_path / "a"), MOD, FN, [{"args": [], "kwargs": {}}], **_kw())
    assert [o.get("kind") for o in obs.outcomes] == ["return"], obs.outcomes
    assert obs.outcomes[0]["repr"] == repr(repr([])), obs.outcomes  # no spec path, no runner flag


def test_identical_trees_never_refute_through_argv(tmp_path):
    base, post = _tree(tmp_path / "base"), _tree(tmp_path / "post")
    ob = fb.probe_obligation("o", base, post, MOD, FN, [{"args": [], "kwargs": {}}], None, **_kw())
    assert ob.verdict is not Verdict.REFUTED, ob


ARGPARSE_CLI = ("import argparse\n\ndef main(argv=None):\n    p = argparse.ArgumentParser(prog='cli')\n"
                "    p.add_argument('--mode', default='encode')\n    a = p.parse_args(argv)\n    return a.mode\n")


def test_argparse_cli_does_not_crash_the_probe(tmp_path):
    # the idna shape: an argparse CLI with argv=None parsed the runner's spec path and the probe step failed
    (tmp_path / "c" / "src").mkdir(parents=True)
    (tmp_path / "c" / "src" / "m.py").write_text(ARGPARSE_CLI)
    obs = fb.observe(tmp_path / "c" / "src", MOD, FN, [{"args": [], "kwargs": {}}], **_kw())
    assert obs.outcomes and obs.outcomes[0].get("kind") == "return" and obs.outcomes[0]["repr"] == repr("encode"), obs.outcomes


def test_target_sys_exit_is_an_outcome_not_a_probe_crash(tmp_path):
    (tmp_path / "e" / "src").mkdir(parents=True)
    (tmp_path / "e" / "src" / "m.py").write_text("import sys\n\ndef main(argv=None):\n    sys.exit(2)\n")
    obs = fb.observe(tmp_path / "e" / "src", MOD, FN, [{"args": [], "kwargs": {}}, {"args": [], "kwargs": {}}], **_kw())
    assert obs.outcomes == ({"kind": "raise", "exc": "builtins.SystemExit"},) * 2 or\
        list(obs.outcomes) == [{"kind": "raise", "exc": "builtins.SystemExit"}] * 2, obs.outcomes
