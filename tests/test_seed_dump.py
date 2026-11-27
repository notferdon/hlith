"""case: the read-only seed dump is off by default and never changes the verdict."""
import json

from hlith import differential


def _world(tmp_path, tag, post_body):
    for side, body in (("base", "def f(s: str) -> str:\n    return s.strip().lower()\n"), ("post", post_body)):
        d = tmp_path / tag / side
        d.mkdir(parents=True)
        (d / "m.py").write_text(body)
    (tmp_path / tag / "prop").mkdir()
    return dict(base_root=str(tmp_path / tag / "base"), post_root=str(tmp_path / tag / "post"), module="m", function="f",
                proposer_paths=[str(tmp_path / tag / "prop")], scratch=str(tmp_path / tag / "scratch"), max_examples=20)


def _run(tmp_path, post_body):
    off = differential.run_differential(**_world(tmp_path, "off", post_body))
    on = differential.run_differential(**_world(tmp_path, "on", post_body), seed_dump=True)
    return off, on


def test_dump_off_by_default_and_verdict_unchanged_equivalent(tmp_path):
    off, on = _run(tmp_path, "def f(s: str) -> str:\n    t = s.strip()\n    return t.lower()\n")
    assert off.verdict == on.verdict
    assert not (tmp_path / "off" / "scratch" / "seed-dump.jsonl").exists()
    rows = [json.loads(x) for x in (tmp_path / "on" / "scratch" / "seed-dump.jsonl").read_text().splitlines()]
    assert rows and all(set(r) == {"args", "kwargs", "env", "inject"} for r in rows)


def test_verdict_unchanged_when_refuted(tmp_path):
    off, on = _run(tmp_path, "def f(s: str) -> str:\n    return s.strip().casefold()\n")
    assert off.verdict == on.verdict and off.verdict.value == "refuted"
    assert off.witness == on.witness
