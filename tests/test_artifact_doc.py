"""docs/ARTIFACT.md is generated from the schema (scripts/gen_artifact_doc.py); it must never drift (design review 2026-11-13)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _gen():
    spec = importlib.util.spec_from_file_location("gen_artifact_doc", ROOT / "scripts/gen_artifact_doc.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_artifact_doc_matches_the_generator():
    assert (ROOT / "docs/ARTIFACT.md").read_text() == _gen().generate(),\
        "docs/ARTIFACT.md is stale: run python3 -I scripts/gen_artifact_doc.py --write"


def test_generator_refuses_a_schema_key_without_a_note(monkeypatch, tmp_path):
    import json

    import pytest

    g = _gen()
    real = json.loads(g.SCHEMA.read_text())
    real["properties"]["brand_new_key"] = {"type": "string"}
    tmp = tmp_path / "schema.json"
    tmp.write_text(json.dumps(real))
    monkeypatch.setattr(g, "SCHEMA", tmp)
    with pytest.raises(SystemExit, match="brand_new_key"):
        g.generate()
