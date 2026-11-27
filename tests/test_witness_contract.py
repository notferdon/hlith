"""P2.4 typed witness record, export contract and replay envelope.

Default tier: pure adapter / exporter / argument-error rows. Full tier (HLITH_CONTRACT_FULL=1): real recordings from the
differential, replayed confined and exported, and the replay command on a real run artifact.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hlith import differential
from hlith.contract import codec, witness as ws
from hlith.operator.witness_export import NotExportable, write_pytest

full_only = pytest.mark.skipif(os.environ.get("HLITH_CONTRACT_FULL") != "1",
                               reason="runs confined engine work; set HLITH_CONTRACT_FULL=1")

CALL = {"module": "m", "qualname": "f", "args": [1], "kwargs": {}, "env": None, "inject": None, "receiver": None,
        "pre": {"k": "ret", "r": "2", "unrepr": False, "out": "", "g": ""},
        "post": {"k": "ret", "r": "3", "unrepr": False, "out": "", "g": ""}}


def _with(side: str, **fields) -> dict:
    call = copy.deepcopy(CALL)
    call[side].update(fields)
    return call


def _refused(tmp_path: Path, call: dict, match: str) -> None:
    for expect in ("pre", "post"):
        out = tmp_path / "new" / "deep" / "t.py"
        with pytest.raises(NotExportable, match=match):
            write_pytest(out, ws.adapt(call), expect=expect)
        assert not (tmp_path / "new").exists()


def test_adapter_is_versioned_deterministic_and_does_not_touch_the_call():
    call = copy.deepcopy(CALL)
    first = ws.adapt(call)
    assert call == CALL
    assert first["schema_version"] == 1 and type(first["schema_version"]) is int
    assert first == ws.adapt(json.loads(json.dumps(call)))
    assert json.loads(codec.canonical_bytes(first)) == first, "the record must be storable in a canonical artifact"
    assert first["pre"]["value"] == {"text": "2", "fidelity": "exact", "masks": []}
    assert first["complete"] is True and first["unknown"] == [] and first["oracle"] == "differential"


@pytest.mark.parametrize("message,m_only,role", [("boom", True, "behaviour"), ("args=('k',)", False, "data"),
                                                 ("", False, "informational")])
def test_adapter_message_role(message, m_only, role):
    outcome = {"k": "exc", "t": "builtins.ValueError", "m": message}
    if not m_only:
        outcome["mi"] = "raw"
    assert ws.adapt({**CALL, "pre": outcome})["pre"]["role"] == role


@pytest.mark.parametrize("text,fidelity", [("'a'", "exact"), ("'<tree>/m.py'", "masked"), ("<m.C object at 0x?>", "masked"),
                                           ("head…#0123456789abcdef", "capped"),
                                           ("'x...<4000 chars sha256:0123456789abcdef>", "capped"),
                                           ("<unrepresentable>", "opaque")])
def test_adapter_text_fidelity(text, fidelity):
    assert ws.adapt(_with("post", r=text))["post"]["value"]["fidelity"] == fidelity


@pytest.mark.parametrize("flag", ["lazy", "unrepr", "iter_raised", "rng", "thr", "nothrow"])
@pytest.mark.parametrize("side", ["pre", "post"])
def test_unstable_or_non_plain_outcome_is_refused(tmp_path, side, flag):
    _refused(tmp_path, _with(side, **{flag: True}), "not a plain stable value")


def test_unrecognised_fields_block_export(tmp_path):
    _refused(tmp_path, {**CALL, "later_field": 1}, "unrecognised fields")
    _refused(tmp_path, _with("post", later=1), "unrecognised fields")
    _refused(tmp_path, {**CALL, "oracle": "later-oracle"}, "oracle")
    _refused(tmp_path, {**CALL, "phase": "universe_import"}, "import")


def test_wx_is_not_behaviour(tmp_path):
    write_pytest(tmp_path / "t.py", ws.adapt(_with("post", wx="DeprecationWarning: x")), expect="pre")


@pytest.mark.parametrize("version", [0, 2, "1", True, None, 1.0])
def test_only_integer_version_1_is_exported(tmp_path, version):
    with pytest.raises(NotExportable, match="schema_version"):
        write_pytest(tmp_path / "t.py", dict(ws.adapt(CALL), schema_version=version), expect="pre")


def test_record_must_match_the_replayed_call():
    record = ws.adapt(CALL)
    assert ws.record_for_export(CALL, record) is record
    with pytest.raises(NotExportable, match="does not match"):
        ws.record_for_export(_with("pre", r="99"), record)
    with pytest.raises(NotExportable, match="legacy"):
        ws.record_for_export(CALL, None)


@pytest.mark.parametrize("mutate", [lambda r: r.pop("call"), lambda r: r.update(extra=1),
                                    lambda r: r["call"].update(extra=1), lambda r: r["pre"].pop("channels")])
def test_malformed_record_is_refused_not_crashed(tmp_path, mutate):
    record = ws.adapt(CALL)
    mutate(record)
    with pytest.raises(NotExportable):
        write_pytest(tmp_path / "t.py", record, expect="pre")


def test_refusal_leaves_an_existing_output_untouched(tmp_path):
    out = tmp_path / "t.py"
    out.write_text("keep\n")
    with pytest.raises(NotExportable):
        write_pytest(out, ws.adapt(_with("post", w="UserWarning: x")), expect="pre")
    assert out.read_text() == "keep\n" and sorted(p.name for p in tmp_path.iterdir()) == ["t.py"]


@pytest.mark.parametrize("shape", ["directory", "parent-is-file"])
def test_unwritable_output_is_a_refusal_with_nothing_left_behind(tmp_path, shape):
    if shape == "directory":
        out = tmp_path / "t.py"
        out.mkdir()
    else:
        (tmp_path / "file").write_text("x")
        out = tmp_path / "file" / "t.py"
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    with pytest.raises(NotExportable):
        write_pytest(out, ws.adapt(CALL), expect="pre")
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "PYTHONPATH": str(Path(ws.__file__).resolve().parents[2]),
           "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "hlith.operator.cli", "replay", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("args,export", [
    (["x.json", "--json", "--expect", "sideways"], None),
    (["--json"], None),
    (["x.json", "--json", "--pytest-out"], "not-attempted"),
    (["x.json", "--pytest-out", "w/t.py", "--expect", "sideways", "--json"], "not-attempted"),
    (["x.json", "--json", "--emit-pytest", "w/t.py"], "not-attempted"),
    (["missing.json", "--json"], None),
])
def test_json_usage_errors_always_carry_the_envelope(tmp_path, args, export):
    proc = _cli(*args, cwd=tmp_path)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    envelope = json.loads(proc.stdout)
    assert envelope["envelope"] == "hlith.replay/1" and envelope["status"] == "USAGE ERROR" and envelope["exit_status"] == 2
    assert envelope["why"]
    assert (envelope["pytest_export"] or {}).get("status") == export
    assert list(tmp_path.iterdir()) == []


def test_argument_errors_without_json_print_nothing_on_stdout(tmp_path):
    proc = _cli("x.json", "--expect", "sideways", cwd=tmp_path)
    assert proc.returncode == 2 and proc.stdout == "" and "usage:" in proc.stderr


# ---------------------------------------------------------------- full tier: real recording -> replay -> export

# name: (base body, post body, expected export: None = written, else a substring of the refusal)
MATRIX = {
    "int-return": ("def f(n: int):\n    return n + 1\n", "def f(n: int):\n    return n + 2\n", None),
    "str-return": ("def f(n: int):\n    return 'a' * 2\n", "def f(n: int):\n    return 'b' * 2\n", None),
    "none-return": ("def f(n: int):\n    return None\n", "def f(n: int):\n    return -1\n", None),
    "float-return": ("def f(n: int):\n    return n + 0.5\n", "def f(n: int):\n    return n - 0.5\n", None),
    "raise-to-return": ("def f(n: int):\n    raise ValueError('limit exceeded')\n", "def f(n: int):\n    return 1\n", None),
    "keyerror": ("def f(n: int):\n    return {}['left']\n", "def f(n: int):\n    return 1\n", None),
    "printed": ("def f(n: int):\n    return n\n", "def f(n: int):\n    print('x')\n    return n\n", "printed output"),
    "warning": ("def f(n: int):\n    return n\n",
                "import warnings\ndef f(n: int):\n    warnings.warn('old')\n    return n\n", "warnings channel"),
    "global-write": ("SEEN = []\ndef f(n: int):\n    return n\n",
                     "SEEN = []\ndef f(n: int):\n    SEEN.append(n)\n    return n\n", "state-write channel"),
    "list-argument": ("def f(xs: list[int]):\n    return len(xs)\n", "def f(xs: list[int]):\n    return len(xs) + 1\n",
                      "state channel"),
    "container": ("def f(n: int):\n    return n + 1\n", "def f(n: int):\n    return [n + 1]\n", "container"),
    "generator": ("def f(n: int):\n    yield n\n", "def f(n: int):\n    yield n + 1\n", "not a plain stable value"),
    "float-argument": ("def f(x: float):\n    return 1\n", "def f(x: float):\n    return 2\n", "evaluator marker"),
    "long-return": ("def f(n: int):\n    return 'a' * 5000\n", "def f(n: int):\n    return 'b' * 5000\n", "truncated"),
}
BROKEN = "def f(*a):\n    raise RuntimeError('neither recorded side')\n"


def _run_exported(test: Path, tree: Path) -> int:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tree), "HLITH_WITNESS_ROOT": str(tree), "PYTHONDONTWRITEBYTECODE": "1"}
    boot = ("import sys; sys.modules['hlith'] = None; import pytest; "
            f"sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', {str(test)!r}]))")
    return subprocess.run([sys.executable, "-I", "-B", "-c", boot], cwd=tree, env=env, capture_output=True, text=True,
                          timeout=120).returncode


@full_only
@pytest.mark.parametrize("name", list(MATRIX))
def test_real_recording_replays_and_exports_or_refuses(tmp_path, name):
    base_body, post_body, refusal = MATRIX[name]
    for side, body in (("base", base_body), ("post", post_body), ("broken", BROKEN)):
        (tmp_path / side).mkdir()
        (tmp_path / side / "mwit.py").write_text(body)
    (tmp_path / "proposer").mkdir()
    differential.reset_observed_witnesses()
    obligation = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="mwit", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_examples=60)
    observed = differential.observed_witnesses()
    differential.reset_observed_witnesses()
    assert obligation.verdict.value == "refuted" and observed, obligation
    # exactly what an artifact stores
    call = json.loads(codec.canonical_bytes(codec.encode_call_values(observed[-1]["witness_call"])))
    record = json.loads(codec.canonical_bytes(ws.adapt(call)))
    replay = differential.replay_witness(call, str(tmp_path / "base"), str(tmp_path / "post"))
    assert replay.get("reproduced"), (call, replay.get("why"), replay.get("why_not_reproduced"))
    assert ws.record_for_export(call, record) is record
    for expect in ("pre", "post"):
        out = tmp_path / "out" / f"test_{expect}.py"
        if refusal:
            with pytest.raises(NotExportable, match=refusal):
                write_pytest(out, record, expect=expect)
            assert not out.parent.exists()
            continue
        write_pytest(out, record, expect=expect)
        results = tuple(_run_exported(out, tmp_path / side) for side in ("base", "post", "broken"))
        assert results == ((0, 1, 1) if expect == "pre" else (1, 0, 1)), (call, results)


@full_only
def test_replay_command_on_a_real_artifact(tmp_path):
    import test_review_contract_suite as suite

    box = suite.box.__wrapped__(tmp_path)
    box = next(box) if hasattr(box, "__next__") else box
    repo = suite.make_repo(box["tmp"] / "fx")
    proc, _ = suite._check(box, repo, "refute.patch", box["tmp"] / "r")
    assert proc.returncode == 10, proc.stderr[-1500:]
    artifact = box["tmp"] / "r" / "out.json"
    original = artifact.read_text()
    data = json.loads(original)
    row = next(o for o in data["obligations"] if o.get("witness_call"))
    assert row["witness_record"] == ws.adapt(row["witness_call"])

    def replay(mutate=None, *extra):
        doc = json.loads(original)
        if mutate:
            mutate(next(o for o in doc["obligations"] if o.get("witness_call")))
        artifact.write_text(json.dumps(doc))
        done = suite.hlith(box, "replay", str(artifact), "--repo", str(repo), "--json", *extra)
        return done.returncode, json.loads(done.stdout)

    code, env = replay()
    assert (code, env["status"], env["pytest_export"]) == (0, "REPRODUCED", None), env
    out = box["tmp"] / "w" / "t.py"
    asked = ("--pytest-out", str(out), "--expect", "pre")
    for mutate, reason in ((lambda o: o.pop("witness_record"), "legacy-witness"),
                           (lambda o: o["witness_record"].update(schema_version=2), "schema_version"),
                           (lambda o: o["witness_record"]["pre"]["value"].update(text="99"), "does not match")):
        code, env = replay(mutate, *asked)
        assert (code, env["status"], env["pytest_export"]["status"]) == (0, "REPRODUCED", "refused"), env
        assert reason in env["pytest_export"]["reason"] and env["pytest_export"]["path"] is None
        assert not out.parent.exists()

    def never_recorded(o):
        o["witness_call"]["pre"]["r"] = "12345"

    code, env = replay(never_recorded, *asked)
    assert (code, env["status"], env["pytest_export"]["status"]) == (1, "NOT REPRODUCED", "not-attempted"), env
    assert not out.parent.exists()
    code, env = replay(lambda o: o.pop("witness_call"), *asked)
    assert (code, env["status"], env["pytest_export"]["status"]) == (12, "NOT REPLAYABLE", "not-attempted"), env
    code, env = replay(None, "--obligation", "nope", *asked)
    assert (code, env["status"], env["pytest_export"]["status"]) == (2, "USAGE ERROR", "not-attempted"), env
    code, env = replay(None, *asked)
    assert (code, env["pytest_export"]["status"], env["pytest_export"]["path"]) == (0, "written", str(out)), env
    assert out.is_file()


# ---------------------------------------------------------------- static pytest witness generation & safety contracts


def _static_ast_invariants(src: str, *, expect: str, module: str, root_name: str) -> None:
    import ast

    tree = ast.parse(src)
    assert len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef)
    assert tree.body[0].name == f"test_recorded_{expect}_behavior"
    imports = set()
    from_imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            from_imports.add((node.module, tuple(a.name for a in node.names)))
            imports.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id != "getattr"
            elif isinstance(node.func, ast.Attribute):
                assert node.func.attr != "getattr"
    assert not (imports & {"hlith", "importlib", "json"}), imports
    assert (module, (root_name,)) in from_imports, from_imports
    assert "# Provenance:" in src


def test_static_export_uses_direct_import_direct_call_and_provenance(tmp_path):
    from hlith.operator.witness_export import build_pytest_source

    call = {
        **CALL,
        "module": "pkg.limits",
        "qualname": "effective_timeout",
        "args": [-1, "x", None, True],
        "kwargs": {"limit": 300, "from": 2, "a-b": [1, {"k": "v"}]},
    }
    src = build_pytest_source(
        ws.adapt(call),
        import_root="src",
        base_commit="a" * 40,
        post_tree="b" * 40,
        expect="pre",
    )
    _static_ast_invariants(src, expect="pre", module="pkg.limits", root_name="effective_timeout")
    assert "from pkg.limits import effective_timeout" in src
    assert "effective_timeout(-1, 'x', None, True, limit=300, **{'a-b': [1, {'k': 'v'}], 'from': 2})" in src
    prov_line = [ln for ln in src.splitlines() if ln.startswith("# Provenance: ")][-1]
    prov = json.loads(prov_line.split("# Provenance: ", 1)[1])
    assert prov["base_commit"] == "a" * 40 and prov["post_tree"] == "b" * 40
    assert prov["import_root"] == "src" and prov["expect"] == "pre"
    assert prov["module"] == "pkg.limits" and prov["qualname"] == "effective_timeout"


def test_static_export_dotted_qualname_and_colliding_names_execute_cleanly(tmp_path):
    from hlith.operator.witness_export import build_pytest_source

    # 1. Dotted staticmethod/classmethod qualname + nested import_root
    dotted = {
        **CALL,
        "module": "pkg.box",
        "qualname": "Box.make",
        "args": [5],
        "kwargs": {"scale": 2},
        "pre": {"k": "ret", "r": "10", "out": ""},
        "post": {"k": "ret", "r": "11", "out": ""},
    }
    out_dotted = tmp_path / "test_dotted.py"
    src_dotted = build_pytest_source(ws.adapt(dotted), import_root="packages/core/src", expect="pre")
    _static_ast_invariants(src_dotted, expect="pre", module="pkg.box", root_name="Box")
    assert "Box.make(5, scale=2)" in src_dotted
    out_dotted.write_text(src_dotted, encoding="utf-8")

    for side, expr in (("good", "x * scale"), ("bad", "x * scale + 1")):
        tree = tmp_path / f"dotted_{side}"
        mod = tree / "packages" / "core" / "src" / "pkg" / "box.py"
        mod.parent.mkdir(parents=True)
        (mod.parent / "__init__.py").write_text("", encoding="utf-8")
        mod.write_text(f"class Box:\n    @staticmethod\n    def make(x, scale=1):\n        return {expr}\n", encoding="utf-8")
    assert (_run_exported(out_dotted, tmp_path / "dotted_good"), _run_exported(out_dotted, tmp_path / "dotted_bad")) == (0, 1)

    # 2. Target callable whose name collides with a builtin (`type`) or internal prefix (`_hlith_sys`)
    for fn_name in ("type", "repr", "ValueError", "_hlith_sys"):
        coll = {
            **CALL,
            "module": f"coll_{fn_name}",
            "qualname": fn_name,
            "args": [0],
            "kwargs": {},
            "pre": {"k": "exc", "t": "builtins.ValueError", "mi": "boom {x}", "out": ""},
            "post": {"k": "ret", "r": "1", "out": ""},
        }
        out = tmp_path / f"test_{fn_name}.py"
        src = build_pytest_source(ws.adapt(coll), expect="pre")
        _static_ast_invariants(src, expect="pre", module=f"coll_{fn_name}", root_name=fn_name)
        out.write_text(src, encoding="utf-8")
        tree_ok = tmp_path / f"ok_{fn_name}"
        tree_ok.mkdir()
        (tree_ok / f"coll_{fn_name}.py").write_text(
            f"import builtins as _b\ndef {fn_name}(x):\n    raise _b.ValueError('boom {{x}}')\n",
            encoding="utf-8",
        )
        tree_bad = tmp_path / f"bad_{fn_name}"
        tree_bad.mkdir()
        (tree_bad / f"coll_{fn_name}.py").write_text(f"def {fn_name}(x):\n    return 1\n", encoding="utf-8")
        assert (_run_exported(out, tree_ok), _run_exported(out, tree_bad)) == (0, 1), fn_name


def test_static_export_does_not_execute_brace_payloads_in_return_or_exception(tmp_path):
    payload = "{__import__('os').environ['PWNED']}"
    for label, pre, post, body_ok, body_bad in (
        (
            "ret",
            {"k": "ret", "r": repr(payload), "out": ""},
            {"k": "ret", "r": "'other'", "out": ""},
            f"def f(x):\n    return {payload!r}\n",
            "def f(x):\n    return 'other'\n",
        ),
        (
            "exc",
            {"k": "exc", "t": "builtins.ValueError", "mi": payload, "out": ""},
            {"k": "ret", "r": "1", "out": ""},
            f"def f(x):\n    raise ValueError({payload!r})\n",
            "def f(x):\n    raise ValueError('other')\n",
        ),
    ):
        call = {**CALL, "module": f"brace_{label}", "qualname": "f", "pre": pre, "post": post}
        out = tmp_path / f"test_brace_{label}.py"
        write_pytest(out, ws.adapt(call), expect="pre")
        for side, body in (("ok", body_ok), ("bad", body_bad)):
            t = tmp_path / f"brace_{label}_{side}"
            t.mkdir()
            (t / f"brace_{label}.py").write_text(body, encoding="utf-8")
        assert (_run_exported(out, tmp_path / f"brace_{label}_ok"), _run_exported(out, tmp_path / f"brace_{label}_bad")) == (0, 1)


@pytest.mark.parametrize("bad_module", [
    "", "a..b", ".m", "m.", "m; import os", "m\nimport os", "class", "def.m", "1bad",
    "hlith", "hlith.operator.cli", "builtins", "__main__", "pkg.__init__",
])
def test_static_export_refuses_invalid_or_disallowed_module(tmp_path, bad_module):
    _refused(tmp_path, {**CALL, "module": bad_module}, "importable|hlith|plain user callable")


@pytest.mark.parametrize("bad_qualname", [
    "", "f()", "f\nimport os", "<lambda>", "outer.<locals>.f", "a..b", ".f", "f.",
    "def", "C.class", "1fn", "C.__init__", "__import__",
])
def test_static_export_refuses_invalid_or_disallowed_qualname(tmp_path, bad_qualname):
    _refused(tmp_path, {**CALL, "qualname": bad_qualname}, "importable|plain user callable")


@pytest.mark.parametrize("bad_root", [
    "/etc", "/work/repo/src", "../src", "src/../etc", "src/.", ".", "..", "src//pkg",
    "src/", "src\\pkg", "C:/src", "src\nimport os", "src\x00x", 123,
])
def test_static_export_refuses_invalid_or_path_leaking_import_root(tmp_path, bad_root):
    out = tmp_path / "new" / "t.py"
    with pytest.raises(NotExportable, match="import_root"):
        write_pytest(out, ws.adapt(CALL), import_root=bad_root, expect="pre")  # type: ignore[arg-type]
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("kw", [
    {"base_commit": "/home/user/repo"},
    {"base_commit": "abc\nimport os"},
    {"post_tree": "../tree"},
    {"post_tree": "dead\\beef"},
])
def test_static_export_refuses_path_or_newline_in_provenance(tmp_path, kw):
    out = tmp_path / "new" / "t.py"
    with pytest.raises(NotExportable, match="provenance"):
        write_pytest(out, ws.adapt(CALL), expect="pre", **kw)
    assert not (tmp_path / "new").exists()


def test_static_export_refuses_non_finite_and_non_plain_args(tmp_path):
    for bad in (float("nan"), float("inf"), float("-inf")):
        _refused(tmp_path, {**CALL, "args": [bad]}, "non-finite float")
    _refused(tmp_path, {**CALL, "args": [{1: "a"}]}, "non-string dict keys")
    _refused(tmp_path, {**CALL, "args": [object()]}, "not plain data")
    _refused(tmp_path, _with("post", r="1e400"), "finite Python literal")
    deep: list = []
    cur = deep
    for _ in range(40):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    _refused(tmp_path, {**CALL, "args": [deep]}, "nesting depth")


def test_static_export_restores_sys_path_on_pass_and_fail(tmp_path, monkeypatch):
    """Exported guard must not leak entries into sys.path across tests (pass, fail, or import error)."""
    call = {
        **CALL,
        "module": "spcheck_mod_unique",
        "qualname": "f",
        "args": [1],
        "pre": {"k": "ret", "r": "2", "out": ""},
        "post": {"k": "ret", "r": "3", "out": ""},
    }
    out = tmp_path / "test_sp.py"
    write_pytest(out, ws.adapt(call), import_root="src", expect="pre")
    src = out.read_text(encoding="utf-8")

    # Pass case
    ok_tree = tmp_path / "ok_tree"
    (ok_tree / "src").mkdir(parents=True)
    (ok_tree / "src" / "spcheck_mod_unique.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    ns: dict = {}
    exec(compile(src, str(out), "exec"), ns)
    monkeypatch.setenv("HLITH_WITNESS_ROOT", str(ok_tree))
    before = list(sys.path)
    try:
        ns["test_recorded_pre_behavior"]()
        assert sys.path == before
    finally:
        sys.modules.pop("spcheck_mod_unique", None)

    # Fail case (assertion fails)
    bad_tree = tmp_path / "bad_tree"
    (bad_tree / "src").mkdir(parents=True)
    (bad_tree / "src" / "spcheck_mod_unique.py").write_text("def f(x):\n    return x + 2\n", encoding="utf-8")
    monkeypatch.setenv("HLITH_WITNESS_ROOT", str(bad_tree))
    before = list(sys.path)
    try:
        with pytest.raises(AssertionError):
            ns["test_recorded_pre_behavior"]()
        assert sys.path == before
    finally:
        sys.modules.pop("spcheck_mod_unique", None)

    # Import-error case
    empty_tree = tmp_path / "empty_tree"
    (empty_tree / "src").mkdir(parents=True)
    monkeypatch.setenv("HLITH_WITNESS_ROOT", str(empty_tree))
    before = list(sys.path)
    with pytest.raises(ModuleNotFoundError):
        ns["test_recorded_pre_behavior"]()
    assert sys.path == before


@full_only
def test_static_exported_guard_survives_retention_in_later_hlith_check(tmp_path):
    """Mechanism-only end-to-end proof:
    1. Export static PRE guard from a real REFUTED witness (`hlith replay --pytest-out ... --expect pre`).
    2. Standalone guard (no Hlith) fails buggy revision and passes intended correction.
    3. Committed guard in `tests/` participates in later `hlith check` `impacted_test_nodes`/`impacted_call_sites`
       (even as the SOLE reaching test): preserving refactor exits 0 (LANDED), refuting change exits 10 (REFUTED).
    4. Uncommitted added guard in the checked diff still exits 11 (NOT-DERIVED, added-unreached only — no weakened
       added-callable scrutiny, and zero dynamic_import_module/dynamic_getattr blockers).
    """
    import test_review_contract_suite as suite

    box = suite.box.__wrapped__(tmp_path)
    box = next(box) if hasattr(box, "__next__") else box
    repo = box["tmp"] / "fx_static_guard"
    (repo / "src" / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    base_src = (
        "def effective_timeout(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    if value > 300:\n"
        "        return 300\n"
        "    return value\n"
    )
    (repo / "src" / "pkg" / "limits.py").write_text(base_src, encoding="utf-8")
    (repo / "tests" / "test_limits.py").write_text(
        "from pkg.limits import effective_timeout\n\n"
        "def test_caps():\n"
        "    assert effective_timeout(60) == 60\n"
        "    assert effective_timeout(600) == 300\n",
        encoding="utf-8",
    )
    suite._git(repo, "init", "-q", "-b", "main")
    suite._git(repo, "add", ".")
    suite._git(repo, *suite._GIT_ID, "commit", "-qm", "base")

    # 1. Buggy edit removes value <= 0 guard -> REFUTED (exit 10)
    buggy_src = (
        "def effective_timeout(value: int) -> int:\n"
        "    if value > 300:\n"
        "        return 300\n"
        "    return value\n"
    )
    (repo / "src" / "pkg" / "limits.py").write_text(buggy_src, encoding="utf-8")
    art1 = box["tmp"] / "r_seed"
    p1 = suite.hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(art1))
    assert p1.returncode == 10, p1.stderr[-1500:]
    env1 = json.loads(p1.stdout)
    run_id = env1["check"]["run_id"]

    # Export static PRE guard outside repo first
    guard_out = box["tmp"] / "test_hlith_guard.py"
    rp = suite.hlith(box, "replay", run_id, "--repo", str(repo), "--json", "--pytest-out", str(guard_out), "--expect", "pre")
    assert rp.returncode == 0 and guard_out.is_file(), rp.stderr[-1500:]
    assert json.loads(rp.stdout)["pytest_export"]["status"] == "written"
    guard_text = guard_out.read_text(encoding="utf-8")
    _static_ast_invariants(guard_text, expect="pre", module="pkg.limits", root_name="effective_timeout")

    # 2. Standalone outside Hlith: fails on buggy tree, passes on intended non-revert fix
    assert _run_exported(guard_out, repo) == 1
    fixed_src = (
        "def effective_timeout(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    capped = 300 if value > 300 else value\n"
        "    return capped\n"
    )
    (repo / "src" / "pkg" / "limits.py").write_text(fixed_src, encoding="utf-8")
    assert _run_exported(guard_out, repo) == 0

    # 3. Uncommitted added guard + preserving edit: exits 11 NOT-DERIVED ONLY from added-callable rules (no dynamic blockers)
    (repo / "tests" / "test_hlith_guard.py").write_text(guard_text, encoding="utf-8")
    art_added = box["tmp"] / "r_added"
    p_added = suite.hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(art_added))
    assert p_added.returncode == 11, p_added.stderr[-1500:]
    added_art = json.loads(p_added.stdout)["artifact"]
    assert set(added_art["blocking"]) == {
        "added-unreached:tests.test_hlith_guard.test_recorded_pre_behavior",
        "signature_binding:tests.test_hlith_guard.test_recorded_pre_behavior",
    }, added_art["blocking"]

    # 4. Commit the guard (as the SOLE reaching test!) and verify later checks
    (repo / "src" / "pkg" / "limits.py").write_text(fixed_src, encoding="utf-8")
    (repo / "tests" / "test_limits.py").unlink()
    suite._git(repo, "add", "-A")
    suite._git(repo, *suite._GIT_ID, "commit", "-qm", "retain static guard as sole test")

    # Positive control: distinct behavior-preserving change -> exit 0 LANDED, static guard reaches target
    pres_src = (
        "def effective_timeout(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    if value > 300:\n"
        "        out = 300\n"
        "    else:\n"
        "        out = value\n"
        "    return out\n"
    )
    (repo / "src" / "pkg" / "limits.py").write_text(pres_src, encoding="utf-8")
    art_pos = box["tmp"] / "r_pos"
    p_pos = suite.hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(art_pos))
    assert p_pos.returncode == 0, p_pos.stderr[-1500:]
    pos_art = json.loads(p_pos.stdout)["artifact"]
    assert pos_art["outcome"] == "landed" and pos_art["blocking"] == []
    impacted_ids = [t["node_id"] for t in pos_art["effect_account"]["impacted_tests"]]
    assert "tests/test_hlith_guard.py::test_recorded_pre_behavior" in impacted_ids, impacted_ids
    site_callers = [s["caller"] for s in pos_art["effect_account"]["impacted_sites"]]
    assert "tests.test_hlith_guard.test_recorded_pre_behavior" in site_callers, site_callers

    # Negative control: distinct refuting change (cap 300 -> 350) -> exit 10 REFUTED
    refute_src = (
        "def effective_timeout(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    if value > 350:\n"
        "        return 350\n"
        "    return value\n"
    )
    (repo / "src" / "pkg" / "limits.py").write_text(refute_src, encoding="utf-8")
    art_neg = box["tmp"] / "r_neg"
    p_neg = suite.hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(art_neg))
    assert p_neg.returncode == 10, p_neg.stderr[-1500:]
    neg_art = json.loads(p_neg.stdout)["artifact"]
    assert neg_art["outcome"] == "refused"
    assert any(o.get("verdict") == "refuted" for o in neg_art["obligations"])
