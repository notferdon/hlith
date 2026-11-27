"""case lever (3): static proof that an UNCHANGED callable cannot read an edited docstring (review).
The scan is conservative: anything dynamic = 'cannot show' = the callable keeps today's per-callable differential."""
import json
import subprocess
from pathlib import Path

import pytest

from hlith import cli, docstring_check
from hlith.obligation import docstring_check as dc

F = 'def f(x: int) -> int:\n    """Return x plus one."""\n    return x + 1\n\n'


def _scan(extra: str, edited=(("f",),), head=F):
    return dc.static_doc_clear(head + extra, list(edited))


@pytest.mark.parametrize("name,body,clear", [
    ("pure", "def g(a, b):\n    return a + b\n", True),
    pytest.param(
        "unresolved_receiver_not_naming_f",
        "def g(items):\n    return items.run(items[0])\n",
        True,
        marks=pytest.mark.xfail(
            strict=True,
            reason="fail-closed since c36f671c: unresolved items.run receiver could read edited documentation; needs a specific sound receiver proof",
        ),
    ),
    pytest.param(
        "literal_getattr",
        "def g(o):\n    return getattr(o, 'name', None)\n",
        True,
        marks=pytest.mark.xfail(
            strict=True,
            reason="fail-closed since c36f671c: receiver-supplied getattr is not proven unable to observe edited documentation",
        ),
    ),
    pytest.param(
        "re_compile_attr",
        "import re\n\n\ndef g(s):\n    return re.compile(s)\n",
        True,
        marks=pytest.mark.xfail(
            strict=True,
            reason="fail-closed since c36f671c: external re.compile binding lacks a specific sound no-reader proof",
        ),
    ),
    pytest.param(
        "contextmanager",
        "import contextlib\n\n\n@contextlib.contextmanager\ndef g():\n    yield 1\n",
        True,
        marks=pytest.mark.xfail(
            strict=True,
            reason="fail-closed since c36f671c: external contextlib decorator lacks a specific sound doc-reader proof",
        ),
    ),
    # ---- must NOT be shown clear (the falls-back list: each keeps the per-callable differential) ----
    ("reads_dunder_doc", "def g(o):\n    return o.__doc__\n", False),
    ("names_edited_function", "def g():\n    return f(1)\n", False),
    ("attribute_named_like_edited", "def g(items):\n    return items.f(items[0])\n", False),
    ("getattr_nonliteral", "def g(o, n):\n    return getattr(o, n)\n", False),
    ("getattr_doc_literal", "def g(o):\n    return getattr(o, '__doc__')\n", False),
    ("getattr_edited_name", "def g(o):\n    return getattr(o, 'f')\n", False),
    ("getattr_passed_not_called", "def g(o):\n    return list(map(getattr, [o], ['x']))\n", False),
    ("vars", "def g(o):\n    return vars(o)\n", False),
    ("dunder_dict", "def g(o):\n    return o.__dict__\n", False),
    ("dir", "def g(o):\n    return dir(o)\n", False),
    ("eval", "def g(s):\n    return eval(s)\n", False),
    ("exec", "def g(s):\n    exec(s)\n", False),
    ("builtin_compile", "def g(s):\n    return compile(s, 'x', 'exec')\n", False),
    ("dunder_import", "def g(n):\n    return __import__(n)\n", False),
    ("importlib", "import importlib\n\n\ndef g(n):\n    return importlib.import_module(n)\n", False),
    ("inspect_getdoc", "import inspect\n\n\ndef g(o):\n    return inspect.getdoc(o)\n", False),
    ("inspect_getsource", "import inspect\n\n\ndef g(o):\n    return inspect.getsource(o)\n", False),
    ("cleandoc", "from inspect import cleandoc\n\n\ndef g(s):\n    return cleandoc(s)\n", False),
    ("help", "def g(o):\n    help(o)\n", False),
    ("pydoc", "import pydoc\n\n\ndef g(o):\n    return pydoc.render_doc(o)\n", False),
    ("doctest", "import doctest\n\n\ndef g():\n    return doctest.testmod()\n", False),
    ("wraps", "import functools\n\n\ndef g(h):\n    return functools.wraps(h)\n", False),
    ("sys_modules", "import sys\n\n\ndef g(n):\n    return sys.modules[n]\n", False),
    ("globals", "def g(n):\n    return globals()[n]\n", False),
    ("string_mentions_doc", "def g():\n    return '__doc__'\n", False),
    ("decorated_other", "import functools\n\n\n@functools.lru_cache\ndef g(a):\n    return a\n", False),
    ("nested_def_reads", "def g(o):\n    def inner():\n        return o.__doc__\n    return inner()\n", False),
    ("lambda_reads", "def g(o):\n    return (lambda: o.__doc__)()\n", False),
    ("global_rebind", "G = 1\n\n\ndef g():\n    global G\n    G = 2\n", False),
    ("conditional_def_reads", "def g(o):\n    if o:\n        def h():\n            return o.__doc__\n        return h()\n", False),
    ("async_reads", "async def g(o):\n    return o.__doc__\n", False),
])
def test_scan_is_conservative(name, body, clear):
    c, fall = _scan(body)
    assert ("g" in c) is clear, (name, c, fall)


def test_transitive_reader_closure_falls_back():
    c, fall = _scan("def h(o):\n    return o.__doc__\n\n\ndef g(o):\n    return h(o)\n")
    assert "g" not in c and "h" not in c and "uses 'h'" in fall["g"][0], fall


def test_edited_object_and_module_doc_never_cleared():
    c, fall = _scan("def g(a):\n    return a\n")
    assert "f" not in c and "g" in c  # the edited function keeps its own differential
    c2, _ = _scan("def g(a):\n    return a\n", edited=[()])  # module docstring edited
    assert c2 == {}


def test_method_docstring_edit_names_class_and_method():
    head = 'class Box:\n    def m(self):\n        """doc."""\n        return 1\n\n\n'
    c, fall = dc.static_doc_clear(head + "def g():\n    return Box()\n\n\ndef h(a):\n    return a\n", [("Box", "m")])
    assert "g" not in c and "h" in c, (c, fall)


# ---------------- end to end through the real gate (no resource-bounded slot: toy modules) ----------------
@pytest.fixture(autouse=True)
def _enable_measured_docstring(monkeypatch):
    monkeypatch.setattr(docstring_check, "_DOCSTRING_MEASURED", True)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout


def _run(
    tmp_path,
    old_src,
    new_src,
    *,
    engine="pipeline",
    test_src=None,
    extra_sys_path=None,
    repo_files=None,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    for relative, content in (repo_files or {}).items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "mod.py").write_text(old_src)
    (repo / "test_mod.py").write_text(
        test_src or "from mod import f\n\ndef test_f():\n    assert f(1) == 2\n"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "mod.py").write_text(new_src)
    patch, manifest, out = tmp_path / "c.patch", tmp_path / "c.manifest.json", tmp_path / "out.json"
    patch.write_text(_git(repo, "diff"))
    manifest.write_text(json.dumps({"paths": {"mod.py": ["modify"]}}))
    _git(repo, "checkout", "-q", "mod.py")
    # Measured-docstring cases use the pipeline contract; --layer1 is legacy-only.
    args = ["run", "--engine", engine, "--repo", str(repo), "--patch", str(patch), "--manifest", str(manifest),
            "--artifact-out", str(out)]
    if extra_sys_path is not None:
        args.extend(["--extra-sys-path", str(extra_sys_path)])
    if engine == "legacy":
        args.extend(["--layer1", "langgraph"])
    cli.main(args)
    return json.loads(out.read_text())


@pytest.mark.xfail(
    strict=True,
    reason="fail-closed since c36f671c: unresolved items.run receiver could observe changed documentation; landing needs a specific sound proof",
)
def test_unresolved_receiver_neighbour_not_naming_f_lands_with_named_residual(tmp_path):
    old = F + "def g(items):\n    return items.run(items[0])\n"
    art = _run(tmp_path, old, old.replace("Return x plus one.", "Return x + 1."))
    assert art["outcome"] == "landed" and art["exit_status"] == 0, art
    ids = [o["id"] for o in art["obligations"]]
    assert "differential:mod.g" not in ids, ids  # g is not executed: code unchanged, no reader
    meas = next(o for o in art["obligations"] if o["id"].startswith("docstring-measured:"))
    ev = meas["evidence"]
    assert "docstring-other-static: 1 callable(s) not executed" in ev["explored"], ev
    assert "external/receiver-supplied readers not excluded" in ev["unexplored"], ev
    assert next(o for o in art["obligations"] if o["id"] == "differential:mod.f")["verdict"] == "held"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "documented differential limit: values supplied by non-repo callers are not explored, "
        "including receiver properties; see the schema example"
    ),
)
def test_receiver_property_read_is_not_skipped_for_docstring_edit(tmp_path):
    old = (
        F
        + "def g(obj):\n    return obj.value\n"
    )
    external = tmp_path / "external"
    external.mkdir()
    (external / "ext_reader.py").write_text(
        "import importlib\n\n"
        "class Reader:\n"
        "    @property\n"
        "    def value(self):\n"
        "        return importlib.import_module('mod').f.__doc__\n"
    )
    test_src = (
        "from mod import f, g\n"
        "from ext_reader import Reader\n\n"
        "def test_f():\n"
        "    assert f(1) == 2\n\n"
        "def test_receiver_reader():\n"
        "    assert isinstance(g(Reader()), str)\n"
    )
    art = _run(
        tmp_path,
        old,
        old.replace("Return x plus one.", "Return x plus one, updated."),
        test_src=test_src,
        extra_sys_path=external,
    )

    assert art["outcome"] != "landed", art


def test_sys_modules_builtin_rebinding_does_not_land_on_static_clear_alone(tmp_path):
    old = (
        F
        + "from sys import modules as registry\n"
        + "def g(value):\n    return type(value)\n\n"
        + "registry['builtins'].type = lambda value: value.__doc__\n"
    )
    test_src = (
        "import builtins\n"
        "saved_type = builtins.type\n"
        "from mod import f, g\n"
        "patched_type = builtins.type\n"
        "builtins.type = saved_type\n\n"
        "def test_f():\n"
        "    assert f(1) == 2\n\n"
        "def test_g():\n"
        "    builtins.type = patched_type\n"
        "    try:\n"
        "        assert g(f) == f.__doc__\n"
        "    finally:\n"
        "        builtins.type = saved_type\n"
    )
    art = _run(
        tmp_path,
        old,
        old.replace("Return x plus one.", "Return x plus one, updated."),
        test_src=test_src,
    )

    assert art["outcome"] != "landed", art


@pytest.mark.parametrize(
    "import_stmt,local_module",
    [
        ("import ext_side_effect", False),
        ("from ext_side_effect import marker", False),
        ("import side_effect", True),
    ],
)
def test_lazy_import_side_effect_reader_is_not_skipped(tmp_path, import_stmt, local_module):
    old = F + f"def g():\n    {import_stmt}\n    return 1\n"
    side_effect = (
        "import importlib\n"
        "print(importlib.import_module('mod').f.__doc__)\n"
        "marker = object()\n"
    )
    external = None
    repo_files = None
    if local_module:
        repo_files = {"side_effect.py": side_effect}
    else:
        external = tmp_path / "external"
        external.mkdir()
        (external / "ext_side_effect.py").write_text(side_effect)
    test_src = "from mod import f\n\ndef test_f():\n    assert f(1) == 2\n"
    art = _run(
        tmp_path,
        old,
        old.replace("Return x plus one.", "Return x plus one, updated."),
        test_src=test_src,
        extra_sys_path=external,
        repo_files=repo_files,
    )

    assert art["outcome"] != "landed", art


def test_clear_callable_is_differentially_checked_when_not_skipped(tmp_path):
    old = F + "def g():\n    return 1\n"
    art = _run(
        tmp_path,
        old,
        old.replace("Return x plus one.", "Return x plus one, updated."),
    )

    g_diff = next(
        (o for o in art["obligations"] if o["id"] == "differential:mod.g"), None
    )
    assert g_diff is not None, art
    if art["outcome"] == "landed":
        assert g_diff["verdict"] == "held", g_diff
        evidence = g_diff.get("evidence") or {}
        assert evidence.get("executions", 0) > 0, g_diff
        assert evidence.get("explored"), g_diff


def test_neighbour_naming_edited_attribute_keeps_its_differential_and_still_refuses(tmp_path):
    # the pre-existing toy: `items.f(items[0])` names the edited object `f` as an Attribute: cannot show, so the old behaviour stands
    old = F + "def g(items):\n    return items.f(items[0])\n"
    # Preserve this original legacy-engine refusal contract (7495b93ce).
    art = _run(tmp_path, old, old.replace("Return x plus one.", "Return x + 1."), engine="legacy")
    assert "differential:mod.g" in [o["id"] for o in art["obligations"]]
    assert art["outcome"] == "refused" and art["exit_status"] in (10, 11, 12), art
    assert "differential:mod.g" in art["blocking"], art
    unresolved = next(o for o in art["obligations"] if o["id"] == "unresolved-0")
    assert unresolved["verdict"] == "not-derived", unresolved
    assert "items.f(items[0])" in unresolved["stop_reason"], unresolved


def test_neighbour_reading_the_edited_docstring_is_refused(tmp_path):
    old = F + "def g():\n    return f.__doc__\n"
    art = _run(tmp_path, old, old.replace("Return x plus one.", "Return x + 1."))
    assert art["outcome"] == "refused", art
    assert "differential:mod.g" in [o["id"] for o in art["obligations"]]


def test_neighbour_getattr_by_name_is_refused(tmp_path):
    old = F + "def g(name):\n    return getattr(__import__('mod'), name).__doc__\n"
    art = _run(tmp_path, old, old.replace("Return x plus one.", "Return x + 1."))
    assert art["outcome"] == "refused", art


def test_static_doc_residual_is_disclosed_next_to_the_verdict():
    from hlith.operator import disclosure
    o = {"unexplored": "docstring is observable by code ...; docstring-other-static: 3 callable(s) not executed: "
                       + dc.STATIC_RESIDUAL}
    note = disclosure.annotation_bound([o])
    assert note and "3 callable(s) not executed" in note and "receiver-supplied readers not excluded" in note, note
    assert disclosure.tag(o) == "static doc proof (unchanged callables not executed)"
    assert disclosure.annotation_bound([{"unexplored": "docstring is observable by code"}]) is None


def test_static_doc_text_only_for_a_held_with_static_proof():
    from hlith.operator import disclosure
    tok = "docstring-other-static: 2 callable(s) not executed: " + dc.STATIC_RESIDUAL
    held_static = {"verdict": "held", "unexplored": "x; " + tok}
    held_plain = {"verdict": "held", "unexplored": "docstring is observable by code or outputs not compared"}
    # a HELD WITHOUT static proof shows no such text; a non-HELD verdict shows none even if the text were present
    assert disclosure.annotation_bound([held_plain]) is None and disclosure.tag(held_plain) is None
    for v in ("refuted", "unverified", "not-derived"):
        r = {"verdict": v, "unexplored": "x; " + tok}
        assert disclosure.annotation_bound([r]) is None and disclosure.tag(r) is None, v
    assert "2 callable(s) not executed" in disclosure.annotation_bound([held_static])
    # strictly additive: an annotation-bounded HELD keeps exactly its old note, with or without the static text
    ab = {"verdict": "held", "unexplored": "ANNOTATION-BOUNDED: parameter(s) n: int; inputs violating declared annotations are not explored; " + tok}
    assert disclosure.annotation_bound([ab]).startswith("HELD is annotation-bounded")
    assert disclosure.tag(ab).startswith("annotation-bounded")


def test_static_note_is_not_masked_by_annotation_bound_and_is_sanitised():
    from hlith.operator import disclosure
    tok = "docstring-other-static: 2 callable(s) not executed: " + dc.STATIC_RESIDUAL
    ab = {"verdict": "held", "unexplored": "ANNOTATION-BOUNDED: parameter(s) n: int; inputs violating declared annotations are not explored"}
    st = {"verdict": "held", "unexplored": "x; " + tok}
    both = disclosure.annotation_bound([ab, st])
    assert both.startswith(disclosure.annotation_bound([ab])) and "2 callable(s) not executed" in both, both
    assert disclosure.annotation_bound([ab]) == disclosure.annotation_bound([ab, {"verdict": "held", "unexplored": "none"}])  # old text unchanged
    evil = {"verdict": "held", "unexplored": "docstring-other-static: 1 callable(s) not executed\x1b[31m\x07 red\x00"}
    out = disclosure.annotation_bound([evil])
    assert out and not any(ord(c) < 32 or ord(c) == 127 for c in out), repr(out)


def test_escape_sequences_in_unexplored_never_reach_the_note_on_either_path():
    from hlith.operator import disclosure
    csi = "\x1b[2J\x1b]0;pwn\x07"
    st = {"verdict": "held", "unexplored": f"docstring-other-static: 3 callable(s) not executed: {csi} tail"}
    ab = {"verdict": "held", "unexplored": f"ANNOTATION-BOUNDED: parameter(s) n: int{csi}; inputs violating declared annotations are not explored"}
    for rows in ([st], [ab], [ab, st]):
        out = disclosure.annotation_bound(rows)
        assert out and not any(ord(c) < 32 or ord(c) == 127 for c in out), repr(out)  # no real control byte (clean() escapes them)
    assert "3 callable(s) not executed" in disclosure.annotation_bound([st]) and "tail" not in disclosure.annotation_bound([st])


# ---- review's predicted false-HELD toys (DV1, DV5, DV5b, DV8, DV9): every one has an UNCHANGED neighbour g whose value changes with the
# edited docstring; none may be shown clear. DV1 needs a real second module (the closure must follow in-repo imports).
def _scan_repo(tmp_path, files: dict, edited=(("f",),)):
    for rel, txt in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(txt)
    tops = dc._local_tops(tmp_path, tmp_path, tmp_path)
    ctx = {"roots": [tmp_path], "module": "m", "is_pkg": False}
    return dc.static_doc_clear((tmp_path / "m.py").read_text(), list(edited), tops, ctx)


@pytest.mark.parametrize("name,files,gclear", [
    ("DV1_module_import_reader", {"m.py": F + "import other\n\n\ndef g():\n    return other.describe()\n",
                                  "other.py": "import m\n\n\ndef describe():\n    return len(m.f.__doc__)\n"}, False),
    ("DV1b_from_import_reader", {"m.py": F + "from other import describe\n\n\ndef g():\n    return describe()\n",
                                 "other.py": "import m\n\n\ndef describe():\n    return len(m.f.__doc__)\n"}, False),
    ("DV1c_reader_two_hops", {"m.py": F + "from other import describe\n\n\ndef g():\n    return describe()\n",
                              "other.py": "from third import deep as describe\n", "third.py": "def deep():\n    return __import__('m').f.__doc__\n"}, False),
    ("DV1d_relative_import_cycle", {"m.py": F + "from other import describe\n\n\ndef g():\n    return describe()\n",
                                    "other.py": "from m import g as describe\n"}, False),
    ("DV1e_inert_repo_helper_is_clear", {"m.py": F + "from other import add\n\n\ndef g(a, b):\n    return add(a, b)\n",
                                         "other.py": "def add(a, b):\n    return a + b\n"}, True),
    ("DV5_module_lambda", {"m.py": F + "get = lambda: f.__doc__\n\n\ndef g():\n    return get()\n"}, False),
    ("DV5b_factory_closure", {"m.py": F + "def make():\n    return lambda: f.__doc__\n\n\nget = make()\n\n\ndef g():\n    return get()\n"}, False),
    ("DV8_class_method_reader", {"m.py": F + "class Reader:\n    def read(self):\n        return f.__doc__\n\n\ndef g():\n    return Reader().read()\n"}, False),
    ("DV9_conditional_def", {"m.py": F + "import sys\nif sys.version_info >= (3,):\n    def h():\n        return f.__doc__\nelse:\n    def h():\n        return ''\n\n\n"
                             "def g():\n    return h()\n"}, False),
    ("DV9b_try_def", {"m.py": F + "try:\n    def h():\n        return f.__doc__\nexcept Exception:\n    pass\n\n\ndef g():\n    return h()\n"}, False),
    ("DV_alias", {"m.py": F + "h = f\n\n\ndef g():\n    return h.__doc__\n"}, False),
    ("DV_alias_no_dunder", {"m.py": F + "table = {'k': f}\n\n\ndef g(k):\n    return table[k]\n"}, False),
    ("DV3_default_arg", {"m.py": F + "def g(x=f.__doc__):\n    return x\n"}, False),
    ("plain_module_constant_is_clear", {"m.py": F + "LIMIT = 5\n\n\ndef g(x):\n    return x + LIMIT\n"}, True),
])
def test_n2_predicted_false_held_toys_are_not_cleared(tmp_path, name, files, gclear):
    clear, fall = _scan_repo(tmp_path, files)
    assert ("g" in clear) is gclear, (name, clear, fall)


@pytest.mark.parametrize("name,files", [
    # review amendment A2: the reader is imported INSIDE g, reaches f without the token m.f, or hides the dunder
    ("DV10_import_inside_g_getattr_reader", {"m.py": F + "def g():\n    import other\n    return other.describe()\n",
                                              "other.py": "import m\n\n\ndef describe():\n    return getattr(m, 'f').__doc__\n"}),
    ("DV10b_from_import_inside_g", {"m.py": F + "def g():\n    from other import describe\n    return describe()\n",
                                    "other.py": "import m\n\n\ndef describe():\n    return getattr(m, 'f').__doc__\n"}),
    ("DV11_module_getattr", {"m.py": F + "def __getattr__(name):\n    return f.__doc__\n\n\ndef g():\n    from m import DOCX\n    return DOCX\n"}),
    ("DV14_alias_import_and_format", {"m.py": F + "def g():\n    from m import f as zz\n    return ('{0._' + '_doc__}').format(zz)\n"}),
    ("DV14b_import_self_module", {"m.py": F + "def g():\n    import m\n    return ('{0._' + '_doc__}').format(m.f)\n"}),
    ("DV_relative_import_inside_g", {"pkg/__init__.py": "", "pkg/m.py": F + "def g():\n    from . import other\n    return other.d()\n",
                                     "pkg/other.py": "from . import m\n\n\ndef d():\n    return getattr(m, 'f').__doc__\n"}),
])
def test_n2_a2_import_inside_g_and_hidden_readers_are_not_cleared(tmp_path, name, files):
    for rel, txt in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(txt)
    tops = dc._local_tops(tmp_path, tmp_path, tmp_path)
    mod, rel = ("pkg.m", "pkg/m.py") if "pkg/m.py" in files else ("m", "m.py")
    ctx = {"roots": [tmp_path], "module": mod, "is_pkg": False}
    clear, fall = dc.static_doc_clear((tmp_path / rel).read_text(), [("f",)], tops, ctx)
    assert "g" not in clear and "g" in fall, (name, clear, fall)
