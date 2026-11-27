# SPDX-License-Identifier: Apache-2.0
"""review 2026-11-25, case: the six gate-witnessed false-HELD programs of the 13d28535 release red-team (review), through the differential gate.
Each divergence is executed here as ground truth; the gate must not answer HELD. Regression only: these programs are spent as independent evidence."""

from __future__ import annotations

import subprocess
import sys

import pytest

from hlith import differential
from hlith.types import Verdict

CASES = {'re_c02_helper_import_shadow': {'base': {'pkg/__init__.py': '',
                                          'pkg/mod.py': 'def _scale(a):\n'
                                                        '    return a * 2\n'
                                                        '\n'
                                                        '\n'
                                                        'from pkg.other import _scale\n'
                                                        '\n'
                                                        '\n'
                                                        'def f(x):\n'
                                                        '    return _scale(x)\n',
                                          'pkg/other.py': 'def _scale(a):\n    return a * 2 if a != 982451653 else 0\n',
                                          'pytest.ini': '[pytest]\npythonpath = .\ntestpaths = tests\n',
                                          'tests/test_mod.py': 'from pkg.mod import f\n\ndef test_f():\n    assert f(3) == 6\n'},
                                 'post': {'pkg/mod.py': 'def _scale(a):\n'
                                                        '    return a * 2\n'
                                                        '\n'
                                                        '\n'
                                                        'from pkg.other import _scale\n'
                                                        '\n'
                                                        '\n'
                                                        'def f(x):\n'
                                                        '    return x * 2\n'},
                                 'truth': 'from pkg.mod import f; print(f(982451653))'},
 're_c05_sum_import_shadow': {'base': {'pkg/__init__.py': '',
                                       'pkg/mod.py': 'from pkg.other import sum\n'
                                                     '\n'
                                                     '\n'
                                                     'def f(xs: tuple[int, ...]) -> int:\n'
                                                     '    total = 0\n'
                                                     '    for v in xs:\n'
                                                     '        total += v\n'
                                                     '    return total\n',
                                       'pkg/other.py': 'def sum(xs):\n'
                                                       '    t = 0\n'
                                                       '    for v in xs:\n'
                                                       '        t += v if v != 982451653 else 0\n'
                                                       '    return t\n',
                                       'pytest.ini': '[pytest]\npythonpath = .\ntestpaths = tests\n',
                                       'tests/test_mod.py': 'from pkg.mod import f\n\ndef test_f():\n    assert f((1, 2)) == 3\n'},
                              'post': {'pkg/mod.py': 'from pkg.other import sum\n'
                                                     '\n'
                                                     '\n'
                                                     'def f(xs: tuple[int, ...]) -> int:\n'
                                                     '    total = sum(xs)\n'
                                                     '    return total\n'},
                              'truth': 'from pkg.mod import f; print(f((982451653, 1)))'},
 're_c08_try_import_accel': {'base': {'pkg/__init__.py': '',
                                      'pkg/_speed.py': 'def _scale(a):\n    return a * 2 if a != 982451653 else 0\n',
                                      'pkg/mod.py': 'def _scale(a):\n'
                                                    '    return a * 2\n'
                                                    '\n'
                                                    '\n'
                                                    'try:\n'
                                                    '    from pkg._speed import _scale\n'
                                                    'except ImportError:\n'
                                                    '    pass\n'
                                                    '\n'
                                                    '\n'
                                                    'def f(x):\n'
                                                    '    return _scale(x)\n',
                                      'pytest.ini': '[pytest]\npythonpath = .\ntestpaths = tests\n',
                                      'tests/test_mod.py': 'from pkg.mod import f\n\ndef test_f():\n    assert f(3) == 6\n'},
                             'post': {'pkg/mod.py': 'def _scale(a):\n'
                                                    '    return a * 2\n'
                                                    '\n'
                                                    '\n'
                                                    'try:\n'
                                                    '    from pkg._speed import _scale\n'
                                                    'except ImportError:\n'
                                                    '    pass\n'
                                                    '\n'
                                                    '\n'
                                                    'def f(x):\n'
                                                    '    return x * 2\n'},
                             'truth': 'from pkg.mod import f; print(f(982451653))'},
 're_c09_def_then_assign_rebind': {'base': {'pkg/__init__.py': '',
                                            'pkg/mod.py': 'from pkg import other\n'
                                                          '\n'
                                                          '\n'
                                                          'def _fee(a):\n'
                                                          '    return a * 2\n'
                                                          '\n'
                                                          '\n'
                                                          '_fee = other._scale\n'
                                                          '\n'
                                                          '\n'
                                                          'def _twice(a):\n'
                                                          '    return a * 2\n'
                                                          '\n'
                                                          '\n'
                                                          'def f(x):\n'
                                                          '    return _fee(x)\n',
                                            'pkg/other.py': 'def _scale(a):\n    return a * 2 if a != 982451653 else 0\n',
                                            'pytest.ini': '[pytest]\npythonpath = .\ntestpaths = tests\n',
                                            'tests/test_mod.py': 'from pkg.mod import f\n\ndef test_f():\n    assert f(3) == 6\n'},
                                   'post': {'pkg/mod.py': 'from pkg import other\n'
                                                          '\n'
                                                          '\n'
                                                          'def _fee(a):\n'
                                                          '    return a * 2\n'
                                                          '\n'
                                                          '\n'
                                                          '_fee = other._scale\n'
                                                          '\n'
                                                          '\n'
                                                          'def _twice(a):\n'
                                                          '    return a * 2\n'
                                                          '\n'
                                                          '\n'
                                                          'def f(x):\n'
                                                          '    return _twice(x)\n'},
                                   'truth': 'from pkg.mod import f; print(f(982451653))'},
 're_c12_comp_in_suppress': {'base': {'pkg/__init__.py': '',
                                      'pkg/mod.py': 'import contextlib\n'
                                                    '\n'
                                                    '\n'
                                                    'def _q(v):\n'
                                                    '    return 100 // (v - 7000 - 919)\n'
                                                    '\n'
                                                    '\n'
                                                    'def f(items):\n'
                                                    '    with contextlib.suppress(ZeroDivisionError):\n'
                                                    '        out = []\n'
                                                    '        for v in items:\n'
                                                    '            out.append(_q(v))\n'
                                                    '    return out\n',
                                      'pytest.ini': '[pytest]\npythonpath = .\ntestpaths = tests\n',
                                      'tests/test_mod.py': 'from pkg.mod import f\n\ndef test_f():\n    assert len(f([1, 2])) == 2\n'},
                             'post': {'pkg/mod.py': 'import contextlib\n'
                                                    '\n'
                                                    '\n'
                                                    'def _q(v):\n'
                                                    '    return 100 // (v - 7000 - 919)\n'
                                                    '\n'
                                                    '\n'
                                                    'def f(items):\n'
                                                    '    with contextlib.suppress(ZeroDivisionError):\n'
                                                    '        out = [_q(v) for v in items]\n'
                                                    '    return out\n'},
                             'truth': 'from pkg.mod import f; print(f([1, 7919]))'},
 're_c20_shared_inner_list': {'base': {'pkg/__init__.py': '',
                                       'pkg/mod.py': 'def f(n: int) -> list[list[int]]:\n    row = [n]\n    return [row, row]\n',
                                       'pytest.ini': '[pytest]\npythonpath = .\ntestpaths = tests\n',
                                       'tests/test_mod.py': 'from pkg.mod import f\n\ndef test_f():\n    assert f(1) == [[1], [1]]\n'},
                              'post': {'pkg/mod.py': 'def f(n: int) -> list[list[int]]:\n    return [[n], [n]]\n'},
                              'truth': 'from pkg.mod import f; r=f(1); r[0].append(9); print(r)'}}
# the two shapes of the independent verification (review)
_PY = {"pytest.ini": "[pytest]\npythonpath = .\ntestpaths = tests\n", "pkg/__init__.py": ""}


def _sharing(name, base, post, test_expr, probe):
    CASES[name] = {"base": {**_PY, "pkg/mod.py": base, "tests/test_mod.py": f"from pkg.mod import f\n\ndef test_f():\n    assert {test_expr}\n"},
                   "post": {"pkg/mod.py": post}, "truth": f"from pkg.mod import f; {probe}"}


_sharing("n4_b3_tuple_of_aliases", "def f(n: int) -> tuple:\n    a = [n]\n    b = [n]\n    return (a, b)\n",
         "def f(n: int) -> tuple:\n    a = [n]\n    return (a, a)\n", "f(1) == ([1], [1])", "r = f(1); r[0].append(2); print(r)")
_sharing("n4_a5_rebinding_alias", "def f(xs: list[int]) -> tuple:\n    out = list(xs)\n    res = list(xs)\n    return (out, res)\n",
         "def f(xs: list[int]) -> tuple:\n    out = list(xs)\n    res = out\n    return (out, res)\n", "f([1]) == ([1], [1])", "r = f([1]); r[0].append(9); print(r)")


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_witnessed_false_held_stays_non_held(tmp_path, name):
    c = CASES[name]
    truth = []
    for side, files in (("base", c["base"]), ("post", {**c["base"], **c["post"]})):
        for rel, text in files.items():
            (tmp_path / side / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / side / rel).write_text(text)
        r = subprocess.run([sys.executable, "-B", "-c", c["truth"]], cwd=tmp_path / side, capture_output=True, text=True, timeout=60)
        truth.append((r.stdout + (r.stderr.strip().splitlines() or [""])[-1]).strip())
    assert truth[0] != truth[1], f"{name}: vacuous fixture: {truth}"
    (tmp_path / "prop").mkdir()
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.mod", function="f",
                                       proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=40, adequacy_gate=True)
    assert ob.verdict is not Verdict.HELD, (name, ob.verdict, ob.evidence.explored[-400:])
