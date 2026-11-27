# SPDX-License-Identifier: Apache-2.0
"""Soundness campaign of the symbolic equivalence prover.

For every function of the corpus and every single-site mutant of it: ask the prover whether base and mutant are equivalent. Whenever it answers PROVED, run both concretely
(tests/symeq/oracle.py): exact builtin inputs for a typed proof, random interpretations (probes) for an any-argument proof. A proved pair the oracle can tell apart is a FALSE PROOF.

Also reported (not a failure): how many mutants the oracle could not tell apart and the prover left unproved (completeness on equivalent variants).

    python tests/symeq/campaign.py [--only NAME] [--limit N] [--verbose]      exit 1 on any false proof"""

from __future__ import annotations

import argparse
import ast
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "src"))

import corpus  # noqa: E402
import mutate  # noqa: E402
import oracle  # noqa: E402

from hlith.obligation import symeq  # noqa: E402
from hlith.obligation.symeq import terms  # noqa: E402


def param_types(src: str, name: str):
    """Per-parameter alternative type lists as the prover's typed mode sees them (None for an unannotated / non-exact parameter)."""
    mi = symeq.ModuleInfo(src)
    fn, _ = mi.find(name)
    out = []
    for p in symeq._params(fn):
        alts = symeq._ann_alternatives(p.annotation)
        if alts is not None:
            alts = symeq._expanded(alts)
        out.append(alts)
    return out


def check_pair(base: str, post: str, name: str, verbose=False):
    """(prover status, mode, verdict) where verdict is 'ok', 'FALSE PROOF: ...' or 'unproved-equal' / 'unproved-different'."""
    r = symeq.prove(base, post, name)
    pts = param_types(base, name)
    n = len(pts)
    diff = None
    if r.ok:
        if r.mode == "any":
            typed = None
            d = oracle.differ_probes(base, post, name, n, seeds=40)
            if d is not None:
                return r, f"FALSE PROOF (any): seed {d[0]}: {d[1]} vs {d[2]}"
            # an any-argument proof must also hold on exact builtin inputs
            if all(p is not None for p in pts):
                d = oracle.differ_typed(base, post, name, pts, limit=300)
                if d is not None:
                    return r, f"FALSE PROOF (any, typed input): {d[0]!r}: {d[1]} vs {d[2]}"
            return r, "ok"
        typed_idx = {}
        import random

        rng = random.Random(1)
        dom = dict(r.domain)
        mi = symeq.ModuleInfo(base)
        fn, _ = mi.find(name)
        names = [p.arg for p in symeq._params(fn)]
        if all(nm in dom for nm in names):
            d = oracle.differ_typed(base, post, name, [pts[i] for i in range(n)], limit=600)
            if d is not None:
                return r, f"FALSE PROOF (typed): {d[0]!r}: {d[1]} vs {d[2]}"
            return r, "ok"
        for i, nm in enumerate(names):
            if nm in dom:
                vs = []
                for t in pts[i]:
                    vs += oracle.values(t, rng)
                typed_idx[i] = vs
        d = oracle.differ_probes(base, post, name, n, seeds=60, typed=typed_idx)
        if d is not None:
            return r, f"FALSE PROOF (typed+probes): seed {d[0]}: {d[1]} vs {d[2]}"
        return r, "ok"
    # not proved: is it actually different (informational)
    try:
        if all(p is not None for p in pts):
            diff = oracle.differ_typed(base, post, name, pts, limit=300)
        else:
            import random

            rng = random.Random(1)
            typed_idx = {i: [v for t in pts[i] for v in oracle.values(t, rng)] for i in range(n) if pts[i] is not None}
            diff = oracle.differ_probes(base, post, name, n, seeds=40, typed=typed_idx or None)
    except Exception:  # noqa: BLE001
        diff = "error"
    return r, "unproved-different" if diff is not None else "unproved-equal"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--limit", type=int, default=10 ** 9)
    ap.add_argument("--verbose", action="store_true")
    ns = ap.parse_args(argv)
    only = set(x for x in ns.only.split(",") if x)
    totals = {"mutants": 0, "proved": 0, "false_proofs": 0, "unproved_equal": 0, "unproved_different": 0, "crash": 0, "identity_unproved": 0}
    false_list = []
    t0 = time.time()
    for group in (corpus.TYPED, corpus.OPEN):
        for name, src in group.items():
            if only and name not in only:
                continue
            # the unchanged function must always be provable (and passes through the oracle like any other pair)
            try:
                r, verdict = check_pair(src, src, name)
            except Exception as e:  # noqa: BLE001
                r, verdict = None, f"CRASH {type(e).__name__}: {e}"
            if r is None or not r.ok:
                totals["identity_unproved"] += 1
                print(f"[identity] {name}: {verdict if r is None else r.status + ' ' + r.reason}")
            row = {"proved": 0, "false": 0, "ue": 0, "ud": 0, "n": 0}
            for label, msrc in mutate.mutants(src, name, ns.limit):
                totals["mutants"] += 1
                row["n"] += 1
                try:
                    r, verdict = check_pair(src, msrc, name)
                except RecursionError:
                    totals["crash"] += 1
                    print(f"[crash] {name} {label}: RecursionError")
                    continue
                except Exception as e:  # noqa: BLE001
                    totals["crash"] += 1
                    print(f"[crash] {name} {label}: {type(e).__name__}: {e}")
                    if ns.verbose:
                        import traceback

                        traceback.print_exc()
                    continue
                if verdict.startswith("FALSE PROOF"):
                    totals["false_proofs"] += 1
                    row["false"] += 1
                    false_list.append((name, label, verdict, msrc))
                    print(f"[FALSE PROOF] {name} {label} mode={r.mode}: {verdict[:300]}")
                elif r.ok:
                    totals["proved"] += 1
                    row["proved"] += 1
                    if ns.verbose:
                        print(f"   proved   {name} {label} ({r.mode})")
                elif verdict == "unproved-equal":
                    totals["unproved_equal"] += 1
                    row["ue"] += 1
                    if ns.verbose:
                        print(f"   unproved-equal {name} {label}: {r.status} {r.reason[:100]}")
                else:
                    totals["unproved_different"] += 1
                    row["ud"] += 1
            print(f"{name:18s} mutants={row['n']:3d} proved={row['proved']:3d} false={row['false']} unproved: equal={row['ue']:3d} different={row['ud']:3d}")
            sys.stdout.flush()
    print(f"TOTAL {totals}  [{time.time() - t0:.0f}s]")
    for name, label, verdict, msrc in false_list[:5]:
        print("=" * 100)
        print(name, label, verdict)
        print(msrc)
    return 1 if totals["false_proofs"] or totals["crash"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
