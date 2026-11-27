# SPDX-License-Identifier: Apache-2.0
"""Layer 5: feedback records that change what later runs are allowed to conclude.

NOTE: ``_legacy`` is a historical filename retained without renaming to preserve internal
imports; this module is the active Layer 5 implementation backing ``hlith.feedback``.

A ``FeedbackRecord`` is a content-addressed JSON file under
``<repo>/.hlith/feedback/``. That directory is kept outside the tracked tree
(``.git/info/exclude``) so a record never makes the target dirty for the gate,
and it is written only by ``persist``. ``persist`` is meant to be called from
the gate supervisor after an outcome, and it refuses while a landing journal is
pending.

There are three directives:

* ``pin_regression_counterexample``: one concrete input and the outcome the
  base produced for it. A later check of the symbol must reproduce that outcome.
* ``require_differential_domain_constraint``: inputs a later differential must
  run first, plus whether a new exception class counts as a divergence.
* ``mark_construct_unresolvable``: a construct that later derivation must treat
  as not derivable.

Records load by symbol cone: a record applies when its ``target_symbols``
intersect the transitive caller/callee cone of the current effect. Layer 2
computes the cone; this module only intersects with it.

The post-gate probe (``post_gate_probe``) runs base and landed code under
``hlith.sandbox`` on boundary variants of the inputs a check already used, and
pins each input where the two disagree. ``probe_obligation`` turns the probe
into an obligation. Its provenance is measured: the confined runner tries to
open every proposer path and reports what it could read.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import stat
import re
import subprocess
import sys
from dataclasses import dataclass, field, replace as _dc_replace
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..sandbox import Profile, run_confined
from ..types import BoundedEvidence, CheckProvenance, Obligation, Verdict

SCHEMA_VERSION = "0.1.0"
FEEDBACK_SUBDIR = Path(".hlith") / "feedback"
_ID_RE = re.compile(r"^fb-[a-f0-9]{20}$")
_SUPERSEDED_RE = re.compile(r"^(fb-[a-f0-9]{20})\.superseded\.jsonl$")  # appended provenance beside a record (design review F-A)
_GIT_SHA_RE = re.compile(r"^([a-f0-9]{40}|[a-f0-9]{64})$")


class FeedbackIntegrityError(RuntimeError):
    """A record on disk is unreadable, mislabelled or tampered with. Fail closed."""


class FeedbackWriteRefused(RuntimeError):
    """The store cannot be written safely right now."""


class DirectiveKind(str, enum.Enum):
    PIN_REGRESSION_COUNTEREXAMPLE = "pin_regression_counterexample"
    REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT = "require_differential_domain_constraint"
    MARK_CONSTRUCT_UNRESOLVABLE = "mark_construct_unresolvable"
    ORACLE_REGRESSION = "oracle_regression"
    NOT_DERIVED_CONSTRUCT = "not_derived_construct"


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _json_safe(value: Any, what: str) -> Any:
    try:
        return json.loads(_canon(value))
    except (TypeError, ValueError) as e:
        raise ValueError(f"{what} must be JSON-representable: {e}") from None


# a pin input beyond this is refused (reported unpinned, never silently dropped): generous enough for the extended probe's
# truncation inputs (a 70000-element list is ~210 KB) but bounded so a hostile or runaway witness cannot bloat the store
_MAX_PIN_INPUT_BYTES = 1 << 20


def _call_input(args: Sequence[Any], kwargs: dict | None, env: dict | None = None) -> dict:
    """A call input. ``env`` (optional) is part of the input: environment variables set for the call
    (value None = unset). Behaviour that depends on os.environ diverges on (args, env) pairs."""
    if not isinstance(args, (list, tuple)):  # list('abc') would silently splat a str into three positional args (a wrong pin)
        raise TypeError(f"args must be a list or tuple of positional arguments, not {type(args).__name__}")
    from ..contract.codec import encode_pin_values  # a float is recorded as a typed, bit-exact tag: the contract store refuses a raw float and the pin used to be DROPPED

    out = {"args": _json_safe(encode_pin_values(list(args)), "args"), "kwargs": _json_safe(encode_pin_values(dict(kwargs or {})), "kwargs")}
    if env:
        if not all(isinstance(k, str) and (v is None or isinstance(v, str)) for k, v in env.items()):
            raise ValueError("env must map str -> str | None")
        out["env"] = dict(sorted(env.items()))
    size = len(_canon(out))  # one serialization of the COMPLETE input (args, kwargs and the normalised env)
    if size > _MAX_PIN_INPUT_BYTES:
        raise ValueError(f"pin input too large ({size} > {_MAX_PIN_INPUT_BYTES} bytes)")
    return out


def _inp(i: dict) -> dict:
    return _call_input(i["args"], i.get("kwargs"), i.get("env"))


def _check_outcome(o: Any) -> dict:
    if not isinstance(o, dict) or o.get("kind") not in ("return", "raise", "timeout"):
        raise ValueError(f"bad outcome: {o!r}")
    return _json_safe(o, "outcome")


_PAYLOAD_KEYS = {
    DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE: {"symbol", "input", "expected", "observed"},
    DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT: {"pinned_inputs", "disallow_exception_widening"},
    DirectiveKind.MARK_CONSTRUCT_UNRESOLVABLE: {"symbol", "construct_kind", "location"},
    DirectiveKind.ORACLE_REGRESSION: {"symbol", "tests", "input", "expected", "observed"},
    DirectiveKind.NOT_DERIVED_CONSTRUCT: {"symbol", "construct_kind", "location", "node_sha256"},
}
_PROVENANCE_KEYS = {"writer_run_id", "origin_kind", "observed_in_run", "f2_novelty_eligible", "scope"}
_PROVENANCE_ORIGINS = {
    "unknown-legacy": "unknown", "refusal-probe": "refused", "post-gate-probe": "refuted",
    "differential-witness": "refuted", "external-pin": "external",
    "predeclared-external-pin": "external", "unresolved-construct": "refused",
}


def _f2_novelty_source_is_eligible(kind: DirectiveKind, origin: str, observed: str) -> bool:
    if kind is DirectiveKind.NOT_DERIVED_CONSTRUCT:
        return origin == "unresolved-construct" and observed == "refused"
    if kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE:
        return (origin == "refusal-probe" and observed == "refused") or (
            origin in ("post-gate-probe", "differential-witness") and observed == "refuted"
        ) or (origin in ("external-pin", "predeclared-external-pin") and observed == "external")
    if kind is DirectiveKind.ORACLE_REGRESSION:
        return (origin == "post-gate-probe" and observed == "refuted") or (
            origin in ("external-pin", "predeclared-external-pin") and observed == "external"
        )
    return False


def _check_probe_meta(m: Any) -> None:
    """Replay data of an extended post-landing probe pin: {family, seed, origin, budget_s}, nothing else."""
    if not (isinstance(m, dict) and set(m) == {"family", "seed", "origin", "budget_s"} and isinstance(m["family"], str)
            and type(m["seed"]) is int and isinstance(m["origin"], str) and m["family"] and m["origin"]
            and len(m["family"]) <= 32 and len(m["origin"]) <= 200 and type(m["budget_s"]) is int):
        raise ValueError(f"bad probe provenance: {m!r}")


@dataclass(frozen=True)
class FeedbackRecord:
    source_run_id: str
    target_symbols: tuple[str, ...]
    directive_kind: DirectiveKind
    directive_payload: dict
    schema_version: str = SCHEMA_VERSION
    feedback_id: str = field(default="")
    provenance: dict | None = None
    _legacy_provenance_compat: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        if not self.source_run_id or not self.target_symbols or not all(self.target_symbols):
            raise ValueError("record needs a source run and at least one target symbol")
        kind = DirectiveKind(self.directive_kind)
        object.__setattr__(self, "directive_kind", kind)
        object.__setattr__(self, "target_symbols", tuple(sorted(set(self.target_symbols))))
        payload = _json_safe(self.directive_payload, "directive_payload")
        keys_ = set(payload) if isinstance(payload, dict) else None
        if kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE and keys_ == _PAYLOAD_KEYS[kind] | {"probe"}:
            _check_probe_meta(payload["probe"])  # an extended post-landing probe's replay data (seed, origin)
        elif keys_ != _PAYLOAD_KEYS[kind]:
            raise ValueError(f"{kind.value} payload needs exactly {sorted(_PAYLOAD_KEYS[kind])}")
        if kind is DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT and not payload["pinned_inputs"]:
            raise ValueError("domain constraint needs at least one pinned input")
        object.__setattr__(self, "directive_payload", payload)
        if self.provenance is None and kind in {
            DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE,
            DirectiveKind.ORACLE_REGRESSION,
        }:
            object.__setattr__(self, "provenance", {
                "writer_run_id": self.source_run_id,
                "origin_kind": "unknown-legacy",
                "observed_in_run": "unknown",
                "f2_novelty_eligible": False,
                "scope": list(self.target_symbols),
            })
        if self.provenance is not None:
            provenance = _json_safe(self.provenance, "provenance")
            if not isinstance(provenance, dict) or set(provenance) != _PROVENANCE_KEYS:
                raise ValueError(f"feedback provenance needs exactly {sorted(_PROVENANCE_KEYS)}")
            writer, origin, observed = (provenance[k] for k in ("writer_run_id", "origin_kind", "observed_in_run"))
            scope = provenance["scope"]
            if not all(isinstance(v, str) and v for v in (writer, origin, observed)) or writer != self.source_run_id:
                raise ValueError("feedback provenance writer and labels must match the record")
            if origin not in _PROVENANCE_ORIGINS or _PROVENANCE_ORIGINS[origin] != observed:
                raise ValueError("unsupported or inconsistent feedback provenance origin")
            if not isinstance(scope, list) or scope != list(self.target_symbols):
                raise ValueError("feedback provenance scope must exactly match target_symbols")
            eligible = _f2_novelty_source_is_eligible(kind, origin, observed)
            if type(provenance["f2_novelty_eligible"]) is not bool or provenance["f2_novelty_eligible"] != eligible:
                raise ValueError("feedback provenance novelty eligibility does not match its source")
            object.__setattr__(self, "provenance", provenance)
        want = "fb-" + hashlib.sha256(_canon(self._body()).encode()).hexdigest()[:20]
        if self.feedback_id and self.feedback_id != want:
            raise FeedbackIntegrityError(f"feedback_id {self.feedback_id} does not match content ({want})")
        object.__setattr__(self, "feedback_id", want)

    def _body(self) -> dict:
        body = {
            "schema_version": self.schema_version,
            "source_run_id": self.source_run_id,
            "target_symbols": list(self.target_symbols),
            "directive_kind": self.directive_kind.value,
            "directive_payload": self.directive_payload,
        }
        if self.provenance is not None and not self._legacy_provenance_compat:
            body["provenance"] = self.provenance
        return body

    def to_json(self) -> dict:
        return {"feedback_id": self.feedback_id, **self._body()}

    @classmethod
    def from_json(cls, data: dict) -> "FeedbackRecord":
        if not isinstance(data, dict) or set(data) not in ({"feedback_id", *cls._body_keys()}, {"feedback_id", *cls._body_keys(), "provenance"}):
            raise FeedbackIntegrityError(f"record keys {sorted(data) if isinstance(data, dict) else data!r}")
        try:
            return cls(
                source_run_id=data["source_run_id"],
                target_symbols=tuple(data["target_symbols"]),
                directive_kind=DirectiveKind(data["directive_kind"]),
                directive_payload=data["directive_payload"],
                schema_version=data["schema_version"],
                feedback_id=data["feedback_id"],
                provenance=data["provenance"] if "provenance" in data else None,
                _legacy_provenance_compat=(
                    "provenance" not in data
                    and data["directive_kind"] in {
                        DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE.value,
                        DirectiveKind.ORACLE_REGRESSION.value,
                    }
                ),
            )
        except (ValueError, TypeError) as e:
            raise FeedbackIntegrityError(str(e)) from None

    @staticmethod
    def _body_keys() -> set[str]:
        return {"schema_version", "source_run_id", "target_symbols", "directive_kind", "directive_payload"}


def with_provenance(record: FeedbackRecord, *, origin_kind: str, observed_in_run: str) -> FeedbackRecord:
    if origin_kind not in _PROVENANCE_ORIGINS or _PROVENANCE_ORIGINS[origin_kind] != observed_in_run:
        raise ValueError("unsupported or inconsistent feedback provenance origin")
    provenance = {"writer_run_id": record.source_run_id, "origin_kind": origin_kind,
                  "observed_in_run": observed_in_run,
                  "f2_novelty_eligible": _f2_novelty_source_is_eligible(record.directive_kind, origin_kind, observed_in_run),
                  "scope": list(record.target_symbols)}
    return _dc_replace(record, provenance=provenance, feedback_id="", _legacy_provenance_compat=False)


def eligible_for_f2(record: FeedbackRecord, run1_id: str) -> tuple[bool, str]:
    provenance = record.provenance
    if not isinstance(provenance, dict) or provenance.get("f2_novelty_eligible") is not True:
        return False, "no-independent-source"
    if provenance.get("writer_run_id") == run1_id:
        if provenance.get("origin_kind") in ("refusal-probe", "differential-witness", "post-gate-probe"):
            return False, "written-by-run1-probe"
        if record.directive_kind is not DirectiveKind.NOT_DERIVED_CONSTRUCT:
            return False, "no-independent-source"
    if tuple(provenance.get("scope", ())) != record.target_symbols:
        return False, "no-independent-source"
    return True, "eligible-source; I3 evidence still required"


# ---- the three directive constructors -------------------------------------------------


def pin_regression_counterexample(
    source_run_id: str, symbol: str, args: Sequence[Any], kwargs: dict | None, *, expected: dict, observed: dict,
    env: dict | None = None,
) -> FeedbackRecord:
    return FeedbackRecord(
        source_run_id,
        (symbol,),
        DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE,
        {"symbol": symbol, "input": _call_input(args, kwargs, env),
         "expected": _check_outcome(expected), "observed": _check_outcome(observed)},
    )


def require_differential_domain_constraint(
    source_run_id: str,
    target_symbols: Iterable[str],
    pinned_inputs: Iterable[tuple[Sequence[Any], dict | None]],
    *,
    disallow_exception_widening: bool = True,
) -> FeedbackRecord:
    return FeedbackRecord(
        source_run_id,
        tuple(target_symbols),
        DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT,
        {"pinned_inputs": [_call_input(a, k) for a, k in pinned_inputs],
         "disallow_exception_widening": bool(disallow_exception_widening)},
    )


def oracle_regression(source_run_id: str, symbol: str, tests: Sequence[str], args: Sequence[Any], kwargs: dict | None,
                      *, expected: dict, observed: dict, env: dict | None = None) -> FeedbackRecord:
    """Hlith.md OR4: the test oracle a held verdict relied on (``tests``: the repository tests that reference
    the target) passed while the landed change diverged on ``input``. The record marks that oracle as
    insufficient; the counterexample tightens every later check of ``symbol`` (pinned, expected = base)."""
    if not tests:
        raise ValueError("oracle_regression needs the relied-upon tests")
    return FeedbackRecord(
        source_run_id,
        (symbol,),
        DirectiveKind.ORACLE_REGRESSION,
        {"symbol": symbol, "tests": sorted(set(tests)), "input": _call_input(args, kwargs, env),
         "expected": _check_outcome(expected), "observed": _check_outcome(observed)},
    )


def not_derived_construct(source_run_id: str, symbol: str, construct_kind: str, location: str,
                          node_sha256: str) -> FeedbackRecord:
    """A construct a refused run stopped on (not-derived), bound to the exact source node (review's provenance
    node_sha256). It applies to a later run only while the effect account still reports a construct with the
    same file and node digest: a removed or edited construct never matches, so the record can never refuse
    stale code."""
    if not construct_kind or not location or not re.fullmatch(r"[0-9a-f]{64}", node_sha256 or ""):
        raise ValueError("construct_kind, location and a 64-hex node_sha256 are required")
    record = FeedbackRecord(
        source_run_id,
        (symbol,),
        DirectiveKind.NOT_DERIVED_CONSTRUCT,
        {"symbol": symbol, "construct_kind": construct_kind, "location": location, "node_sha256": node_sha256},
    )
    return with_provenance(record, origin_kind="unresolved-construct", observed_in_run="refused")


def recurrent_constructs(records: Iterable[FeedbackRecord], constructs: Iterable[dict]) -> list[dict]:
    """design policy 2026-11-13: recurrence is INFORMATION, not an obligation. For each current construct that already
    stopped earlier refused runs (matched on file + node_sha256 on the changed side, never on location alone), one
    entry with the construct key, the count of earlier runs and their ids. Never blocks: whenever such a construct
    is derived again, derive already blocks it with its own unresolved-* obligation in the same run; and an
    unsupported_entry_guard deferred for an approved delta must not be re-blocked by memory of earlier refusals.
    One entry per construct (file, node digest, kind), however many refused runs recorded it (review rerun finding b);
    the id is derived from that key, so it is stable across runs."""
    # only constructs present in the CHANGED tree count: the account also inventories the base side, and a
    # construct the change removed must never be reported. Without review's side marker nothing matches.
    cur = {((c.get("provenance") or {}).get("source_file") or c.get("file_path"),
            (c.get("provenance") or {}).get("node_sha256")) for c in constructs
           if c.get("side") in ("post", "both")}
    groups: dict[tuple[str, str, str], list[FeedbackRecord]] = {}
    for r in records:
        if r.directive_kind is not DirectiveKind.NOT_DERIVED_CONSTRUCT:
            continue
        p = r.directive_payload
        key = (p["location"].rsplit(":", 1)[0], p["node_sha256"], p["construct_kind"])
        if key[:2] in cur:
            groups.setdefault(key, []).append(r)
    out = []
    for key in sorted(groups):
        rs = sorted(groups[key], key=lambda r: r.feedback_id)
        p = rs[0].directive_payload
        out.append({"id": "recurrent-" + hashlib.sha256("\0".join(key).encode()).hexdigest()[:20],
                    "construct": {"kind": p["construct_kind"], "site": p["location"], "node_sha256": p["node_sha256"]},
                    "symbol": p["symbol"],
                    "earlier_refused_runs": len({r.source_run_id for r in rs}),
                    "run_ids": sorted({r.source_run_id for r in rs}),
                    "fb_ids": [r.feedback_id for r in rs],
                    "note": (f"this construct already stopped {len({r.source_run_id for r in rs})} earlier refused "
                             f"run{'s' if len({r.source_run_id for r in rs}) != 1 else ''} (information, not an obligation)")})
    return out


def mark_construct_unresolvable(source_run_id: str, symbol: str, construct_kind: str, location: str) -> FeedbackRecord:
    if not construct_kind or not location:
        raise ValueError("construct_kind and location are required")
    return FeedbackRecord(
        source_run_id,
        (symbol,),
        DirectiveKind.MARK_CONSTRUCT_UNRESOLVABLE,
        {"symbol": symbol, "construct_kind": construct_kind, "location": location},
    )


# ---- store -----------------------------------------------------------------------------


def _run_git_ro(repo: Path, args: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    from ..hostio.git_read import TIMEOUT, readonly_argv, scrubbed_git_env, vet_repository

    real = Path(repo).resolve()
    violation = vet_repository(real)  # closed-world, fail-closed (this runner used to vet only the .git shape)
    if violation is not None:
        raise FeedbackWriteRefused(f"git {' '.join(args)}: {violation}")
    try:
        return subprocess.run(readonly_argv(real, args), capture_output=True, text=True, env=scrubbed_git_env(None), check=False, timeout=TIMEOUT * 4)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FeedbackWriteRefused(f"git {' '.join(args)}: cannot run git ({getattr(exc, 'strerror', None) or exc})") from None


def _git(repo: Path, *args: str) -> str:
    # Every git call on a user-selected repository goes through the hardened runner (scrubbed allow-listed env, no inherited GIT_DIR/GIT_WORK_TREE,
    # fsmonitor/hooks/attributes/pager neutralised): plain `git -C repo` would execute repository-configured programs.
    cp = _run_git_ro(Path(repo), tuple(args))
    if cp.returncode != 0:
        raise FeedbackWriteRefused(f"git {' '.join(args)}: {cp.stderr.strip()}")
    return cp.stdout


_GIT_BIN = "git"


def _apply_diff_scrubbed(cand: Path, diff: str):
    """`git apply` inside a plain EXPORT directory (not a repository, so real-.git rule does not apply). Scrubbed environment: no inherited
    GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE, no user/system config, no parent-repository discovery above the export."""
    import tempfile
    from ..hostio.git_read import _HARDEN

    with tempfile.TemporaryDirectory(prefix="hlith-git-home-", dir="/tmp") as home:
        env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "LC_ALL": "C", "HOME": home, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_CEILING_DIRECTORIES": str(Path(cand).resolve().parent)}
        return subprocess.run([_GIT_BIN, "--no-pager", *_HARDEN, "apply", "-"], input=diff.encode(), cwd=str(cand), capture_output=True, env=env, check=False)


def feedback_dir(repo: Path) -> Path:
    return Path(repo) / FEEDBACK_SUBDIR


def _safe_dir(repo: Path, create: bool) -> Path:
    """Return the store directory, refusing symlinks and paths that escape the repo."""
    repo = Path(repo).resolve()
    cur = repo
    for part in FEEDBACK_SUBDIR.parts:
        cur = cur / part
        if cur.is_symlink():
            raise FeedbackWriteRefused(f"{cur} is a symlink")
        if create and not cur.exists():
            cur.mkdir(mode=0o700)
    if cur.exists() and cur.resolve().parent.parent != repo:
        raise FeedbackWriteRefused(f"{cur} resolves outside {repo}")
    return cur


def _ensure_excluded(repo: Path) -> None:
    exclude = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude").strip())
    line = f"/{FEEDBACK_SUBDIR.parts[0]}/"
    text = exclude.read_text() if exclude.exists() else ""
    if line not in text.splitlines():
        exclude.parent.mkdir(parents=True, exist_ok=True)
        with open(exclude, "a") as f:
            f.write(("" if text.endswith("\n") or not text else "\n") + line + "\n")


def persist(repo: Path, record: FeedbackRecord) -> Path:
    """Write one record atomically. Called by the gate supervisor after an outcome.

    Refuses while a gate landing journal is pending, when anything under
    ``.hlith/`` is tracked, or when the store is a symlink. Idempotent: the file
    name is the content hash.
    """
    repo = Path(repo)
    journal = Path(_git(repo, "rev-parse", "--absolute-git-dir").strip()) / "hlith-journal.json"
    if journal.exists():
        raise FeedbackWriteRefused("gate landing journal pending; run gate.recover first")
    if _git(repo, "ls-files", "--", FEEDBACK_SUBDIR.parts[0]).strip():
        raise FeedbackWriteRefused(".hlith/ has tracked files; feedback must stay outside the tracked tree")
    _ensure_excluded(repo)
    d = _safe_dir(repo, create=True)
    final = d / f"{record.feedback_id}.json"
    tmp = d / f".tmp-{record.feedback_id}-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, final)
    dfd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return final


def load_records(repo: Path, cone: Iterable[str] | None) -> tuple[FeedbackRecord, ...]:
    """Every intact record whose target symbols intersect ``cone``, in id order.

    Any malformed or tampered record raises ``FeedbackIntegrityError``, even one
    outside the cone, because nobody can tell what it was meant to target.
    """
    d = _safe_dir(Path(repo), create=False)
    if not d.exists():
        return ()
    cone = None if cone is None else set(cone)  # None: every intact record
    out = []
    names = {p.name for p in d.iterdir()}
    landed_superseded = _landed_superseded(Path(repo), d, names)
    for p in sorted(d.iterdir()):
        if p.name.startswith(".tmp-"):
            continue  # torn write from a dead process; never loaded
        if _SUPERSEDED_RE.match(p.name):
            continue  # validated by _landed_superseded
        if p.suffix != ".json" or not _ID_RE.match(p.stem):
            raise FeedbackIntegrityError(f"unexpected file in feedback store: {p.name}")
        if not stat.S_ISREG(os.lstat(p).st_mode):  # FIFO/socket/symlink: never opened (a FIFO read blocks)
            raise FeedbackIntegrityError(f"non-regular file in feedback store: {p.name}")
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError) as e:
            raise FeedbackIntegrityError(f"{p.name}: {e}") from None
        rec = FeedbackRecord.from_json(data)
        if rec.feedback_id != p.stem:
            raise FeedbackIntegrityError(f"{p.name} holds record {rec.feedback_id}")
        if rec.feedback_id in landed_superseded and rec.directive_kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE:
            continue  # design review post-landing rule: HEAD embodies the approved behaviour this pin contradicted
        if cone is None or cone & set(rec.target_symbols):
            out.append(rec)
    return tuple(out)


def _landed_superseded(repo: Path, d: Path, names: set) -> set:
    """fb ids superseded by a LANDED approved delta whose landed commit is still an ancestor of HEAD. Every
    sidecar is validated (regular file, its record present, each line a well-formed supersession) whether or not it
    holds a landing line; anything else is tampering and raises. A landing no longer in HEAD's history (reset,
    rewritten branch) does not count, so the pin applies again."""
    out = set()
    for name in sorted(names):
        m = _SUPERSEDED_RE.match(name)
        if not m:
            continue
        p = d / name
        if not stat.S_ISREG(os.lstat(p).st_mode):
            raise FeedbackIntegrityError(f"non-regular file in feedback store: {name}")
        if f"{m.group(1)}.json" not in names:
            raise FeedbackIntegrityError(f"{name}: supersession for a record that is not in the store")
        try:
            lines = [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
        except (OSError, ValueError) as e:
            raise FeedbackIntegrityError(f"{name}: {e}") from None
        for ln in lines:
            if not isinstance(ln, dict) or not _SHA256_HEX(ln.get("delta_set_sha256")) or\
                    not (("superseded_by_delta" in ln) ^ ("superseded_by_landing" in ln)):
                raise FeedbackIntegrityError(f"{name}: malformed supersession line")
            landed = ln.get("superseded_by_landing")
            if landed is None:
                continue
            if not isinstance(landed, str) or not _GIT_SHA_RE.match(landed):
                raise FeedbackIntegrityError(f"{name}: malformed landed commit")
            anc = _run_git_ro(Path(repo), ("merge-base", "--is-ancestor", landed, "HEAD"))
            if anc.returncode == 0:
                out.add(m.group(1))
    return out


def _SHA256_HEX(v) -> bool:
    return isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) is not None


def _append_supersession(repo: Path, fb_id: str, line: dict) -> None:
    store = _safe_dir(Path(repo), False)  # refuses symlinked or escaping store paths
    p = store / f"{fb_id}.superseded.jsonl"
    if p.exists() and not stat.S_ISREG(os.lstat(p).st_mode):
        raise FeedbackIntegrityError(f"{p} is not a regular file")
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, sort_keys=True) + "\n")


# ---- what loaded records mean for later layers --------------------------------------------


@dataclass(frozen=True)
class Pinned:
    args: tuple
    kwargs: dict
    expected: dict | None = None  # base outcome, when the record pinned one
    env: dict | None = None  # environment set for the call (value None = unset)


@dataclass(frozen=True)
class DifferentialConstraints:
    """Read by attribute by hlith.differential (review); neither module imports the other."""

    pinned_inputs: tuple[Pinned, ...]
    disallow_exception_widening: bool
    source_feedback_ids: tuple[str, ...]


def _decode_floats(v):
    """Typed float tags back to the recorded floats (the inverse of the pin encoding); everything else untouched."""
    from ..contract.codec import decode_call_values

    return decode_call_values(v)


def constraints_for(records: Iterable[FeedbackRecord], symbol: str) -> DifferentialConstraints | None:
    """Merge every applicable record. Order-independent and monotone: adding a record never drops a pin,
    an expected outcome or the widening rule. Distinct expectations for one input are all kept."""
    exps: dict[str, list] = {}  # canonical input -> distinct expected outcomes (None = differential only)
    inputs: dict[str, dict] = {}
    widen = False
    ids: list[str] = []
    for r in sorted(records, key=lambda r: r.feedback_id):
        p = r.directive_payload
        if r.directive_kind in (DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE, DirectiveKind.ORACLE_REGRESSION)\
                and p["symbol"] == symbol:
            new = [(p["input"], p["expected"])]
            widen = True  # a pinned base outcome is a regression oracle
        elif r.directive_kind is DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT and symbol in r.target_symbols:
            new = [(i, None) for i in p["pinned_inputs"]]
            widen = widen or p["disallow_exception_widening"]
        else:
            continue
        ids.append(r.feedback_id)
        for inp, exp in new:
            key = _canon(inp)
            inputs.setdefault(key, inp)
            lst = exps.setdefault(key, [])
            if exp is not None and exp not in lst:
                lst.append(exp)
    if not inputs:
        return None
    pins: list[Pinned] = []
    for key in sorted(inputs):
        inp = inputs[key]
        for exp in sorted(exps[key], key=_canon) or [None]:
            pins.append(Pinned(tuple(_decode_floats(inp["args"])), dict(_decode_floats(inp["kwargs"])), exp, inp.get("env")))
    return DifferentialConstraints(tuple(pins), widen, tuple(ids))


@dataclass(frozen=True)
class Unresolvable:
    symbol: str
    construct_kind: str
    location: str
    feedback_id: str


def unresolvable_for(records: Iterable[FeedbackRecord]) -> tuple[Unresolvable, ...]:
    return tuple(
        Unresolvable(r.directive_payload["symbol"], r.directive_payload["construct_kind"],
                     r.directive_payload["location"], r.feedback_id)
        for r in records
        if r.directive_kind is DirectiveKind.MARK_CONSTRUCT_UNRESOLVABLE
    )


FEEDBACK_ORIGIN = ("feedback-pins:", "feedback-unresolvable-", "feedback-env-unapplied:")


def feedback_effect(obligations: Any, loaded_ids: Sequence[str]) -> dict | None:
    """The per-run counterfactual (design review, cheap form): what decide() WOULD give over the same derived obligations without
    what the loaded feedback caused: the feedback-origin obligations (feedback-pins:*, ...) are removed, and an obligation
    whose refutation is witnessed by a PINNED input (witness 'pinned ...') is counted as feedback-derived and removed too.
    EXACT only when no remaining check had its domain seeded by feedback: a pin that also drove a check's adequacy (its
    explored domain says 'pinned inputs first') means the store-free check could be UNVERIFIED rather than HELD, so the
    counterfactual is then unknown (exact false, without null, no flip claimed; review F2-M on 2a6e539: the cheap form said
    'landed' while the real store-free control refused 12). Pure and deterministic; never changes the real verdict."""
    from ..types import ObligationSet, Verdict, decide

    if not loaded_ids:
        return None
    obs = tuple(obligations.obligations)
    origin = sorted(o.obligation_id for o in obs if o.obligation_id.startswith(FEEDBACK_ORIGIN))
    derived = sorted(o.obligation_id for o in obs if not o.obligation_id.startswith(FEEDBACK_ORIGIN)
                     and o.verdict is Verdict.REFUTED and (o.witness or "").startswith("pinned "))
    influenced = sorted(o.obligation_id for o in obs if not o.obligation_id.startswith(FEEDBACK_ORIGIN)
                        and (o.obligation_id in derived
                             or "pinned inputs first" in ((o.evidence.explored or "") if o.evidence is not None else "")))
    gone = set(origin) | set(derived)
    real = decide(ObligationSet(obs))
    rest = tuple(o for o in obs if o.obligation_id not in gone)
    exact = not influenced
    without = decide(ObligationSet(rest)) if (rest and exact) else None
    w = {"outcome": real.outcome.value, "exit_status": real.exit_status}
    wo = None if without is None else {"outcome": without.outcome.value, "exit_status": without.exit_status}
    return {"loaded_feedback_ids": list(loaded_ids), "feedback_obligations": origin,
            "feedback_derived_refutations": derived, "feedback_influenced": influenced, "exact": exact,
            "with": w, "without": wo,
            "flips": wo is not None and wo["outcome"] != w["outcome"],
            "exit_changes": wo is not None and wo["exit_status"] != w["exit_status"]}


def not_derived_obligations(records: Iterable[FeedbackRecord], impact_slice: Iterable[str]) -> tuple[Obligation, ...]:
    """One NOT_DERIVED obligation per recorded unresolvable construct inside the slice."""
    sl = set(impact_slice)
    return tuple(
        Obligation(
            f"feedback-unresolvable-{u.feedback_id}",
            u.symbol,
            f"construct at {u.location} is resolvable for derivation",
            Verdict.NOT_DERIVED,
            stop_reason=f"{u.construct_kind} at {u.location} (feedback {u.feedback_id})",
        )
        for u in unresolvable_for(records)
        if u.symbol in sl
    )


# ---- confined observation, post-gate probe and pinned check -----------------------------------

_RUNNER = r'''
import hashlib, importlib, json, os, signal, sys
with open(sys.argv[1]) as _f:
    spec = json.load(_f)
# review: an address-space limit, identical on both sides, BEFORE any target code runs. Without it an allocation such as
# 'x' * 10**12 is not refused on an overcommitting host (vm.overcommit_memory=1): the probe fills host memory instead of raising
# MemoryError. Same bound as the L2 evaluator (differential._EVAL_MEM_LIMIT).
import resource as _res
_res.setrlimit(_res.RLIMIT_AS, (int(spec["mem_limit"]),) * 2)
# review: target code must never see the runner's argv (a per-call random spec path): one side-independent argv
sys.argv = [spec["module"]]
readable = []
for p in spec["proposer_paths"]:
    try:
        os.close(os.open(p, os.O_RDONLY))
        readable.append(p)
    except OSError:
        pass
sys.path[:0] = spec["sys_path"]
import re as _re
_mod = importlib.import_module(spec["module"])
_recv = spec.get("receiver")  # review's recipe (differential._method_ctx): {cls, kind, ctor}; executed, never derived here
if _recv is None:
    fn = _mod
    for part in spec["function"].split("."):
        fn = getattr(fn, part)
_ADDR = _re.compile(r" at 0x[0-9a-fA-F]+")
def _state(o):
    try:
        return _ADDR.sub(" at 0x?", repr(sorted(vars(o).items())))
    except TypeError:
        return ""
class _T(BaseException):
    pass
def _exc(name):
    mod, _, qual = name.rpartition(".")
    obj = importlib.import_module(mod or "builtins")
    for part in qual.split("."):
        obj = getattr(obj, part)
    if not (isinstance(obj, type) and issubclass(obj, BaseException)):
        raise TypeError(f"{name} is not an exception class")
    return obj
def _build(x):
    """JSON -> call value. {"$obj": {"attrs": {..}, "methods": {name: {"return": v} | {"raise": "mod.Exc"}}}}
    builds a stub object with a deterministic repr; everything else is plain JSON."""
    if isinstance(x, list):
        return [_build(v) for v in x]
    if isinstance(x, dict):
        if set(x) == {"$float"} and isinstance(x["$float"], dict) and set(x["$float"]) == {"bits", "repr"} and isinstance(x["$float"]["bits"], str) and len(x["$float"]["bits"]) == 16:
            import struct as _st

            return _st.unpack(">d", bytes.fromhex(x["$float"]["bits"]))[0]  # the recorded typed float, bit for bit (sign/payload of a NaN included)
        if set(x) == {"$obj"}:
            spec = x["$obj"]
            ns = {"__repr__": lambda self, _r="<stub " + json.dumps(spec, sort_keys=True) + ">": _r}
            for m, beh in (spec.get("methods") or {}).items():
                if "raise" in beh:
                    ns[m] = (lambda e: lambda self, *a, **k: (_ for _ in ()).throw(e()))(_exc(beh["raise"]))
                else:
                    ns[m] = (lambda v: lambda self, *a, **k: _build(v))(beh.get("return"))
            o = type("Stub", (object,), ns)()
            for k, v in (spec.get("attrs") or {}).items():
                setattr(o, k, _build(v))
            return o
        return {k: _build(v) for k, v in x.items()}
    return x
def _short(s):
    return s if len(s) <= 500 else s[:200] + "...<len=%d sha256=%s>" % (
        len(s), hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest())
def _canon_ret(v, depth=0):
    """Canonical return repr (review): sets/frozensets in sorted element order (process hash order is not
    behaviour), object addresses normalised; containers recursed to a bounded depth."""
    if depth > 6:
        return _ADDR.sub(" at 0x?", repr(v))
    if type(v) in (set, frozenset):
        inner = ", ".join(sorted(_canon_ret(x, depth + 1) for x in v))
        return ("{" + inner + "}" if v else "set()") if type(v) is set else "frozenset({" + inner + "})"
    if type(v) is list:
        return "[" + ", ".join(_canon_ret(x, depth + 1) for x in v) + "]"
    if type(v) is tuple:
        return "(" + ", ".join(_canon_ret(x, depth + 1) for x in v) + ("," if len(v) == 1 else "") + ")"
    if type(v) is dict:
        return "{" + ", ".join(_canon_ret(k, depth + 1) + ": " + _canon_ret(x, depth + 1) for k, x in v.items()) + "}"
    return _ADDR.sub(" at 0x?", repr(v))
def _alarm(*_):
    raise _T()
signal.signal(signal.SIGALRM, _alarm)
out = []
streak = 0
stopped = None
for inp in spec["inputs"]:
    saved = dict(os.environ)
    for k, v in (inp.get("env") or {}).items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    signal.setitimer(signal.ITIMER_REAL, spec["timeout"])
    args, kwargs = _build(inp["args"]), _build(inp["kwargs"])  # fresh objects per call (decoded from JSON)
    recv = None
    try:
        if _recv is not None:  # fresh receiver per call: no state leaks between inputs
            cls = getattr(importlib.import_module(_recv.get("cls_module") or spec["module"]), _recv["cls"])
            meth = spec["function"].split(".")[-1]
            if _recv["kind"] == "instance":
                err = None
                for alt in _recv.get("ctor_alts") or [_recv["ctor"]]:  # review: try the alternatives in order
                    try:
                        recv = cls(*_build(alt[0]), **_build(alt[1]))
                        break
                    except Exception as e:
                        err = e
                else:
                    raise err
                fn = getattr(recv, meth)
            else:
                fn = getattr(cls, meth)
        before = _short(repr((args, kwargs))) + ("" if recv is None else " self=" + _short(_state(recv)))
        r = fn(*args, **kwargs)
        # never compare a truncated repr: long values keep head + length + digest of the whole
        o = {"kind": "return", "repr": _short(_canon_ret(r))}
        after = _short(repr((args, kwargs))) + ("" if recv is None else " self=" + _short(_state(recv)))
        if after != before:  # the callee mutated its arguments: part of observable behaviour
            o["args_after"] = after
    except _T:
        o = {"kind": "timeout"}
    except SystemExit:  # a target calling sys.exit (argparse error, CLI main) is an outcome, never a probe crash
        o = {"kind": "raise", "exc": "builtins.SystemExit"}
    except Exception as e:
        t = type(e)
        o = {"kind": "raise", "exc": t.__module__ + "." + t.__qualname__}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        os.environ.clear()
        os.environ.update(saved)
    out.append(o)
    streak = streak + 1 if o["kind"] == "timeout" else 0
    if streak >= 3 and len(out) < len(spec["inputs"]):  # case: a callable that does not return is not probed n x timeout
        stopped = {"reason": "callable does not return", "consecutive_timeouts": streak, "executed": len(out),
                   "not_executed": len(spec["inputs"]) - len(out)}
        break
sys.stdout.write("\nHLITH-PROBE " + json.dumps({"readable": readable, "outcomes": out, "stopped": stopped}) + "\n")
'''
CHECKER_ID = "hlith.feedback.probe"
CHECKER_SHA256 = hashlib.sha256(_RUNNER.encode()).hexdigest()


PROBE_WALL_CEILING_S = 300.0  # case (design policy): total wall ceiling of one confined probe run; a timeout is UNVERIFIED, never a pass


@dataclass(frozen=True)
class Observation:
    """``outcomes`` hold ONLY the inputs that were executed. If the probe stopped early (3 consecutive per-call timeouts),
    ``stopped`` = {reason, consecutive_timeouts, executed, not_executed}: the remainder was NOT executed, so every consumer
    that pairs inputs with outcomes (zip) sees only executed inputs and no pin or verdict can cover the rest."""

    outcomes: tuple[dict, ...]
    provenance: CheckProvenance
    stopped: dict | None = None


def _interp_prefixes(python: str) -> list[str]:
    from hlith.hostio.interpreter import interpreter_prefixes

    return interpreter_prefixes(python)


def _reject_special_files(roots: Sequence[str | Path]) -> None:
    """Reject FIFOs, sockets, and device nodes under read-only grant roots."""
    for raw in roots:
        p = Path(raw)
        if not p.exists():
            continue
        st = os.lstat(p)
        if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            raise FeedbackIntegrityError(f"special file under read-only root: {p}")
        if stat.S_ISDIR(st.st_mode):
            for dirpath, dirs, files in os.walk(p, followlinks=False):
                for name in (*dirs, *files):
                    cand = Path(dirpath) / name
                    cst = os.lstat(cand)
                    if stat.S_ISFIFO(cst.st_mode) or stat.S_ISSOCK(cst.st_mode) or stat.S_ISCHR(cst.st_mode) or stat.S_ISBLK(cst.st_mode):
                        raise FeedbackIntegrityError(f"special file under read-only root: {cand}")


def observe(
    src_root: str | Path,
    module: str,
    function: str,
    inputs: Sequence[dict],
    *,
    python: str = sys.executable,
    extra_sys_path: Sequence[str] = (),
    proposer_paths: Sequence[str] = (),
    call_timeout: float = 5.0,
    receiver: dict | None = None,
) -> Observation:
    """Call ``module.function`` on each input inside hlith.sandbox; return outcomes and provenance.
    ``receiver`` (a method target): review's recipe {cls, kind, ctor}; a fresh receiver is built per call and
    its state after the call is compared with the arguments' (``args_after``)."""
    import tempfile

    src_root = str(Path(src_root).resolve())
    # finding 24 class: a socket/FIFO/device under a read-only grant stays reachable from confined code (a
    # pathname AF_UNIX connect is not a write). Nothing Layer 5 grants may hold one: fail closed.
    _reject_special_files([src_root, *map(str, extra_sys_path)])
    specdir = tempfile.mkdtemp(prefix="hlith-probe-spec-")  # spec in a file: argv is size-limited
    dist = _probe_dist_info(Path(src_root), Path(specdir))  # same synthesized metadata as review's evaluator
    ro = (src_root, specdir, *map(str, extra_sys_path), *_interp_prefixes(python))
    profile = Profile(ro=ro)
    spec = {
        "sys_path": [src_root, *([dist] if dist else []), *map(str, extra_sys_path)],
        "module": module, "function": function, "timeout": call_timeout,
        "inputs": [dict(i) for i in inputs],
        "proposer_paths": [str(Path(p).resolve()) for p in proposer_paths],
        "receiver": receiver,
        "mem_limit": PROBE_MEM_LIMIT,
    }
    spec_path = Path(specdir) / "spec.json"
    spec_path.write_text(json.dumps(spec))
    try:
        cp = run_confined([python, "-I", "-c", _RUNNER, str(spec_path)], profile,
                          timeout=min(call_timeout * max(1, len(inputs)) + 30, PROBE_WALL_CEILING_S), cwd="/")
    finally:
        spec_path.unlink(missing_ok=True)
        if dist:  # only the files we synthesized: METADATA, INSTALLER, their dirs
            for f in sorted(Path(dist).rglob("*"), reverse=True):
                f.unlink() if f.is_file() else f.rmdir()
            os.rmdir(dist)
        os.rmdir(specdir)
    marker = [ln for ln in cp.stdout.splitlines() if ln.startswith("HLITH-PROBE ")]
    if cp.returncode == 4:
        raise RuntimeError(f"confinement could not be established: {cp.stderr.strip()}")
    if cp.returncode != 0 or len(marker) != 1:
        raise RuntimeError(f"probe failed (exit {cp.returncode}): {cp.stderr.strip()[-800:]}")
    rep = json.loads(marker[0][len("HLITH-PROBE "):])
    prov = CheckProvenance(CHECKER_ID, CHECKER_SHA256, True, bool(rep["readable"]), profile.sha256, cp.returncode)
    return Observation(tuple(rep["outcomes"]), prov, rep.get("stopped"))


_PROBE_BRIDGE: dict[str, Any] = {}


def register_probe_bridge(**callables: Any) -> None:
    """Register coordinator-injected lower probe/evaluator helpers without L5->L3 imports."""
    _PROBE_BRIDGE.update(callables)


def _probe_dist_info(src_root: Path, scratch: Path) -> str | None:
    """A source tree whose package reads its own metadata (importlib.metadata.version) does not import
    unless installed. Uses coordinator-registered dist-info synthesis if present."""
    synth = _PROBE_BRIDGE.get("synthesize_dist_info")
    if synth is None:
        return None
    for tree in (src_root, src_root.parent):
        if any((tree / f).is_file() for f in ("pyproject.toml", "setup.cfg", "setup.py")):
            rel = os.path.relpath(src_root, tree)
            return synth(str(tree), str(scratch / "dist"), "" if rel == "." else rel)
    return None


_TOKEN = re.compile(r"(\w+|\W+)")


def boundary_variants(value: Any) -> list[Any]:
    """Generic structural variants of a string: drop each word, drop each separator+word, empty, NUL."""
    if not isinstance(value, str):
        return []
    toks = _TOKEN.findall(value)
    out: list[str] = []
    for i, t in enumerate(toks):
        if t[0].isalnum() or t[0] == "_":
            out.append("".join(toks[:i] + toks[i + 1:]))
            if i > 0:
                out.append("".join(toks[: i - 1] + toks[i + 1:]))
            if any(c.isalpha() for c in t) and t.swapcase() != t:
                out.append("".join(toks[:i] + [t.swapcase()] + toks[i + 1:]))
    out += ["", value + "\x00"]
    seen, uniq = {value}, []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def _variants_of(inputs: Sequence[dict]) -> list[dict]:
    seen = {_canon(i) for i in inputs}
    out = []
    for inp in inputs:
        for pos, a in enumerate(inp["args"]):
            for v in boundary_variants(a):
                new = {"args": [*inp["args"][:pos], v, *inp["args"][pos + 1:]], "kwargs": dict(inp["kwargs"])}
                if inp.get("env"):
                    new["env"] = dict(inp["env"])
                if _canon(new) not in seen:
                    seen.add(_canon(new))
                    out.append(new)
    return out


def literal_seeds(src_root: str | Path, tests_root: str | Path, module: str, function: str, *, limit: int = 64) -> list[dict]:
    """Probe seeds taken from the target repository's own tests, by AST (nothing imported or run).

    * exact literal calls ``function(<consts>)`` in test files become seeds as written;
    * when the function has exactly one positional parameter, every string constant
      in a test file that references ``function`` becomes a one-argument seed.
    Order is deterministic (path, then source position).
    """
    import ast

    mod_file = _module_file(Path(src_root), module)
    if mod_file is None:
        r = import_root_of(src_root, module)
        mod_file = _module_file(r, module) if r is not None else None
    if mod_file is None:
        return []
    try:
        mod_tree = ast.parse(mod_file.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []
    fdef = next((n for n in ast.walk(mod_tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function.split(".")[-1]), None)
    if fdef is None:
        return []
    single = len(fdef.args.posonlyargs) + len(fdef.args.args) == 1 and not fdef.args.vararg
    name = function.split(".")[-1]
    seeds: list[dict] = []
    seen: set[str] = set()

    def add(inp: dict) -> None:
        k = _canon(inp)
        if k not in seen and len(seeds) < limit:
            seen.add(k)
            seeds.append(inp)

    for py in sorted(Path(tests_root).rglob("*.py")):
        try:
            tree = ast.parse(py.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue
        refs = any(isinstance(n, ast.Name) and n.id == name or isinstance(n, ast.Attribute) and n.attr == name
                   for n in ast.walk(tree))
        if not refs:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) == name:
                if all(isinstance(a, ast.Constant) for a in n.args) and all(isinstance(k.value, ast.Constant) and k.arg for k in n.keywords):
                    add({"args": [a.value for a in n.args], "kwargs": {k.arg: k.value.value for k in n.keywords}})
        if single:
            # only top-level statements (decorators included) that reference the function, imports excluded
            for top in tree.body:
                if isinstance(top, (ast.Import, ast.ImportFrom)):
                    continue
                if not any(isinstance(n, ast.Name) and n.id == name or isinstance(n, ast.Attribute) and n.attr == name
                           for n in ast.walk(top)):
                    continue
                consts = sorted((n for n in ast.walk(top) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                                 and len(n.value) > 3), key=lambda n: (n.lineno, n.col_offset))
                for c in consts:
                    add({"args": [c.value], "kwargs": {}})
    return seeds


_DIFF_SEED_LINE_MAX = 2048
_DIFF_SEED_SCAN_MAX = 64 * 1024


def diff_literal_seeds(effect_diff: str, *, limit: int = 12) -> list[dict]:
    """One-argument probe seeds from the string literals on the ADDED lines of the landed diff (a new guard's own
    trigger value), each bare and wrapped in double quotes, so the post-landing probe reaches the approved change.
    Seeds only: nothing here is evidence, and it runs after the gate decision."""
    import ast
    import re

    out: list[dict] = []
    seen: set[str] = set()
    scanned = 0
    for line in effect_diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if len(line) > _DIFF_SEED_LINE_MAX:  # the literal regex is quadratic on unterminated quotes: bound the work
            continue
        scanned += len(line)
        if scanned > _DIFF_SEED_SCAN_MAX:
            break
        for m in re.finditer(r"""(?<![\w])(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""", line[1:]):
            try:
                v = ast.literal_eval(m.group(0))
            except (ValueError, SyntaxError):
                continue
            if not isinstance(v, str) or not v or len(v) > 40:
                continue
            for w in (v, f'"{v}"', f'"a{v}b"'):
                if w not in seen and len(out) < limit:
                    seen.add(w)
                    out.append({"args": [w], "kwargs": {}})
    return out


def _matches(expected: dict, observed: dict) -> bool:
    """Observed satisfies a recorded expectation. Keys absent from an old record are not compared,
    except args_after: a record made by an oracle that saw no mutation pins 'no mutation'."""
    if any(observed.get(k) != v for k, v in expected.items()):
        return False
    return "args_after" in expected or "args_after" not in observed or expected.get("kind") != "return"


PROBE_MEM_LIMIT = 2 << 30  # RLIMIT_AS of every probe runner, both sides (= differential._EVAL_MEM_LIMIT)


def resource_limited(o: dict) -> bool:
    """The probe runner's memory limit was reached (RLIMIT_AS -> MemoryError). Such an outcome is a limit artefact, never behaviour."""
    return o.get("kind") == "raise" and o.get("exc") == "builtins.MemoryError"


def _diverges(base: dict, post: dict, widen: bool) -> bool:
    if base == post:
        return False
    if resource_limited(base) or resource_limited(post):
        # one side at the memory limit: a legitimate post may allocate a little more; never a witness, never a pin (as L2)
        return False
    if not widen and base["kind"] == "raise" and post["kind"] == "raise":
        return False  # exception class changed but both raise: only a divergence under widening rules
    return True


# ---- extended post-landing probe (design review F2 mechanism) ---------------------------------------------------------
# The ordinary post-landing probe draws from the repository's test literals, their variants and a small pool: a subset
# of what the differential already explored before landing, so it cannot learn anything the run did not already see.
# The extended probe runs AFTER landing (it never delays or changes a verdict) over families the differential's
# bounded domain does not cover: strings far beyond its length boundaries (<= 4097 unless the target spells larger
# constants), Unicode whitespace that str.isspace/strip treat as space, integers of hundreds of digits, long lists, and
# the literal arguments of the repository's OWN call sites (callers and tests, read by AST after landing). It pins only
# a CONFIRMED divergence between landed^ and landed (same record type), and each pin records the family, the seed and
# the origin of its input, so the probe is deterministic and replayable.
EXT_PROBE_FAMILY = "extended-v1"
_EXT_STR_LENGTHS = (8193, 9001, 16385, 32769, 65537)
_EXT_WS = "\x1c\x1d\x1e\x1f\x85\xa0\u1680\u2000\u2007\u200a\u2028\u2029\u202f\u205f\u3000"
_EXT_LIMIT = 64
EXT_BUDGET_S = 20          # total wall budget of the extended probe per run (all symbols), stated in every pin
_EXT_CALL_TIMEOUT = 1.0    # per call; a chunk of _EXT_CHUNK inputs may overrun the budget by at most 4 x chunk x this
_EXT_CHUNK = 8
_HARVEST_FILE_MAX = 512 << 10
_HARVEST_LIT_MAX = 512


def ext_probe_seed(symbol: str) -> int:
    """The derandomised seed of a symbol's extended probe (stable across runs and machines)."""
    return int(hashlib.sha256(f"{EXT_PROBE_FAMILY}:{symbol}".encode()).hexdigest()[:8], 16)


def extended_seeds(src_root: str | Path, module: str, function: str, *, seed: int,
                   limit: int = _EXT_LIMIT) -> list[dict]:
    """Inputs for the extended probe: each required positional parameter varied over the families above (by its
    annotation; unannotated = str and int), the others at a neutral background. Deterministic for a seed; at most
    ``limit``; every input carries its ``origin``."""
    import ast
    import random

    fdef, pos = _target_params(src_root, module, function)
    if fdef is None or not pos:
        return []
    required = pos[:len(pos) - len(fdef.args.defaults)] if fdef.args.defaults else pos
    if not 1 <= len(required) <= 3:
        return []
    rnd = random.Random(seed)

    def fam(arg) -> list:
        ann = ast.unparse(arg.annotation).replace(" ", "") if arg.annotation is not None else ""
        head = ann.split("[")[0]
        out: list = []
        if not ann or "str" in ann:
            out += [(f"len-{n}", "a" * n) for n in _EXT_STR_LENGTHS]
            out += [(f"len-{n}-mixed", "".join(rnd.choice("ab c\t.") for _ in range(n))) for n in _EXT_STR_LENGTHS[:2]]
            out += [(f"ws-{ord(c):04x}", f"{c}a{c}") for c in _EXT_WS]
        if not ann or "int" in ann:
            out += [(f"int-2**{k}", 2 ** k) for k in (64, 128, 1024, 3000)]
            out += [(f"int--2**{k}-1", -(2 ** k) - 1) for k in (64, 1024)]
            out += [(f"int-rand-{i}", rnd.randrange(10 ** 6, 10 ** 12)) for i in range(4)]
        if not ann or head in ("list", "List", "Sequence"):
            out += [(f"list-len-{n}", [1] * n) for n in (5000, 70000)]  # non-zero: a truncation must show
        return out

    def background(arg):
        ann = ast.unparse(arg.annotation).replace(" ", "") if arg.annotation is not None else ""
        return 1 if ann == "int" else [] if ann.split("[")[0] in ("list", "List", "Sequence") else "a"

    bg = [background(a) for a in required]
    per = [fam(a) for a in required]
    rows: list[dict] = []
    for k in range(max((len(f) for f in per), default=0)):  # interleave parameters so a cap keeps them all
        for i, f in enumerate(per):
            if k < len(f):
                origin, v = f[k]
                args = list(bg)
                args[i] = v
                rows.append({"args": args, "kwargs": {}, "origin": f"{required[i].arg}:{origin}"})
    return rows[:limit]


def _iter_py_regular(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in (".git", ".hlith", "__pycache__", ".venv", "venv"))
        for name in sorted(files):
            if name.endswith(".py"):
                out.append(Path(dirpath) / name)
    return out


def _read_regular_text(path: Path, *, limit: int) -> str | None:
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_size > limit:
            return None
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit + 1)[:limit]
    except OSError:
        return None


_LONG_LIST_LEN = 5000  # > the engine's generated-list cap (differential: 4096 elements); one length keeps records bounded
_LONG_LIST_MAX = 4     # variants per probe


def long_list_variants(rows: Sequence[dict]) -> list[dict]:
    """Long lists of the repository's OWN element shapes (review case, route P on requests): for each harvested call-site input
    whose positional argument is a non-empty list, the same input with that list repeated cyclically to _LONG_LIST_LEN elements.
    ``[1]*n`` alone never reaches the length blind spot of a function that validates its elements (pairs, strings, objects): both
    sides reject the ints. Deterministic (input order), bounded (_LONG_LIST_MAX), and typed only by what the repository wrote."""
    out: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        for pos, a in enumerate(r.get("args") or []):
            if len(out) >= _LONG_LIST_MAX:
                return out
            if not isinstance(a, (list, tuple)) or not a or len(a) >= _LONG_LIST_LEN:
                continue
            elems = json.loads(json.dumps(list(a)))  # tuples -> lists, exactly as the input transport carries them
            longer = [elems[i % len(elems)] for i in range(_LONG_LIST_LEN)]
            new = {"args": [*r["args"][:pos], longer, *r["args"][pos + 1:]], "kwargs": dict(r.get("kwargs") or {}),
                   "origin": f"long-list-{_LONG_LIST_LEN}:{r.get('origin', '')}"[:240]}
            key = _canon(new)
            if key not in seen:
                seen.add(key)
                out.append(new)
    return out


def _attr_chain(node) -> str | None:
    """Dotted identifier chain for ``a.b.c`` AST expressions, or None for non-attribute expressions."""
    import ast

    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _file_call_matchers(tree, function: str, module: str) -> tuple[set[str], set[str] | None]:
    """Return ``(bare_names, qual_prefixes)`` that legitimately refer to ``function`` inside ``tree``.

    ``qual_prefixes is None`` for methods (any receiver attribute ``obj.method`` may call the target).
    For top-level functions (``'.' not in function``), attribute calls only match imported module prefixes
    so unrelated receiver methods like ``os.environ.get`` or ``dict.get`` are never harvested as calls to
    a module-level function named ``get``.
    """
    import ast

    name = function.split(".")[-1]
    if "." in function:
        return set(), None
    bare_names = {name}
    qual_prefixes: set[str] = set()
    mod_parts = module.split(".") if module else []
    mod_tail = mod_parts[-1] if mod_parts else ""
    mod_parent = ".".join(mod_parts[:-1]) if len(mod_parts) > 1 else ""
    if module:
        qual_prefixes.add(module)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name
                if not module:
                    qual_prefixes.add(bound)
                    if alias.asname is None:
                        qual_prefixes.add(alias.name.split(".")[0])
                elif alias.name == module:
                    qual_prefixes.add(bound)
                elif mod_parts and alias.name == mod_parts[0] and alias.asname is None:
                    qual_prefixes.add(module)
        elif isinstance(node, ast.ImportFrom):
            src_mod = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                if not module:
                    if alias.name == name:
                        bare_names.add(bound)
                    else:
                        qual_prefixes.add(bound)
                else:
                    if src_mod == module or (node.level and (src_mod == mod_tail or src_mod == "")):
                        if alias.name == name:
                            bare_names.add(bound)
                    if mod_tail and alias.name == mod_tail and (
                        src_mod == mod_parent
                        or (node.level and (src_mod == "" or mod_parent.endswith(src_mod)))
                    ):
                        qual_prefixes.add(bound)
    return bare_names, qual_prefixes


def harvested_call_seeds(tree_root: str | Path, function: str, *, limit: int = 32, module: str = "") -> list[dict]:
    """Literal arguments of the repository's own uses of ``function``, by AST after landing: production-shaped inputs, deterministic
    order (path, line). Three sources, all the repository's own text:
    - call sites with literal arguments (callers and tests), origin ``call-site:``;
    - doctest examples ``>>> function(...)`` in any string constant (docstrings), origin ``doctest:`` (review case);
    - pytest ``parametrize`` rows of a test whose body calls ``function`` with the parametrized names, origin ``parametrize:``.
    Computed arguments (non-literal values, non-literal rows) are skipped, never evaluated."""
    import ast

    from .. import textsafe as _ts

    root = Path(tree_root)
    resolved_mod = module
    resolved_fn = function
    if not resolved_mod and "." in function:
        sp = split_symbol(root, function)
        if sp is not None:
            resolved_mod, resolved_fn = sp
    name = resolved_fn.split(".")[-1]
    out: list[dict] = []

    def _callee(n) -> str | None:
        return n.func.id if isinstance(n.func, ast.Name) else n.func.attr if isinstance(n.func, ast.Attribute) else None

    def _matches_target_call(n, bare_names: set[str], qual_prefixes: set[str] | None) -> bool:
        if isinstance(n.func, ast.Name):
            return qual_prefixes is not None and n.func.id in bare_names
        if isinstance(n.func, ast.Attribute) and n.func.attr == name:
            if qual_prefixes is None:
                return True
            chain = _attr_chain(n.func.value)
            return chain is not None and chain in qual_prefixes
        return False

    def _accept(args: list, kwargs: dict, origin: str) -> bool:
        """Keep a literal input if it is small, printable as it is and JSON-safe; True when the limit is reached."""
        if not all(_printable_literal(v, _ts) for v in [*args, *kwargs.values()]):
            return False
        try:
            _json_safe({"args": args, "kwargs": kwargs}, "input")
        except ValueError:
            return False
        out.append({"args": args, "kwargs": kwargs, "origin": _ts.clean(origin)[:200]})
        return len(out) >= limit

    def _literal_call(c) -> tuple[list, dict] | None:
        if any(isinstance(a, ast.Starred) for a in c.args) or any(k.arg is None for k in c.keywords):
            return None
        try:
            return [ast.literal_eval(a) for a in c.args], {k.arg: ast.literal_eval(k.value) for k in c.keywords}
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            return None

    _LIT_ERR = (ValueError, SyntaxError, TypeError, MemoryError, RecursionError)
    # review audit: the walk is host-side and the tree is hostile: regular files only (lstat, no symlinks, no FIFOs or
    # devices: O_NONBLOCK|O_NOFOLLOW + fstat), bounded size, and only literals that are printable as they are
    for f in _iter_py_regular(root):
        if any(part in (".git", ".hlith", "__pycache__", ".venv", "venv") for part in f.relative_to(root).parts):
            continue
        text = _read_regular_text(f, limit=_HARVEST_FILE_MAX)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
        except _LIT_ERR:
            continue
        bare_names, qual_prefixes = _file_call_matchers(tree, resolved_fn, resolved_mod)
        rel = f.relative_to(root)
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _matches_target_call(n, bare_names, qual_prefixes):
                lit = _literal_call(n)
                if lit is not None and _accept(lit[0], lit[1], f"call-site:{rel}:{n.lineno}"):
                    return out
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and f">>> {name}(" in n.value:
                for line in n.value.splitlines():
                    src = line.strip()
                    if not src.startswith(f">>> {name}("):
                        continue
                    try:
                        expr = ast.parse(src[4:], mode="eval").body
                    except _LIT_ERR:
                        continue
                    lit = _literal_call(expr) if isinstance(expr, ast.Call) and _callee(expr) == name else None
                    if lit is not None and _accept(lit[0], lit[1], f"doctest:{rel}:{n.lineno}"):
                        return out
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = [c for c in ast.walk(n) if isinstance(c, ast.Call) and _matches_target_call(c, bare_names, qual_prefixes)
                         and not c.keywords and not any(isinstance(a, ast.Starred) for a in c.args)]
                if not calls:
                    continue
                for dec in n.decorator_list:
                    if not (isinstance(dec, ast.Call) and _callee(dec) == "parametrize" and len(dec.args) >= 2):
                        continue
                    try:
                        names = ast.literal_eval(dec.args[0])
                        rows = ast.literal_eval(dec.args[1])
                    except _LIT_ERR:
                        continue  # computed argnames or rows: skipped, never evaluated
                    names = [x.strip() for x in names.split(",")] if isinstance(names, str) else list(names)
                    if not isinstance(rows, (list, tuple)):
                        continue
                    for c in calls:
                        for row in rows:
                            vals = dict(zip(names, row if len(names) > 1 and isinstance(row, (list, tuple)) else [row]))
                            args = []
                            for a in c.args:
                                if isinstance(a, ast.Name) and a.id in vals:
                                    args.append(vals[a.id])
                                else:
                                    try:
                                        args.append(ast.literal_eval(a))
                                    except _LIT_ERR:
                                        args = None
                                        break
                            if args is not None and _accept(args, {}, f"parametrize:{rel}:{dec.lineno}"):
                                return out
    return out


def _printable_literal(v: Any, ts: Any, depth: int = 0) -> bool:
    """A harvested literal is kept only if it is small and its text needs no escaping to display safely."""
    if depth > 3 or len(repr(v)) > _HARVEST_LIT_MAX:
        return False
    if isinstance(v, str):
        return ts.clean(v) == v
    if isinstance(v, (list, tuple)):
        return all(_printable_literal(x, ts, depth + 1) for x in v)
    if isinstance(v, dict):
        return all(_printable_literal(k, ts, depth + 1) and _printable_literal(x, ts, depth + 1) for k, x in v.items())
    return isinstance(v, (int, float, bool, type(None), bytes))


def extended_probe(source_run_id: str, base_root: str | Path, landed_root: str | Path, module: str, function: str,
                   *, seed: int, tree_root: str | Path, limit: int = 3, deadline: float | None = None,
                   call_timeout: float = _EXT_CALL_TIMEOUT, agreeing: list | None = None, **observe_kw: Any) -> tuple[tuple, dict]:
    """Run the extended families and the harvested call-site inputs against landed^ and landed; one pin per
    CONFIRMED divergence (at most ``limit``). Confirmed = each side observed TWICE with the same outcome (a value
    that differs between two runs of the same code is not behaviour), neither side timed out, and the two sides
    differ. ``deadline`` (time.monotonic) bounds the whole probe; it is checked before each chunk of inputs.
    ``agreeing`` (optional list, review case): receives every probed input on which both sides returned the SAME non-timeout
    outcome (one observation each side); the caller decides what to keep. Returns (records, stats)."""
    import time as _t

    t0 = _t.monotonic()
    deadline = t0 + EXT_BUDGET_S if deadline is None else deadline
    stats = {"inputs": 0, "seconds": 0.0, "seed": seed, "family": EXT_PROBE_FAMILY, "budget_s": EXT_BUDGET_S}
    if _t.monotonic() >= deadline:
        return (), {**stats, "skipped": "wall budget exhausted"}
    harvested = harvested_call_seeds(tree_root, function, module=module)
    rows = extended_seeds(base_root, module, function, seed=seed) + harvested + long_list_variants(harvested)
    seen: set[str] = set()
    inputs, origins = [], []
    adm = annotation_admission(base_root, module, function)  # the gate's declared domain (design review 2026-11-21), same rule
    for r in rows:
        i = _inp(r)
        if adm is not None and not adm(i):
            stats["annotation_excluded"] = stats.get("annotation_excluded", 0) + 1
            continue
        if _canon(i) not in seen:
            seen.add(_canon(i))
            inputs.append(i)
            origins.append(r["origin"])
    symbol = f"{module}.{function}"
    recs: list = []
    okw = dict(observe_kw, call_timeout=call_timeout)
    done = 0
    for k in range(0, len(inputs), _EXT_CHUNK):
        if _t.monotonic() >= deadline or len(recs) >= limit:
            stats["skipped"] = "wall budget exhausted" if _t.monotonic() >= deadline else ""
            break
        chunk, chunk_o = inputs[k:k + _EXT_CHUNK], origins[k:k + _EXT_CHUNK]
        b1 = observe(base_root, module, function, chunk, **okw).outcomes
        l1 = observe(landed_root, module, function, chunk, **okw).outcomes
        done += len(chunk)
        # design review 15:14 resource rule: an input at the memory limit on either side is UNEXPLORED, named, never agreement or a witness
        stats["resource_limited"] = stats.get("resource_limited", 0) + sum(
            1 for ob, op in zip(b1, l1) if resource_limited(ob) or resource_limited(op))
        cand = [j for j, (ob, op) in enumerate(zip(b1, l1))
                if ob.get("kind") != "timeout" and op.get("kind") != "timeout" and _diverges(ob, op, widen=True)]
        if agreeing is not None:
            agreeing.extend(chunk[j] for j, (ob, op) in enumerate(zip(b1, l1))
                            if j not in cand and ob.get("kind") != "timeout" and not resource_limited(ob) and ob == op)
        if not cand:
            continue
        again = [chunk[j] for j in cand]  # determinism re-run: only the diverging inputs, both sides
        b2 = observe(base_root, module, function, again, **okw).outcomes
        l2 = observe(landed_root, module, function, again, **okw).outcomes
        for j, ob2, op2 in zip(cand, b2, l2):
            ob, op = b1[j], l1[j]
            if ob != ob2 or op != op2 or "timeout" in (ob2.get("kind"), op2.get("kind")):
                continue
            inp = chunk[j]
            r0 = pin_regression_counterexample(source_run_id, symbol, inp["args"], inp["kwargs"],
                                               expected=ob, observed=op, env=inp.get("env"))
            recs.append(FeedbackRecord(r0.source_run_id, r0.target_symbols, r0.directive_kind,
                                       {**r0.directive_payload,
                                        "probe": {"family": EXT_PROBE_FAMILY, "seed": seed, "origin": chunk_o[j],
                                                  "budget_s": EXT_BUDGET_S}}))
            if len(recs) >= limit:
                break
    stats.update(inputs=done, seconds=round(_t.monotonic() - t0, 3))
    return tuple(recs), stats


_STUB_TYPE_HEADS = frozenset({"str", "int", "float", "bool", "bytes", "bytearray", "complex", "list", "tuple", "dict", "set",
                              "frozenset", "None", "NoneType"})


def annotation_admission(src_root: str | Path, module: str, function: str):
    """The GATE's declared input domain for the target, as a predicate over probe inputs ({"args", "kwargs"}).

    design review 2026-11-21 (release blocker, 2aae27e4): the differential gate only compares annotation-admitted values
    (differential._ann_admits), while Layer 5 probed every seed. A rehearsal therefore LANDED 4/4 held and its own post-landing probe
    pinned is_test_path(0) (an int for a `str` parameter: TypeError vs AttributeError), and that pin REFUSED the identical change at
    confirm. L5 now draws only from the same domain, by the SAME rule (imported, not copied):
    - an annotated parameter admits exactly what _ann_admits admits;
    - an unannotated parameter, *args/**kwargs and unknown keywords admit everything (unchanged);
    - a stub object ({"$obj": ...}) stands for an instance of a class, so it is admitted iff the annotation names a non-builtin head.
    An in-annotation divergence is unaffected: it is still pinned and still refuses. Returns None when there is no readable signature
    (nothing is filtered)."""
    import ast
    from ..obligation.api import ann_admits as _ann_admits

    try:
        node, pos = _target_params(src_root, module, function)
    except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    if node is None:
        return None
    ann_of = lambda a: ast.unparse(a.annotation) if a.annotation is not None else None  # noqa: E731
    pos_anns = [ann_of(a) for a in pos]
    kw_anns = {a.arg: ann_of(a) for a in list(pos) + list(node.args.kwonlyargs)}

    def ok(ann, v) -> bool:
        if ann is None:
            return True
        if isinstance(v, dict) and set(v) == {"$obj"}:
            heads = {p.split(".")[-1] for p in re.split(r"[|,\[\]]", ann.replace(" ", "").replace("Optional[", "None|")) if p}
            return _ann_admits(ann, object()) or bool(heads - _STUB_TYPE_HEADS - {"Optional"})
        return _ann_admits(ann, v)

    def admits(inp: dict) -> bool:
        args = inp.get("args") or []
        for i, v in enumerate(args):
            if i < len(pos_anns) and not ok(pos_anns[i], v):
                return False
        for k, v in (inp.get("kwargs") or {}).items():
            if not ok(kw_anns.get(k), v):
                return False
        return True

    return admits


def admitted_inputs(src_root: str | Path, module: str, function: str, inputs: Sequence[dict]) -> tuple[list[dict], int]:
    """(inputs inside the gate's declared domain, number excluded). See annotation_admission."""
    adm = annotation_admission(src_root, module, function)
    if adm is None:
        return list(inputs), 0
    kept = [i for i in inputs if adm(i)]
    return kept, len(inputs) - len(kept)


_GENERIC_PARAM_NAMES = frozenset({
    "self", "cls", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "arg", "args", "kw", "kwargs", "val", "vals", "value", "values", "obj", "objs",
    "item", "items", "data", "input", "inputs", "output", "out", "res", "result",
    "ret", "other", "default", "flag", "mode", "opt", "opts", "options",
})


def _param_background(arg) -> Any:
    import ast

    ann = ast.unparse(arg.annotation).replace(" ", "") if arg.annotation is not None else ""
    head = ann.split("[")[0].split("|")[0].split(".")[-1]
    if head == "int":
        return 1
    if head == "bool":
        return False
    if head == "float":
        return 1.0
    if head in ("list", "List", "Sequence", "tuple", "Tuple"):
        return []
    if head in ("dict", "Dict", "Mapping"):
        return {}
    return "a"


def _bind_input_to_params(inp: dict, pos_names: Sequence[str]) -> dict[str, Any]:
    bound: dict[str, Any] = {}
    args = list(inp.get("args") or ())
    kwargs = dict(inp.get("kwargs") or {})
    for pname, val in zip(pos_names, args):
        bound[pname] = val
    for k, val in kwargs.items():
        if isinstance(k, str):
            bound[k] = val
    return bound


def cone_domain_seeds_for_targets(
    stored_records: Sequence[Any],
    target_symbols: Sequence[str],
    base_root: str | Path,
    *,
    callee_edges: Sequence[Any] = (),
    limit_per_target: int = 16,
) -> tuple[tuple[Any, ...], tuple[tuple[str, dict, str], ...]]:
    """Derive pure domain seeds (expected=None, fresh base vs post only) for ``target_symbols`` from
    stored concrete inputs of related symbols in the call cone or same module that share a non-generic
    semantic parameter name (e.g. ``url``, ``headers``, ``proxies``).

    Returns ``(donor_items, extra_seeds)`` where ``extra_seeds`` are ``(target_symbol, input_dict, feedback_id)``
    triples and ``donor_items`` are the contributing ``StoredRecord`` entries (deduplicated, deterministic).
    Never transfers recorded expectations, never transfers constructs, and filters every transferred input
    through ``annotation_admission`` so out-of-domain values are never injected.
    """
    from ..contract.codec import decode_call_values

    root = Path(base_root)
    targets = tuple(sorted({s for s in target_symbols if isinstance(s, str) and "." in s}))
    if not targets or not stored_records:
        return (), ()

    related_by_edge: dict[str, set[str]] = {}
    for edge in callee_edges or ():
        caller = getattr(edge, "caller", None) if not isinstance(edge, dict) else edge.get("caller") or edge.get("caller_qualified_name")
        callee = getattr(edge, "callee", None) if not isinstance(edge, dict) else edge.get("callee") or edge.get("callee_qualified_name")
        if isinstance(caller, str) and isinstance(callee, str) and caller and callee and caller != callee:
            related_by_edge.setdefault(caller, set()).add(callee)
            related_by_edge.setdefault(callee, set()).add(caller)

    sig_cache: dict[str, tuple[str, str, Any, list, Any] | None] = {}

    def _sig_of(sym: str):
        if sym in sig_cache:
            return sig_cache[sym]
        sp = split_symbol(root, sym)
        if sp is None:
            sig_cache[sym] = None
            return None
        mod, fn = sp
        ir = import_root_of(root, mod)
        if ir is None:
            sig_cache[sym] = None
            return None
        try:
            node, pos = _target_params(ir, mod, fn)
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            sig_cache[sym] = None
            return None
        if node is None:
            sig_cache[sym] = None
            return None
        adm = annotation_admission(ir, mod, fn)
        sig_cache[sym] = (mod, fn, node, pos, adm)
        return sig_cache[sym]

    # Collect existing direct inputs per target so we never emit duplicate seeds or unnecessary donor refs.
    direct_keys: dict[str, set[str]] = {t: set() for t in targets}
    for item in stored_records:
        rec = item.record
        if rec.directive_kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE or rec.directive_kind is DirectiveKind.ORACLE_REGRESSION:
            raw_inps = [rec.directive_payload["input"]]
        elif rec.directive_kind is DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT:
            raw_inps = list(rec.directive_payload["pinned_inputs"])
        else:
            continue
        for sym in rec.target_symbols:
            if sym in direct_keys:
                for raw_inp in raw_inps:
                    direct_keys[sym].add(_canon(_inp(raw_inp)))

    extra_seeds: list[tuple[str, dict, str]] = []
    used_donor_ids: set[str] = set()
    by_id: dict[str, Any] = {}

    for tgt in targets:
        tsig = _sig_of(tgt)
        if tsig is None:
            continue
        tmod, _tfn, tnode, tpos, tadm = tsig
        n_req = len(tpos) - len(tnode.args.defaults) if tnode.args.defaults else len(tpos)
        tpos_names = [a.arg for a in tpos]
        tkw_names = {a.arg for a in tnode.args.kwonlyargs}
        t_semantic = {
            nm for nm in (*tpos_names, *tkw_names)
            if len(nm) >= 2 and nm not in _GENERIC_PARAM_NAMES
        }
        if not t_semantic:
            continue
        posonly = {a.arg for a in tnode.args.posonlyargs}
        required_kwargs = {
            a.arg: _param_background(a)
            for a, default in zip(tnode.args.kwonlyargs, tnode.args.kw_defaults)
            if default is None
        }
        seen_tgt = set(direct_keys[tgt])
        added_tgt = 0

        for item in sorted(stored_records, key=lambda s: s.record.feedback_id):
            if added_tgt >= limit_per_target:
                break
            rec = item.record
            if rec.directive_kind in (DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE, DirectiveKind.ORACLE_REGRESSION):
                raw_inps = [rec.directive_payload["input"]]
            elif rec.directive_kind is DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT:
                raw_inps = list(rec.directive_payload["pinned_inputs"])
            else:
                continue
            for src_sym in rec.target_symbols:
                if src_sym == tgt or added_tgt >= limit_per_target:
                    continue
                ssig = _sig_of(src_sym)
                if ssig is None:
                    continue
                smod, _sfn, _snode, spos, _sadm = ssig
                if smod != tmod and src_sym not in related_by_edge.get(tgt, ()):
                    continue
                spos_names = [a.arg for a in spos]
                for raw_inp in raw_inps:
                    if added_tgt >= limit_per_target:
                        break
                    if raw_inp.get("env"):
                        continue
                    bound = _bind_input_to_params(raw_inp, spos_names)
                    matched = {
                        nm: val for nm, val in bound.items()
                        if nm in t_semantic and _pin_data(val)
                    }
                    if not matched:
                        continue
                    # Build a well-formed call for tgt using matched semantic arguments + neutral required defaults.
                    positional_count = max([n_req, *(i + 1 for i, nm in enumerate(tpos_names)
                                                       if nm in posonly and nm in matched)])
                    call_args = [
                        matched[a.arg] if a.arg in matched else _param_background(a)
                        for a in tpos[:positional_count]
                    ]
                    call_kwargs = {**required_kwargs, **{
                        nm: val for nm, val in matched.items() if nm not in tpos_names[:positional_count]
                    }}
                    cand = {"args": call_args, "kwargs": call_kwargs}
                    try:
                        _json_safe(cand, "input")
                    except ValueError:
                        continue
                    if tadm is not None:
                        decoded = {
                            "args": decode_call_values(call_args),
                            "kwargs": decode_call_values(call_kwargs),
                        }
                        if not tadm(decoded):
                            continue
                    key = _canon(cand)
                    if key in seen_tgt:
                        continue
                    seen_tgt.add(key)
                    extra_seeds.append((tgt, cand, rec.feedback_id))
                    used_donor_ids.add(rec.feedback_id)
                    by_id[rec.feedback_id] = item
                    added_tgt += 1

    donors = tuple(by_id[fid] for fid in sorted(used_donor_ids))
    return donors, tuple(extra_seeds)


def post_gate_probe(
    source_run_id: str,
    base_root: str | Path,
    landed_root: str | Path,
    module: str,
    function: str,
    seed_inputs: Sequence[dict],
    *,
    limit: int = 3,
    excluded_out: list | None = None,
    provenance_origin_kind: str = "post-gate-probe",
    provenance_observed_in_run: str = "refuted",
    **observe_kw: Any,
) -> tuple[FeedbackRecord, ...]:
    """Run boundary variants of the inputs a check already used against base and landed code.

    Returns one ``pin_regression_counterexample`` per diverging input (at most
    ``limit``, in deterministic order). An empty result means no variant
    diverged. It does not mean the landed change is correct. Only inputs inside the gate's declared domain are run
    (annotation_admission); the number excluded is appended to ``excluded_out`` when given.
    """
    seeds = [_inp(i) for i in seed_inputs]
    seen: set[str] = set()
    variants = []
    for v in seeds + _variants_of(seeds):  # the seeds themselves, then their boundary variants
        if _canon(v) not in seen:
            seen.add(_canon(v))
            variants.append(v)
    variants, n_ex = admitted_inputs(base_root, module, function, variants)
    if excluded_out is not None and n_ex:
        excluded_out.append(n_ex)
    if not variants:
        return ()
    b = observe(base_root, module, function, variants, **observe_kw)
    p = observe(landed_root, module, function, variants, **observe_kw)
    symbol = f"{module}.{function}"
    recs = []
    for inp, ob, op in zip(variants, b.outcomes, p.outcomes):
        if _diverges(ob, op, widen=True):
            recs.append(with_provenance(
                pin_regression_counterexample(source_run_id, symbol, inp["args"], inp["kwargs"],
                                              expected=ob, observed=op, env=inp.get("env")),
                origin_kind=provenance_origin_kind, observed_in_run=provenance_observed_in_run))
            if len(recs) >= limit:
                break
    return tuple(recs)


def pin_observed(
    source_run_id: str,
    base_root: str | Path,
    landed_root: str | Path,
    module: str,
    function: str,
    observed_inputs: Sequence[dict],
    **observe_kw: Any,
) -> tuple[tuple[FeedbackRecord, ...], tuple[dict, ...]]:
    """Turn inputs observed after landing (a caller trace, a failing request) into pins.

    The report is never trusted. Each input is re-executed under confinement on base
    and landed code, and only confirmed divergences become
    ``pin_regression_counterexample`` records. Returns ``(records, rejected_inputs)``.
    """
    inputs = [_inp(i) for i in observed_inputs]
    if not inputs:
        return (), ()
    b = observe(base_root, module, function, inputs, **observe_kw)
    p = observe(landed_root, module, function, inputs, **observe_kw)
    symbol = f"{module}.{function}"
    recs, rejected = [], []
    for inp, ob, op in zip(inputs, b.outcomes, p.outcomes):
        if _diverges(ob, op, widen=True):
            recs.append(with_provenance(
                pin_regression_counterexample(source_run_id, symbol, inp["args"], inp["kwargs"],
                                              expected=ob, observed=op, env=inp.get("env")),
                origin_kind="post-gate-probe", observed_in_run="refuted"))
        else:
            rejected.append(inp)
    return tuple(recs), tuple(rejected)


def pin_oracle(
    source_run_id: str,
    landed_root: str | Path,
    module: str,
    function: str,
    cases: Sequence[tuple[dict, Any]],
    **observe_kw: Any,
) -> tuple[tuple[FeedbackRecord, ...], tuple[dict, ...]]:
    """Pins from an external oracle, e.g. the input/expected-value pairs of a later upstream fix's test.

    Each input is executed confined on the landed code. Where the landed outcome differs from the
    oracle's expected return value, a pin records ``expected = return repr(oracle)``. Inputs the
    landed code already satisfies are returned as satisfied, never pinned (an oracle that agrees with
    the landed behaviour is not a counterexample)."""
    inputs = [_inp(i) for i, _ in cases]
    if not inputs:
        return (), ()
    obs = observe(landed_root, module, function, inputs, **observe_kw)
    symbol = f"{module}.{function}"
    recs, satisfied = [], []
    for inp, (_, want), got in zip(inputs, cases, obs.outcomes):
        exp = {"kind": "return", "repr": repr(want)}
        if _matches(exp, got):
            satisfied.append(inp)
        else:
            recs.append(with_provenance(
                pin_regression_counterexample(source_run_id, symbol, inp["args"], inp["kwargs"],
                                              expected=exp, observed=got, env=inp.get("env")),
                origin_kind="external-pin", observed_in_run="external"))
    return tuple(recs), tuple(satisfied)


def _fmt_call(function: str, inp: dict) -> str:
    parts = [repr(a) for a in inp["args"]] + [f"{k}={v!r}" for k, v in sorted(inp["kwargs"].items())]
    return f"{function}({', '.join(parts)})"


def probe_obligation(
    obligation_id: str,
    base_root: str | Path,
    post_root: str | Path,
    module: str,
    function: str,
    sampled_inputs: Sequence[dict],
    constraints: DifferentialConstraints | None,
    **observe_kw: Any,
) -> Obligation:
    """Differential obligation over pinned inputs (first) then sampled inputs, base vs post.

    A pin that carries a base outcome is also checked against that outcome, so it
    still bites when the current base already contains the regression.
    """
    pinned = [_call_input(p.args, p.kwargs, p.env) for p in (constraints.pinned_inputs if constraints else ())]
    expected = [p.expected for p in (constraints.pinned_inputs if constraints else ())]
    sampled = [_inp(i) for i in sampled_inputs]
    inputs = pinned + sampled
    widen = bool(constraints and constraints.disallow_exception_widening)
    symbol = f"{module}.{function}"
    claim = f"{symbol} keeps base behaviour on every checked input"
    if not inputs:
        return Obligation(obligation_id, symbol, claim, Verdict.NOT_DERIVED, stop_reason="no inputs to execute")
    try:
        b = observe(base_root, module, function, inputs, **observe_kw)
        p = observe(post_root, module, function, inputs, **observe_kw)
    except Exception as e:  # a refused grant (special file) or a failed probe is never a pass
        return Obligation(obligation_id, symbol, claim, Verdict.UNVERIFIED,
                          stop_reason=f"probe not run: {type(e).__name__}: {e}"[:400])
    # if either confined run could read a proposer path, that leak is what gets recorded
    prov = b.provenance if b.provenance.proposer_paths_readable else p.provenance
    for i, (inp, ob, op) in enumerate(zip(inputs, b.outcomes, p.outcomes)):
        exp = expected[i] if i < len(expected) else None
        if exp is not None and not _matches(exp, op):
            src = ",".join(constraints.source_feedback_ids) if constraints else ""
            return Obligation(obligation_id, symbol, claim, Verdict.REFUTED,
                              witness=f"{_fmt_call(function, inp)}: pinned {exp} (feedback {src}), post {op}",
                              provenance=prov)
        if _diverges(ob, op, widen):
            return Obligation(obligation_id, symbol, claim, Verdict.REFUTED,
                              witness=f"{_fmt_call(function, inp)}: base {ob}, post {op}", provenance=prov)
    for side, o in (("base", b), ("post", p)):
        if o.stopped or len(o.outcomes) < len(inputs):  # a refutation above wins; otherwise the remainder is unexplored, not covered
            st = o.stopped or {}
            return Obligation(obligation_id, symbol, claim, Verdict.UNVERIFIED, provenance=prov,
                              stop_reason=(f"{st.get('reason', 'probe stopped early')}: {side} stopped after {len(o.outcomes)} of {len(inputs)} inputs "
                                           f"({st.get('consecutive_timeouts', '?')} consecutive timeouts); {len(inputs) - len(o.outcomes)} inputs not executed"))
    ids = ",".join(constraints.source_feedback_ids) if constraints else "none"
    ev = BoundedEvidence(
        len(inputs) * 2,
        f"{len(pinned)} pinned + {len(sampled)} sampled inputs to {symbol}, base vs post; feedback ids: {ids}",
        f"every other input to {symbol}; callers of {symbol}; stateful call sequences",
    )
    return Obligation(obligation_id, symbol, claim, Verdict.HELD, evidence=ev, provenance=prov)


# ---- per-turn full re-run against turn 0 ------------------------------------------------------
#
# A multi-turn agent session lands a series of changes. Checking turn n only against
# turn n-1 misses iterative degradation: a regression that slipped past an earlier
# bounded check stays in the tree and is never looked at again. Each turn therefore
# re-runs the FULL obligation set against the session's turn-0 tree: every symbol
# touched in any turn so far, plus every symbol a loaded record targets. Records
# only add pins, never remove them.

TURNS_SUBDIR = Path(".hlith") / "turns"
_SESSION_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class TurnResult:
    turn: int
    commit: str | None  # landed commit, None if refused
    touched: tuple[str, ...]
    verdicts: dict  # symbol -> verdict value


@dataclass
class TurnLedger:
    repo: str
    session_id: str
    turn0_commit: str
    turns: list[TurnResult] = field(default_factory=list)

    @property
    def path(self) -> Path:
        return Path(self.repo) / TURNS_SUBDIR / f"{self.session_id}.json"

    @classmethod
    def start(cls, repo: Path, session_id: str) -> "TurnLedger":
        if not _SESSION_RE.match(session_id):
            raise ValueError(f"bad session id {session_id!r}")
        led = cls(str(Path(repo).resolve()), session_id, _git(Path(repo), "rev-parse", "HEAD").strip())
        if led.path.exists():
            raise FeedbackWriteRefused(f"session {session_id} already exists")
        led._save()
        return led

    @classmethod
    def load(cls, repo: Path, session_id: str) -> "TurnLedger":
        p = Path(repo).resolve() / TURNS_SUBDIR / f"{session_id}.json"
        d = json.loads(p.read_text())
        return cls(d["repo"], d["session_id"], d["turn0_commit"],
                   [TurnResult(t["turn"], t["commit"], tuple(t["touched"]), dict(t["verdicts"])) for t in d["turns"]])

    def _save(self) -> None:
        repo = Path(self.repo)
        if _git(repo, "ls-files", "--", TURNS_SUBDIR.parts[0]).strip():
            raise FeedbackWriteRefused(".hlith/ has tracked files")
        _ensure_excluded(repo)
        d = repo
        for part in TURNS_SUBDIR.parts:
            d = d / part
            if d.is_symlink():
                raise FeedbackWriteRefused(f"{d} is a symlink")
            d.mkdir(mode=0o700, exist_ok=True)
        body = {"repo": self.repo, "session_id": self.session_id, "turn0_commit": self.turn0_commit,
                "turns": [{"turn": t.turn, "commit": t.commit, "touched": list(t.touched), "verdicts": t.verdicts}
                          for t in self.turns]}
        tmp = self.path.with_name(f".tmp-{self.session_id}-{os.getpid()}")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    def plan(self, touched_now: Iterable[str], records: Iterable[FeedbackRecord] = ()) -> tuple[str, ...]:
        """Every symbol that must be re-checked against turn 0 this turn."""
        syms = set(touched_now)
        for t in self.turns:
            syms |= set(t.touched)
        for r in records:
            if r.directive_kind is not DirectiveKind.MARK_CONSTRUCT_UNRESOLVABLE:
                syms |= set(r.target_symbols)
        return tuple(sorted(syms))

    def record(self, touched: Iterable[str], obligations: Sequence[Obligation], commit: str | None) -> TurnResult:
        res = TurnResult(len(self.turns) + 1, commit, tuple(sorted(set(touched))),
                         {o.target_symbol: o.verdict.value for o in obligations})
        self.turns.append(res)
        self._save()
        return res


def run_turn(
    ledger: TurnLedger,
    turn0_root: str | Path,
    post_root: str | Path,
    touched_now: Iterable[str],
    check: Any,
    *,
    records: Sequence[FeedbackRecord] = (),
    honours_env: bool = True,
) -> tuple[Obligation, ...]:
    """Check the whole plan, base = turn 0 tree, post = this turn's tree.

    ``check(symbol, base_root, post_root, constraints) -> Obligation`` is the
    differential (hlith.differential or probe_obligation). Unresolvable-construct
    records inside the plan add NOT_DERIVED obligations. The result is never empty.
    """
    plan = ledger.plan(touched_now, records)
    if not plan:
        raise ValueError("turn touches nothing and no record applies")
    obs = []
    for sym in plan:
        cons = constraints_for(records, sym)
        obs.append(check(sym, turn0_root, post_root, cons))
        if not honours_env and cons and any(p.env for p in cons.pinned_inputs):
            # a record the checker cannot apply must never pass silently (monotone tightening)
            obs.append(Obligation(f"feedback-env-unapplied:{sym}", sym, f"env-pinned inputs of {sym} were checked",
                                  Verdict.UNVERIFIED,
                                  stop_reason=f"checker cannot set the environment for pinned inputs "
                                              f"(feedback {','.join(cons.source_feedback_ids)})"))
    obs += list(not_derived_obligations(records, plan))
    return tuple(obs)


def report(ledgers: Iterable[TurnLedger]) -> dict:
    """Per repo, per session, per turn: verdict of every re-checked symbol."""
    out: dict = {}
    for led in ledgers:
        out.setdefault(led.repo, {})[led.session_id] = {
            "turn0": led.turn0_commit,
            "turns": [{"turn": t.turn, "landed": t.commit, "touched": list(t.touched), "verdicts": t.verdicts}
                      for t in led.turns],
        }
    return out


# ---- monotone tightening -------------------------------------------------------------------


def tightens(weaker: DifferentialConstraints | None, stronger: DifferentialConstraints | None) -> bool:
    """True iff ``stronger`` checks everything ``weaker`` checks (pins, expectations, widening)."""
    if weaker is None:
        return True
    if stronger is None:
        return False
    have: dict[tuple, set] = {}
    for p in stronger.pinned_inputs:
        have.setdefault((_canon(list(p.args)), _canon(p.kwargs), _canon(p.env)), set()).add(_canon(p.expected))
    for p in weaker.pinned_inputs:
        k = (_canon(list(p.args)), _canon(p.kwargs), _canon(p.env))
        if k not in have or (p.expected is not None and _canon(p.expected) not in have[k]):
            return False
    return stronger.disallow_exception_widening or not weaker.disallow_exception_widening


# ---- held-out generalisation of learned constructs ---------------------------------------------


def generalisation(stores: dict[str, Sequence[FeedbackRecord]], helped: dict[str, set[str]]) -> dict[str, dict]:
    """Status of each learned unresolvable construct kind across repositories.

    ``stores``: repo -> records loaded from that repo's store.
    ``helped``: construct_kind -> repos where applying the kind changed a verdict
    (a NOT_DERIVED that the run would otherwise not have had).
    A kind is ``generalising`` only after it helps on a repo other than one it was
    learned on. Otherwise it is ``repo-local``.
    """
    learned: dict[str, set[str]] = {}
    for repo, recs in stores.items():
        for u in unresolvable_for(recs):
            learned.setdefault(u.construct_kind, set()).add(repo)
    out = {}
    for kind, src in sorted(learned.items()):
        h = set(helped.get(kind, set()))
        out[kind] = {"learned_on": sorted(src), "helped_on": sorted(h),
                     "status": "generalising" if h - src else "repo-local"}
    return out


# ---- generic value pool for multi-parameter callables ---------------------------------------------

POOL: tuple = (None, 0, 1, "", "a", [], ["a"], {}, {"a": 1}, {"a": None}, {"a": 1, "b": None})


def tests_referencing(tests_root: str | Path, function: str, *, limit: int = 200) -> list[str]:
    """'<path relative to tests_root>::<test function>' for every test function whose body names ``function``
    (its last dotted part), by AST. This is the oracle a held verdict on ``function`` leans on."""
    import ast

    name = function.split(".")[-1]
    root = Path(tests_root)
    out: list[str] = []
    if not root.is_dir():
        return out
    for f in sorted(root.rglob("test*.py")):
        try:
            tree = ast.parse(f.read_text())
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test") and any(
                    (isinstance(x, ast.Name) and x.id == name) or (isinstance(x, ast.Attribute) and x.attr == name)
                    for x in ast.walk(n)):
                out.append(f"{f.relative_to(root).as_posix()}::{n.name}")
                if len(out) >= limit:
                    return out
    return out


def literals_from_tests(tests_root: str | Path, function: str, *, limit: int = 64) -> list[str]:
    """String constants (len > 3) in top-level test statements that reference ``function``, by AST."""
    import ast

    name = function.split(".")[-1]
    out: list[str] = []
    if not Path(tests_root).is_dir():
        return out
    for py in sorted(Path(tests_root).rglob("*.py")):
        try:
            tree = ast.parse(py.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue
        for top in tree.body:
            if isinstance(top, (ast.Import, ast.ImportFrom)):
                continue
            if not any(isinstance(n, ast.Name) and n.id == name or isinstance(n, ast.Attribute) and n.attr == name
                       for n in ast.walk(top)):
                continue
            for c in sorted((n for n in ast.walk(top) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                             and len(n.value) > 3), key=lambda n: (n.lineno, n.col_offset)):
                if c.value not in out and len(out) < limit:
                    out.append(c.value)
    return out


def pool_seeds(src_root: str | Path, module: str, function: str, *, max_params: int = 3,
               literals: Sequence[str] = (), max_calls: int = 4000) -> list[dict]:
    """Combinations over the required positional parameters of a small generic value pool plus
    ``literals`` (e.g. ``literals_from_tests``), at most ``max_calls``: literals are trimmed until the
    full product fits. Nothing about the target's domain is assumed."""
    import ast
    import itertools

    fdef, pos = _target_params(src_root, module, function)  # methods: receiver slot dropped
    if fdef is None:
        return []
    required = len(pos) - len(fdef.args.defaults)
    if pos and pos[0].arg in ("self", "cls"):
        return []
    if not 1 <= required <= max_params:
        return []
    lits = list(literals)
    while lits and (len(POOL) + len(lits)) ** required > max_calls:
        lits.pop()
    cands = list(POOL) + lits
    if len(cands) ** required > max_calls:
        return []
    return [{"args": list(c), "kwargs": {}} for c in itertools.product(cands, repeat=required)]


_STUB_BEHAVIOURS = ({"return": 0}, {"return": 7}, {"raise": "builtins.OSError"})


def stub_seeds(src_root: str | Path, module: str, function: str, *, max_names: int = 8) -> list[dict]:
    """Duck-typed stub objects for the first parameter, built from the attribute names the target
    itself uses on it (``p.name``, ``hasattr(p, "name")``, ``getattr(p, "name", ...)``): every single
    name and every pair, each with each simple behaviour. Derived from the target's code, not its domain."""
    import ast
    import itertools

    fdef, pos = _target_params(src_root, module, function)  # methods: receiver slot dropped
    if fdef is None or not pos:
        return []
    p = pos[0].arg
    if p in ("self", "cls"):
        return []
    names: list[str] = []
    for n in ast.walk(fdef):
        nm = None
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == p:
            nm = n.attr
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("hasattr", "getattr")
              and len(n.args) >= 2 and isinstance(n.args[0], ast.Name) and n.args[0].id == p
              and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)):
            nm = n.args[1].value
        if nm and nm not in names:
            names.append(nm)
    names = names[:max_names]
    out = []
    for k in (1, 2):
        for combo in itertools.combinations(names, k):
            for behs in itertools.product(_STUB_BEHAVIOURS, repeat=k):
                out.append({"args": [{"$obj": {"methods": dict(zip(combo, behs))}}], "kwargs": {}})
    return out


def _module_file(src_root: Path, module: str) -> Path | None:
    base = Path(src_root, *module.split("."))
    for cand in (base.with_suffix(".py"), base / "__init__.py"):
        if cand.is_file():
            return cand
    return None


def split_symbol(tree: str | Path, symbol: str) -> tuple[str, str] | None:
    """(module, function) with the module taken from the files in ``tree``, never from the last dot:
    'pkg.mod.Cls.meth' -> ('pkg.mod', 'Cls.meth'). The longest dotted prefix that is a module wins."""
    parts = symbol.split(".")
    for i in range(len(parts) - 1, 0, -1):
        module = ".".join(parts[:i])
        if import_root_of(tree, module) is not None:
            return module, ".".join(parts[i:])
    return None


def receiver_for(tree: str | Path, src_root: str | Path, module: str, function: str) -> tuple[dict | None, str]:
    """For a method target, use coordinator-injected receiver_recipe if registered."""
    if "." not in function:
        return None, ""
    recipe_fn = _PROBE_BRIDGE.get("receiver_recipe")
    if recipe_fn is None:
        return None, f"{module}.{function}: receiver_recipe bridge not registered"

    ir = os.path.relpath(Path(src_root), Path(tree))
    ctx, why = recipe_fn(str(tree), module, function, "" if ir == "." else ir)
    if ctx is None:
        if why == "not a method":
            return None, f"{module}.{function}: not a Class.method in the tree"
        return None, f"{module}.{function}: no receiver derivable ({why})"
    return {"cls": ctx["cls"], "cls_module": ctx.get("cls_module") or module, "kind": ctx["kind"],
            "ctor": ctx["ctor"], "ctor_alts": ctx.get("ctor_alts") or [ctx["ctor"]]}, ""


def _find_method_def(tree: Any, function: str) -> Any:
    import ast

    cls_name, meth_name = function.rsplit(".", 1)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == meth_name:
                    return item
    return None


def _target_params(src_root: str | Path, module: str, function: str):
    """(def node, positional params without the receiver slot) for a function or a Class.method."""
    import ast

    f = _module_file(Path(src_root), module)
    if f is None:
        return None, []
    tree = ast.parse(f.read_text())
    if "." in function:
        node = _find_method_def(tree, function)
    else:
        node = next((n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function), None)
    if node is None:
        return None, []
    pos = list(node.args.posonlyargs + node.args.args)
    if "." in function and pos and pos[0].arg in ("self", "cls"):
        decos = {getattr(d, "id", getattr(d, "attr", "")) for d in node.decorator_list}
        if "staticmethod" not in decos:
            pos = pos[1:]
    return node, pos


def import_root_of(tree: str | Path, module: str) -> Path | None:
    """The directory under ``tree`` from which ``module`` imports (tree itself, src/ or lib/)."""
    for sub in ("", "src", "lib"):
        root = Path(tree) / sub if sub else Path(tree)
        if _module_file(root, module):
            return root
    return None


# ---- pipeline wiring: before derive, after the gate ------------------------------------------------


def account_slice(account: dict) -> set[str]:
    """Symbols an effect account touches: modified callables and both ends of every impacted call site."""
    out = {c["qualified_name"] for c in account.get("modified_callables", ())}
    for s in account.get("impacted_call_sites", ()):
        out |= {s.get("caller_qualified_name"), s.get("callee_qualified_name")} - {None, ""}
    for a in account.get("added_callables", ()):  # review: new callables and the existing callers that reach them
        out.add(a.get("qualified_name"))
        out |= {r.get("caller_qualified_name") for r in a.get("reached_from", ())}
    # Hlith.md loading cone = callers AND callees (review df36a39): records about a callee of the change load too
    out |= {e.get("callee_qualified_name") for e in account.get("callee_edges", ())}
    out |= {c.get("callee_qualified_name") for c in account.get("callee_unresolved_constructs", ())}
    out.discard(None)
    out.discard("")
    return out


@dataclass(frozen=True)
class DeriveFeedback:
    """What Layer 3 receives from Layer 5 for one effect."""

    records: tuple[FeedbackRecord, ...]
    observe_kw: dict
    slice_symbols: frozenset = frozenset()
    constructs: tuple = ()  # the current account's unresolved constructs (with review's provenance)
    callee_constructs: tuple = ()  # review's callee_unresolved_constructs: evidence, never a gate obligation
    witnesses: list = field(default_factory=list)  # review's structured refuting calls seen during this derivation

    def note_witness(self, symbol: str, witness: dict | None) -> None:
        """Keep the differential's exact refuting call (read_witness) for Layer 5 after the gate."""
        if witness:
            self.witnesses.append({"symbol": symbol, **witness})

    @property
    def loaded_ids(self) -> tuple[str, ...]:
        return tuple(r.feedback_id for r in self.records)

    def constraints(self, symbol: str) -> DifferentialConstraints | None:
        return constraints_for(self.records, symbol)

    def recurrent_in_callee_cone(self) -> list[dict]:
        """design policy (non-blocking, visible): a not_derived_construct record whose construct is now reached only
        through the callee cone (same file + node digest, changed side). Reported, never an obligation: the
        account treats callee-cone constructs as evidence, and Layer 5 is not stricter than the design."""
        out = []
        for r in sorted(self.records, key=lambda r: r.feedback_id):
            if r.directive_kind is not DirectiveKind.NOT_DERIVED_CONSTRUCT:
                continue
            p = r.directive_payload
            for c in self.callee_constructs:
                prov = c.get("provenance") or {}
                if c.get("side") == "post" and prov.get("node_sha256") == p["node_sha256"] and\
                        (prov.get("source_file") or c.get("file_path")) == p["location"].rsplit(":", 1)[0]:
                    out.append({"fb_id": r.feedback_id,
                                "construct": {"kind": p["construct_kind"], "site": f"{c['file_path']}:{c['line_number']}"},
                                "callee": c["callee_qualified_name"], "via": list(c.get("path") or [])})
                    break
        return out

    def not_derived(self) -> tuple[Obligation, ...]:
        return not_derived_obligations(self.records, self.slice_symbols)

    def recurrent_constructs(self) -> list[dict]:
        """Non-blocking (design policy): constructs that already stopped earlier refused runs, with counts."""
        return recurrent_constructs(self.records, self.constructs)

    def supersede_pins(self, repo: str | Path, deltas: Sequence[dict], delta_set_sha256: str,
                       run_id: str) -> tuple["DeriveFeedback", list[dict]]:
        """design review F-A (Gate 1): with the delta set CONFIRMED (human approval of exactly this set), a loaded
        pin_regression_counterexample whose pinned input is covered by a declared delta (predicate matches and the
        pinned observed outcome equals the declared expected; delta_covers_pin, review's rule) is not applied in this
        run: the human authorised that behaviour change and the differential still verifies the delta on its own.
        Every other record (pins not covered, oracle_regression, domain constraints, not-derived) still applies.
        Nothing is deleted: the record stays, and one provenance line is appended beside it
        (<fb_id>.superseded.jsonl, ignored by load_records). Supersession is decided per run from the confirmed
        set, never read back, so a changed or unapproved delta set re-applies the pins."""
        repo = Path(repo)
        keep, out = [], []
        for r in self.records:
            hit = None
            if r.directive_kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE:
                sym = r.directive_payload["symbol"]
                split = split_symbol(repo, sym)
                root = import_root_of(repo, split[0]) if split else None
                names = _param_names(root, *split) if root is not None else []
                hit = next((d.get("id") for d in deltas if delta_covers_pin(d, r, names)), None)
            if hit is None:
                keep.append(r)
                continue
            out.append({"fb_id": r.feedback_id, "delta_id": hit, "delta_set_sha256": delta_set_sha256})
        for s in out:
            _append_supersession(repo, s["fb_id"], {"superseded_by_delta": s["delta_id"],
                                                    "delta_set_sha256": delta_set_sha256, "run_id": run_id,
                                                    "rule": "approved delta covers the pinned input"})
        return _dc_replace(self, records=tuple(keep)), out

    def pinned_obligation(self, base_tree: str | Path, post_tree: str | Path, symbol: str) -> Obligation | None:
        """Layer 5's own check of the pins it recorded (its oracle includes argument mutation).
        None when no pin applies to ``symbol``."""
        cons = self.constraints(symbol)
        if cons is None:
            return None
        split = split_symbol(base_tree, symbol)
        module, func = split if split else (symbol.rpartition(".")[0], symbol.rpartition(".")[2])
        b, p = import_root_of(base_tree, module), import_root_of(post_tree, module)
        if split is None or b is None or p is None:
            return Obligation(f"feedback-pins:{symbol}", symbol, f"pinned inputs of {symbol} were checked",
                              Verdict.UNVERIFIED, stop_reason=f"module of {symbol} not found in base/post tree")
        recv, why = receiver_for(base_tree, b, module, func)
        if why:
            return Obligation(f"feedback-pins:{symbol}", symbol, f"pinned inputs of {symbol} were checked",
                              Verdict.UNVERIFIED, stop_reason=why)
        kw = dict(self.observe_kw, receiver=recv) if recv else self.observe_kw
        return probe_obligation(f"feedback-pins:{symbol}", b, p, module, func, (), cons, **kw)


def load_for_derive(repo: Path, account: dict, **observe_kw: Any) -> DeriveFeedback:
    """Records whose target symbols intersect the effect account's slice, ready for Layer 3."""
    sl = frozenset(account_slice(account))
    constructs = tuple(account.get("unresolved_constructs", ()))
    callee = tuple(account.get("callee_unresolved_constructs", ()))
    files = {(c.get("provenance") or {}).get("source_file") or c.get("file_path") for c in (*constructs, *callee)}
    recs = load_records(Path(repo), sl)
    # not_derived_construct records bind to the construct's own file, which may lie outside the symbol slice
    have = {r.feedback_id for r in recs}
    extra = tuple(r for r in load_records(Path(repo), None) if r.feedback_id not in have
                  and r.directive_kind is DirectiveKind.NOT_DERIVED_CONSTRUCT
                  and r.directive_payload["location"].rsplit(":", 1)[0] in files)
    return DeriveFeedback(tuple(sorted(recs + extra, key=lambda r: r.feedback_id)), dict(observe_kw), sl, constructs,
                          callee_constructs=callee)


def _export(repo: Path, rev: str, dest: Path) -> Path:
    from ..hostio.export import export_tree  # clean export: no export-ignore filtering (finding 26)
    return export_tree(repo, rev, dest)


REGRESSION_KINDS = frozenset({DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE, DirectiveKind.ORACLE_REGRESSION})


def delta_covers_pin(delta: dict, rec: FeedbackRecord, param_names: Sequence[str]) -> bool:
    """True iff a declared (confirmed) intended delta covers a Layer 5 probe divergence."""
    # both regression kinds carry the same stale expected outcome (review FB-NEW-1: the oracle twin of a superseded pin kept refuting)
    if rec.directive_kind not in REGRESSION_KINDS or "predicate" not in delta:
        return False
    p = rec.directive_payload
    if delta.get("symbol") != p["symbol"]:
        return False
    inp, obs, exp = p["input"], p["observed"], p["expected"]
    if inp.get("env"):
        return False
    if obs.get("args_after") != exp.get("args_after"):
        return False
    if delta["expected"].get("kind") == "returns_expr":
        if not _computed_expected_covers(delta["expected"]["expr"], inp, obs, param_names):
            return False
    else:
        delta_expected_matches = _PROBE_BRIDGE.get("delta_expected_matches")
        from_feedback = _PROBE_BRIDGE.get("from_feedback")
        if delta_expected_matches is None or from_feedback is None:
            return False
        if not delta_expected_matches(delta["expected"], from_feedback(obs)):
            return False
    pr = delta["predicate"]
    if pr["type"] not in ("literal_inputs", "typed", "expr"):
        return False  # an unknown predicate type covers nothing: it stays pinned
    if pr["type"] == "literal_inputs":
        norm_call = _PROBE_BRIDGE.get("norm_call")
        if norm_call is None:
            return False
        call = norm_call(inp["args"], inp.get("kwargs", {}))
        return any(call == norm_call(i["args"], i["kwargs"]) for i in pr["inputs"])
    bound = dict(zip(param_names, inp["args"]))
    bound.update(inp.get("kwargs", {}))
    if pr["param"] not in bound:
        return False
    v = bound[pr["param"]]
    if isinstance(v, dict) and "$obj" in v:
        return False
    if pr["type"] == "expr":
        expr_matches = _PROBE_BRIDGE.get("expr_matches")
        if expr_matches is None:
            return False
        try:
            return bool(expr_matches(pr["param"], pr["expr"], v))
        except Exception:
            return False
    typed_match = _PROBE_BRIDGE.get("typed_match")
    if typed_match is None:
        return False
    return typed_match(pr["class"], v, pr.get("key"))


def _pin_data(v, depth: int = 0) -> bool:
    """A pinned input value is plain JSON data: no stub-object/marker dicts ($obj, $...) anywhere."""
    if depth > 20:
        return False
    if isinstance(v, dict):
        return all(isinstance(k, str) and not k.startswith("$") and _pin_data(x, depth + 1) for k, x in v.items())
    if isinstance(v, list):
        return all(_pin_data(x, depth + 1) for x in v)
    return True


def _computed_expected_covers(expr: str, inp: dict, obs: dict, param_names: Sequence[str]) -> bool:
    """design review ruling (e), 2026-11-13: evaluates a returns_expr via coordinator-injected expected_expr helpers."""
    evaluate_expected_expr = _PROBE_BRIDGE.get("evaluate_expected_expr")
    inert_from_repr = _PROBE_BRIDGE.get("inert_from_repr")
    is_inert = _PROBE_BRIDGE.get("is_inert")
    value_matches = _PROBE_BRIDGE.get("value_matches")
    if None in (evaluate_expected_expr, inert_from_repr, is_inert, value_matches):
        return False

    if obs.get("kind") != "return":
        return False
    ok, post = inert_from_repr(obs.get("repr"))
    if not ok:
        return False
    args, kwargs = list(inp.get("args") or []), dict(inp.get("kwargs") or {})
    if len(args) > len(param_names):
        return False  # *args overflow: cannot bind by name
    bound = dict(zip(param_names, args))
    for k, v in kwargs.items():
        if k in bound:
            return False
        bound[k] = v
    if not all(_pin_data(v) and is_inert(v) for v in bound.values()):
        return False
    ok, val = evaluate_expected_expr(expr, bound)
    return bool(ok) and value_matches(val, post)


def _param_names(root: Path, module: str, func: str) -> list[str]:
    node, pos = _target_params(root, module, func)
    return [a.arg for a in pos] if node is not None else []


def _witness_outcome(o: dict) -> dict:
    """review's evaluator outcome {k: ret|exc|timeout, r|t} -> a feedback outcome {kind, repr|exc}."""
    if o.get("k") == "ret":
        return {"kind": "return", "repr": str(o.get("r", ""))}
    if o.get("k") == "exc":
        return {"kind": "raise", "exc": str(o.get("t", ""))}
    return {"kind": "timeout"}


def _pin_limit(witness: dict) -> str | None:
    """A feedback pin can represent a plain call and its current base outcome."""
    if witness.get("oracle") == "recorded-expected":
        return "historical expectation (already stored)"
    if witness.get("truncated"):
        return "truncated"
    if witness.get("inject") is not None:
        return "inject"
    if witness.get("receiver") is not None:
        return "receiver construction is not stored in a feedback pin"
    if witness.get("throw"):
        return "generator throw is not stored in a feedback pin"
    return None


def _pin_witnesses(repo: Path, source_run_id: str, witnesses: Sequence[dict], unpinned: list | None) -> list[Path]:
    """The differential's exact refuting call, pinned verbatim (expected = its pre outcome). A fault-injection
    witness or a size-capped one is not a plain replayable call: reported in ``unpinned``, never dropped
    silently (unresolved and owned: replay injection in the probe)."""
    out: list[Path] = []
    for w in witnesses:
        why = _pin_limit(w)
        if why is None and not all(k in w for k in ("args", "kwargs", "pre", "post")):
            why = "incomplete"
        if why is not None:
            if unpinned is not None:
                unpinned.append({"symbol": w["symbol"], "reason": why})
            continue
        rec = pin_regression_counterexample(source_run_id, w["symbol"], w["args"], w["kwargs"],
                                            expected=_witness_outcome(w["pre"]), observed=_witness_outcome(w["post"]),
                                            env=w.get("env") or None)
        rec = with_provenance(rec, origin_kind="differential-witness", observed_in_run="refuted")
        out.append(persist(repo, rec))
    return out


def _after_refusal(repo: Path, obligations: Any, source_run_id: str, effect_diff: str, probe_limit: int,
                   constructs: Sequence[dict] = (), witnesses: Sequence[dict] = (), unpinned: list | None = None,
                     probe_allowed: bool = True, **observe_kw: Any) -> tuple[Path, ...]:
    """Hlith.md 1.5: a refused outcome also produces loadable records (from the refusal execution trace).
    Each REFUTED behavioural obligation -> the base-vs-candidate divergences, re-observed confined on the
    refused candidate tree, pinned with expected = base outcome: a later attempt on the symbol is checked on
    them first. They were found in this run, so they are refusal memory, never 'learning' (F2).
    Each unresolved construct that blocked the refusal (an ``unresolved-*`` NOT_DERIVED obligation) -> a
    not_derived_construct record bound to its node digest (review provenance), so it can never go stale."""
    import tempfile
    import time as _tm

    written: list[Path] = _pin_witnesses(repo, source_run_id, witnesses, unpinned)
    witness_keys = {
        (w["symbol"], _canon(_call_input(w["args"], w["kwargs"], w.get("env") or None)))
        for w in witnesses if "symbol" in w and "args" in w and "kwargs" in w
    }
    blocked = {o.stop_reason for o in obligations.obligations
               if o.verdict is Verdict.NOT_DERIVED and o.obligation_id.startswith("unresolved-") and o.stop_reason}
    for c in constructs:
        prov = c.get("provenance") or {}
        loc = f"{c.get('file_path')}:{c.get('line_number')}"
        sha = prov.get("node_sha256")
        if not sha or not any(b.startswith(f"{loc} {c.get('kind')}:") for b in blocked):
            continue
        written.append(persist(repo, not_derived_construct(
            source_run_id, c.get("caller_qualified_name") or c.get("file_path"), c.get("kind"), loc, sha)))
    if not probe_allowed:
        return tuple(written)

    refuted = sorted({o.target_symbol for o in obligations.obligations if o.verdict is Verdict.REFUTED
                      and o.obligation_id.startswith(("differential:", "feedback-pins:")) and "." in o.target_symbol})
    other_diff = sorted({o.target_symbol for o in obligations.obligations
                         if o.obligation_id.startswith("differential:") and "." in o.target_symbol
                         and o.target_symbol not in refuted})
    symbols = refuted + other_diff
    if not symbols or not effect_diff:
        return tuple(written)
    ext_deadline = _tm.monotonic() + EXT_BUDGET_S
    with tempfile.TemporaryDirectory(prefix="hlith-feedback-refused-") as tmp:
        base = _export(repo, "HEAD", Path(tmp) / "base")
        cand = _export(repo, "HEAD", Path(tmp) / "candidate")
        ap = _apply_diff_scrubbed(Path(cand), effect_diff)
        if ap.returncode != 0:
            return tuple(written)
        for sym in symbols:
            split = split_symbol(base, sym)
            if split is None:
                continue
            module, func = split
            b, p = import_root_of(base, module), import_root_of(cand, module)
            if b is None or p is None:
                continue
            recv, why = receiver_for(base, b, module, func)
            if why:
                continue
            okw = dict(observe_kw, receiver=recv) if recv else observe_kw
            tests = base / "tests"
            seeds = literal_seeds(b, tests, module, func) if tests.is_dir() else []
            seeds += pool_seeds(b, module, func, literals=literals_from_tests(tests, func))
            seeds += stub_seeds(b, module, func)
            if seeds:
                for rec in post_gate_probe(
                    source_run_id, b, p, module, func, seeds, limit=probe_limit,
                    provenance_origin_kind="refusal-probe", provenance_observed_in_run="refused", **okw,
                ):
                    if (sym, _canon(rec.directive_payload["input"])) not in witness_keys:
                        written.append(persist(repo, rec))
            if probe_limit > 0:
                ext, _stats = extended_probe(source_run_id, b, p, module, func, seed=ext_probe_seed(sym),
                                             tree_root=cand, limit=probe_limit, deadline=ext_deadline, **okw)
                for rec in ext:
                    if (sym, _canon(rec.directive_payload["input"])) not in witness_keys:
                        written.append(persist(repo, with_provenance(
                            rec, origin_kind="refusal-probe", observed_in_run="refused")))
    return tuple(written)


def after_gate(
    repo: Path,
    decision: Any,
    obligations: Any,
    *,
    source_run_id: str,
    probe_limit: int = 3,
    deltas: Sequence[dict] = (),
    deltas_confirmed: bool = False,
    covered: list | None = None,
    effect_diff: str = "",
    constructs: Sequence[dict] = (),
    witnesses: Sequence[dict] = (),
    unpinned: list | None = None,
    superseded: Sequence[dict] = (),
    **observe_kw: Any,
) -> tuple[Path, ...]:
    """Supervisor-side Layer 5 step, after every gate outcome. Never called by the worker.

    ``superseded`` (design review post-landing rule): the pins this run did not apply because the confirmed delta set covered
    them (DeriveFeedback.supersede_pins). When the run LANDED with that confirmed set, each gets a
    superseded-by-landing line (landed commit + delta_set_sha256) and is never loaded again while that commit stays in
    HEAD's history: HEAD now embodies the approved behaviour, and any later change is judged against the new base.

    ``deltas`` + ``deltas_confirmed``: the landed effect's declared intended deltas and whether
    their exact set was independently confirmed. Only when confirmed AND landed is a divergence
    one of them covers (``delta_covers_pin``) treated as the approved change rather than a
    regression: it is not pinned, and it is reported in ``covered`` as
    {"covered_by_delta": id, "symbol", "count", "examples" (<= 5 inputs)}, never dropped silently. Pins recorded by any
    other path (earlier runs, pin_oracle) are untouched and still refute.

    LANDED: for each callable a differential obligation covered, probe base (landed^) vs
    landed on the repository's own test literals, their boundary variants and a generic
    value pool, under hlith.sandbox, with the argument-mutation oracle. Persist one pin per
    confirmed divergence; when the held verdict relied on the repository's tests for the
    symbol, also an oracle_regression record naming them (Hlith.md OR4).
    REFUSED: records from the refusal trace (``_after_refusal``; needs ``effect_diff`` for the
    candidate tree). Returns the written record paths.
    """
    import tempfile

    exit_status = getattr(decision, "exit_status", None)
    if getattr(getattr(decision, "outcome", None), "value", None) != "landed" or not decision.landed_commit:
        return _after_refusal(Path(repo), obligations, source_run_id, effect_diff, probe_limit, constructs,
                               witnesses, unpinned, probe_allowed=(exit_status == 10), **observe_kw)
    repo = Path(repo)
    if deltas_confirmed:
        for s in superseded:
            _append_supersession(repo, s["fb_id"], {"superseded_by_landing": decision.landed_commit,
                                                    "delta_set_sha256": s["delta_set_sha256"], "run_id": source_run_id,
                                                    "rule": "post-landing: the approved behaviour landed"})
    symbols = sorted({o.target_symbol for o in obligations.obligations
                      if o.obligation_id.startswith("differential:") and "." in o.target_symbol})
    written: list[Path] = []
    import time as _tm
    ext_deadline = _tm.monotonic() + EXT_BUDGET_S  # the extended probe's TOTAL wall budget for this run
    with tempfile.TemporaryDirectory(prefix="hlith-feedback-") as tmp:
        base = _export(repo, f"{decision.landed_commit}^", Path(tmp) / "base")
        landed = _export(repo, decision.landed_commit, Path(tmp) / "landed")
        for sym in symbols:
            split = split_symbol(base, sym)  # module from the files: methods are not split at the class
            if split is None:
                continue
            module, func = split
            b, p = import_root_of(base, module), import_root_of(landed, module)
            if b is None or p is None:
                continue
            recv, why = receiver_for(base, b, module, func)
            if why:
                continue  # a method with no derivable receiver teaches nothing here
            okw = dict(observe_kw, receiver=recv) if recv else observe_kw
            tests = base / "tests"
            seeds = literal_seeds(b, tests, module, func) if tests.is_dir() else []
            seeds += pool_seeds(b, module, func, literals=literals_from_tests(tests, func))
            seeds += stub_seeds(b, module, func)
            _d, _ps = _target_params(b, module, func)
            if effect_diff and _d is not None and len(_ps) == 1:  # the landed hunks' own literals (appended; existing seeds untouched)
                have = {_canon(x) for x in seeds}
                seeds += [x for x in diff_literal_seeds(effect_diff) if _canon(x) not in have]
            if not seeds and recv is not None and not _target_params(b, module, func)[1]:
                seeds = [{"args": [], "kwargs": {}}]  # a no-argument method: one call on a fresh receiver
            if not seeds:
                continue
            held_on_tests = any(o.obligation_id == f"differential:{sym}" and o.verdict is Verdict.HELD
                                and o.evidence is not None and "impacted tests" in (o.evidence.explored or "")
                                for o in obligations.obligations)
            relied_tests = tests_referencing(base / "tests", func) if held_on_tests else []
            active = tuple(deltas) if deltas_confirmed else ()
            names = _param_names(p, module, func) if active else []
            # every divergence first, then the delta filter, then the pin limit: covered divergences
            # must never use up the limit and hide an uncovered one
            divs = post_gate_probe(source_run_id, b, p, module, func, seeds,
                                   limit=1 << 30 if active else probe_limit, **okw)
            hits: dict[str, dict] = {}
            pinned = 0
            for rec in divs:
                hit = next((d for d in active if delta_covers_pin(d, rec, names)), None)
                if hit is not None:
                    h = hits.setdefault(hit["id"], {"covered_by_delta": hit["id"], "symbol": sym, "count": 0,
                                                    "examples": []})
                    h["count"] += 1
                    if len(h["examples"]) < 5:
                        h["examples"].append(rec.directive_payload["input"])
                    continue
                if pinned < probe_limit:
                    if not (
                        rec.provenance
                        and rec.provenance.get("origin_kind") == "post-gate-probe"
                        and rec.provenance.get("observed_in_run") == "refuted"
                    ):
                        rec = with_provenance(rec, origin_kind="post-gate-probe", observed_in_run="refuted")
                    written.append(persist(repo, rec))
                    pinned += 1
                    if relied_tests:  # the held verdict leaned on these tests and they missed it (OR4)
                        pp = rec.directive_payload
                        oracle = oracle_regression(
                            source_run_id, sym, relied_tests, pp["input"]["args"], pp["input"]["kwargs"],
                            expected=pp["expected"], observed=pp["observed"], env=pp["input"].get("env"))
                        oracle = with_provenance(oracle, origin_kind="post-gate-probe", observed_in_run="refuted")
                        written.append(persist(repo, oracle))
            if pinned < probe_limit:  # extended families: a domain the differential did not explore (design review F2)
                ext_seed = ext_probe_seed(sym)
                ext, _stats = extended_probe(source_run_id, b, p, module, func, seed=ext_seed, tree_root=landed,
                                             limit=1 << 30 if active else probe_limit - pinned,
                                             deadline=ext_deadline, **okw)
                for rec in ext:
                    hit = next((d for d in active if delta_covers_pin(d, rec, names)), None)
                    if hit is not None:
                        h = hits.setdefault(hit["id"], {"covered_by_delta": hit["id"], "symbol": sym, "count": 0,
                                                        "examples": []})
                        h["count"] += 1
                        if len(h["examples"]) < 5:
                            h["examples"].append(rec.directive_payload["input"])
                        continue
                    if pinned < probe_limit:
                        written.append(persist(repo, with_provenance(
                            rec, origin_kind="post-gate-probe", observed_in_run="refuted")))
                        pinned += 1
            if covered is not None:
                covered.extend(hits[k] for k in sorted(hits))
    return tuple(written)
