# SPDX-License-Identifier: Apache-2.0
"""Assemble the section capabilities the trusted pipeline needs, from the sections' PUBLIC APIs only.

The operator host (a trusted coordinator process, not the renderer) may use the public APIs of L1-L5 and hostio (import-boundary
section 3). Keys stay inside hostio: the verification service holds the VERIFIER_ISSUE key; the L3 engine receives only the
``VerificationIssuer`` capability and L4 only the ``VerificationVerifier`` capability. Any section a caller overrides with
``None`` makes ``pipeline.run_pipeline`` refuse closed (exit 4, ``missing capabilities``); it never runs without it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .pipeline import PipelineCapabilities
from .intent.manifest import intent_from_manifest


def default_capabilities(*, state_root: Path | None = None, thread_store: Path | None = None, event_sink=None,
                         python: str | None = None, extra_sys_path: Sequence[str] = (),
                         proposer_paths: Sequence[str] = (), differential_timeout: float = 600.0,
                         intent=None, probe_bridge=None, resume_proposer=None, resume_timeout: float = 120.0,
                         resume_checkpoint_id: str | None = None) -> PipelineCapabilities:
    from ..agent import AgentApiImpl
    from ..effect import EffectService
    from ..feedback import LocalFeedbackService
    from ..gate import LocalGateService
    from ..hostio import HardenedGitRead, LocalHostState, LocalSnapshotService
    from ..hostio.verification import LocalVerificationService
    from ..obligation.api import ObligationEngine

    _register_probe_bridge(probe_bridge)
    host = LocalHostState(state_root)
    git_read = HardenedGitRead()
    snapshots = LocalSnapshotService(git_read)
    verification = LocalVerificationService(host)  # issuer (L3) and verifier (L4) over the one VERIFIER_ISSUE key
    agent_cls = AgentApiImpl
    if resume_proposer is not None or resume_checkpoint_id is not None:
        class _ResumeBoundAgent(AgentApiImpl):
            """The pipeline's resume request carries only the thread id. A mid-agent thread continues with the same local command.
            A thread already parked at its effect interrupt is resumed by checkpoint id and does not call the proposer again."""

            def resume(self, thread_id, *, redo_inflight: bool = False, **kw):
                if resume_checkpoint_id is not None:
                    kw["checkpoint_id"] = resume_checkpoint_id
                    return super().resume(thread_id, redo_inflight=redo_inflight, proposer=None, timeout=resume_timeout, **kw)
                return super().resume(thread_id, redo_inflight=redo_inflight, proposer=resume_proposer, timeout=resume_timeout, **kw)

        agent_cls = _ResumeBoundAgent
    return PipelineCapabilities(
        snapshot_service=snapshots,
        host_state=host,
        agent_api=agent_cls(snapshot_service=snapshots, host_state=host, git_read=git_read, thread_store=thread_store,
                            event_sink=event_sink),
        effect_api=EffectService(),
        obligation_api=ObligationEngine(verification, intent=intent, python=python, extra_sys_path=extra_sys_path,
                                        proposer_paths=proposer_paths, differential_timeout=differential_timeout),
        gate_api=LocalGateService(host, git_read=git_read, snapshot_service=snapshots),
        verifier=verification,
        # design review P1-2: L5's probes use the run's own target interpreter and import paths (same as the obligation engine above)
        feedback_api=LocalFeedbackService(host, observe_kw={"python": python, "extra_sys_path": tuple(extra_sys_path),
                                                            "proposer_paths": tuple(proposer_paths)}),
        intent=intent,
    )


PROBE_BRIDGE_KEYS = ("synthesize_dist_info", "receiver_recipe", "expr_matches", "typed_match", "delta_expected_matches",
                     "from_feedback", "norm_call", "evaluate_expected_expr", "inert_from_repr", "is_inert", "value_matches")


class ProbeBridgeUnavailable(RuntimeError):
    """The L3 probe helpers are not exported (or incomplete): F2 probing would silently do less, so the coordinator refuses."""


def _register_probe_bridge(bridge) -> None:
    """The coordinator injects the real L3 helpers into L5 at startup (L5 must not import L3). An unregistered bridge makes the
    probes a silent no-op, so a missing or incomplete bridge is a named startup failure, never a degraded run. ``bridge`` is
    injectable; the default is ``hlith.obligation.probe_bridge()`` (review's public export)."""
    from .. import feedback

    if bridge is None:
        from .. import obligation

        provider = getattr(obligation, "probe_bridge", None)
        if provider is None:
            raise ProbeBridgeUnavailable("hlith.obligation.probe_bridge is not exported yet (needed: " + ", ".join(PROBE_BRIDGE_KEYS) + ")")
        bridge = provider()
    missing = [k for k in PROBE_BRIDGE_KEYS if not callable(bridge.get(k))]
    if missing:
        raise ProbeBridgeUnavailable("L3 probe bridge is missing: " + ", ".join(missing))
    feedback.register_probe_bridge(**{k: bridge[k] for k in PROBE_BRIDGE_KEYS})


def proposer_private_paths(worker_argv, worker_ro, patch, manifest, proposer, *, extra=()) -> list[str]:
    """The proposer-owned inputs a blinded check must be unable to read: the patch and manifest files, every existing path named by
    the worker command or its read-only grants, a script's parent directory (relative imports reach sibling code), the thread store,
    and whatever a proposer object declares via ``referenced_paths``. Shared interpreter/runtime prefixes are excluded; non-existent
    paths are dropped (blindness is proven against paths that exist). An empty result stays an empty list: the differential refuses it."""
    import sys

    candidates = [*worker_argv, *worker_ro, *[x for x in (patch, manifest, *extra) if x is not None]]
    referenced = getattr(proposer, "referenced_paths", None)
    if callable(referenced):
        for raw in referenced():
            path = Path(raw).expanduser().resolve()
            candidates.append(path)
            if path.is_file():  # running a script puts its parent on sys.path
                candidates.append(path.parent)
    runtime_roots = {Path(p).resolve() for p in {sys.prefix, sys.base_prefix, "/usr", "/lib", "/bin"}}
    paths = set()
    for raw in candidates:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, TypeError, ValueError):
            continue
        if not path.exists() or any(path == root or root in path.parents for root in runtime_roots):
            continue
        paths.add(str(path))
    return sorted(paths)
