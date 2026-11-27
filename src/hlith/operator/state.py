# SPDX-License-Identifier: Apache-2.0
"""Operator view of host state: a narrowing wrapper over hostio's ``LocalHostState`` (L0 owns the root, the layout and the
repository identity rules). The operator may use the ``runs`` namespace only and can never read an engine key.

Layout (hostio): ``$XDG_STATE_HOME/hlith/repositories/<stable-repo-identity>/runs/<run_id>/`` (``HLITH_STATE_DIR`` overrides).
Pre-freeze UI state (``HLITH_UI_STATE`` / ~/.local/state/hlith-ui/runs) stays readable, read-only, with its original schema
identity. Local-first and offline: nothing here touches a network or the target repository.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..hostio import HostIntegrityError, LocalHostState, default_state_root

__all__ = ["LocalState", "HostIntegrityError", "state_root", "legacy_ui_state"]


def ui_directory() -> Path:
    """UI preferences and old launch records. Engine state has its own precedence."""
    chosen = os.environ.get("HLITH_UI_STATE") or os.environ.get("HLITH_STATE_DIR")
    return Path(chosen).expanduser() if chosen else Path.home() / ".local" / "state" / "hlith-ui"


def _is_launcher_preview_ui_dir(path: Path) -> bool:
    """True when HLITH_UI_STATE is only the installed launcher's default operator-preview fallback."""
    try:
        return path.expanduser() == (Path.home() / ".local" / "state" / "hlith" / "operator-preview")
    except RuntimeError:
        return False


def state_root(ui_dir: Path | None = None) -> Path:
    """Resolve the engine store without creating it, even when called during review."""
    explicit_ui = os.environ.get("HLITH_UI_STATE")
    has_state_dir = bool(os.environ.get("HLITH_STATE_DIR"))
    if ui_dir is not None:
        ui_path = Path(ui_dir)
        if ui_path != ui_directory():
            return ui_path / "host"
        if explicit_ui and not (has_state_dir and _is_launcher_preview_ui_dir(ui_path)):
            return ui_path / "host"
    if has_state_dir:
        return default_state_root()
    if explicit_ui:
        return ui_directory() / "host"
    return default_state_root()


def legacy_ui_state() -> Path:
    return Path(os.environ.get("HLITH_UI_STATE") or (Path.home() / ".local" / "state" / "hlith-ui"))


class LocalState:
    """The operator's HostState: ``runs`` only; no key."""

    def __init__(self, root: Path | None = None) -> None:
        self._host = LocalHostState(state_root(root))

    @property
    def root(self) -> Path:
        return Path(self._host._root)

    def stable_repo_identity(self, repo: Path) -> str:
        return self._host.stable_repo_identity(Path(repo))

    def namespace(self, repo_identity: str, name: str) -> Path:
        if name != "runs":
            raise PermissionError(f"the operator may only use the 'runs' namespace, not {name!r}")
        return self._host.namespace(repo_identity, "runs")

    def key(self, purpose) -> bytes:
        raise PermissionError("the operator holds no engine key")

    def existing_runs_dir(self, repo: Path) -> Path | None:
        """The repository's runs directory WITHOUT creating anything (a viewer never writes). None if absent or the repository
        identity cannot be computed (hostile/unreadable repository: nothing is listed, nothing is guessed)."""
        try:
            ident = self.stable_repo_identity(repo)
        except HostIntegrityError:
            return None
        d = self.root / "repositories" / ident / "runs"
        return d if d.is_dir() else None
