"""A TUI-launched engine must keep its client/engine lifecycle contract."""

from hlith.operator import engine_cli
from hlith.hostio import lifecycle


def test_standalone_tui_engine_does_not_arm_headless_parent_death(monkeypatch, tmp_path):
    armed = []
    monkeypatch.setattr(lifecycle, "die_with_parent", lambda: armed.append(True))

    def tui_engine(args):
        assert args.surface_mode == "standalone"
        return 0

    monkeypatch.setattr(engine_cli, "_run_via_pipeline", tui_engine)
    rc = engine_cli.main([
        "run", "--repo", str(tmp_path), "--worker-cmd", "true", "--artifact-out", str(tmp_path / "out.json"),
        "--engine", "pipeline", "--surface-mode", "standalone",
    ])

    assert rc == 0
    assert armed == []
