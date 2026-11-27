"""The Landlock capability report: pure ABI mapping, its agreement with the confinement launcher, and a read-only host query."""
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("landlock_capabilities", ROOT / "scripts" / "landlock_capabilities.py")
lc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lc)


def by_name(abi):
    return {c["feature"]: c for c in lc.capabilities(abi)}


def test_abi6_scopes_abstract_unix_and_signals_but_not_pathname_unix_or_udp():
    c = by_name(6)
    assert c["abstract UNIX socket scope"]["in_effect"] and c["signal scope"]["in_effect"]
    assert not c["pathname UNIX socket resolution (LANDLOCK_ACCESS_FS_RESOLVE_UNIX)"]["available"]
    assert not c["UDP bind/connect-send rules"]["available"]


def test_pathname_unix_and_udp_are_never_claimed_in_effect_even_when_the_kernel_has_them():
    for abi in (9, 10, 12):
        c = by_name(abi)
        assert c["pathname UNIX socket resolution (LANDLOCK_ACCESS_FS_RESOLVE_UNIX)"]["available"] == (abi >= 9)
        assert not c["pathname UNIX socket resolution (LANDLOCK_ACCESS_FS_RESOLVE_UNIX)"]["in_effect"]
        assert c["UDP bind/connect-send rules"]["available"] == (abi >= 10)
        assert not c["UDP bind/connect-send rules"]["in_effect"]


def test_the_report_mirrors_what_the_launcher_requests():
    src = (ROOT / "src" / "hlith" / "hostio" / "confine_exec.py").read_text()
    fs_map = re.search(r"FS = \{.*?\n\}", src, re.S).group(0)
    launcher = {int(b): int(m) for b, m in re.findall(r"1 << (\d+): (\d+)", fs_map)}
    assert {k.bit_length() - 1: v for k, v in lc.FS_BITS.items()} == launcher
    assert "scoped = 3" in src and "NET_BIND | NET_CONNECT" in src
    assert "RESOLVE_UNIX" not in src.split("def landlock(")[1].split("def landlock_only(")[0].replace("LANDLOCK_ACCESS_FS_RESOLVE_UNIX (ABI 9), which is not requested", "")


def test_host_report_is_read_only_and_consistent():
    rep = lc.host_report()
    if rep["abi"] is None:
        return  # no Landlock on this host: nothing to compare (the engine refuses with exit 4 there)
    assert rep["trials"]["hlith ruleset (fs + TCP + abstract-unix/signal scopes)"] == "created"
    if rep["abi"] < 9:
        assert rep["trials"]["next filesystem bit (1<<16)"] == "EINVAL"
    if rep["abi"] < 10:
        assert rep["trials"]["next network bit (1<<2)"] == "EINVAL"
