"""Report the host's Landlock ABI and which confinement capabilities Hlith requests on it (read-only).

    python scripts/landlock_capabilities.py [--json]

Only queries the kernel: landlock_create_ruleset() for the ABI version and for trial rulesets, each fd closed at once.
It never calls landlock_restrict_self(), opens no socket, starts no process. A trial with the next unused filesystem
bit (16) or network bit (2) failing with EINVAL shows the kernel offers no right beyond the ones Hlith knows; the
names given to those future rights (pathname UNIX resolution at ABI 9, UDP at ABI 10) come from the upstream
Landlock documentation, not from this host.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import sys

SYS_CREATE = 444
VERSION, ERRATA = 1 << 0, 1 << 1
# filesystem access bit -> minimum ABI (mirrors hlith/hostio/confine_exec.py FS)
FS_BITS = {**{1 << b: 1 for b in range(13)}, 1 << 13: 2, 1 << 14: 3, 1 << 15: 5}
NET_TCP = (1 << 0) | (1 << 1)  # bind, connect (ABI 4)
SCOPES = (1 << 0) | (1 << 1)  # abstract unix socket, signal (ABI 6)

# (capability, minimum ABI, requested by Hlith's confine_exec.landlock())
FEATURES = (
    ("filesystem rules (exec, read, write, make/remove)", 1, True),
    ("refer (cross-directory link/rename)", 2, True),
    ("truncate", 3, True),
    ("TCP bind/connect rules", 4, True),
    ("device ioctl rule", 5, True),
    ("abstract UNIX socket scope", 6, True),
    ("signal scope", 6, True),
    ("audit logging flags for restrict_self", 7, False),
    ("thread-sync (TSYNC) for restrict_self", 8, False),
    ("pathname UNIX socket resolution (LANDLOCK_ACCESS_FS_RESOLVE_UNIX)", 9, False),
    ("UDP bind/connect-send rules", 10, False),
)


class Attr(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


def capabilities(abi: int) -> list[dict]:
    """Pure: which features this ABI provides and which Hlith requests (no kernel access)."""
    return [{"feature": name, "min_abi": need, "available": abi >= need, "requested_by_hlith": req, "in_effect": req and abi >= need}
            for name, need, req in FEATURES]


def _create(libc, attr, size: int, flags: int = 0) -> tuple[int, int]:
    ctypes.set_errno(0)
    fd = libc.syscall(SYS_CREATE, ctypes.byref(attr) if attr is not None else None, ctypes.c_size_t(size), ctypes.c_uint32(flags))
    err = ctypes.get_errno()
    if fd >= 0 and attr is not None:
        os.close(fd)
    return fd, err


def host_report() -> dict:
    libc = ctypes.CDLL(None, use_errno=True)
    abi, err = _create(libc, None, 0, VERSION)
    if abi < 0:
        return {"abi": None, "error": errno.errorcode.get(err, str(err)), "capabilities": capabilities(0), "trials": {}}
    errata, _ = _create(libc, None, 0, ERRATA)
    fs = 0
    for bit, need in FS_BITS.items():
        if abi >= need:
            fs |= bit
    size = 8 if abi < 4 else (16 if abi < 6 else 24)
    hlith = Attr(fs, NET_TCP if abi >= 4 else 0, SCOPES if abi >= 6 else 0)
    trials = {}
    fd, e = _create(libc, hlith, size)
    trials["hlith ruleset (fs + TCP + abstract-unix/signal scopes)"] = "created" if fd >= 0 else errno.errorcode.get(e, str(e))
    if abi >= 6:
        for label, attr in (("next filesystem bit (1<<16)", Attr(fs | (1 << 16), NET_TCP, SCOPES)),
                            ("next network bit (1<<2)", Attr(fs, NET_TCP | (1 << 2), SCOPES)),
                            ("next scope bit (1<<2)", Attr(fs, NET_TCP, SCOPES | (1 << 2)))):
            fd, e = _create(libc, attr, 24)
            trials[label] = "created" if fd >= 0 else errno.errorcode.get(e, str(e))
    return {"abi": abi, "errata": errata if errata >= 0 else None, "capabilities": capabilities(abi), "trials": trials}


def main(argv: list[str]) -> int:
    rep = host_report()
    if "--json" in argv:
        print(json.dumps(rep, indent=1))
        return 0 if rep["abi"] else 1
    print(f"Landlock ABI: {rep['abi']}  (errata bitmask: {rep.get('errata')})")
    for c in rep["capabilities"]:
        state = "IN EFFECT" if c["in_effect"] else ("available, not requested" if c["available"] else f"not on this host (ABI {c['min_abi']}+)")
        print(f"  - {c['feature']}: {state}")
    for k, v in rep["trials"].items():
        print(f"  trial {k}: {v}")
    return 0 if rep["abi"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
