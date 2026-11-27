# SPDX-License-Identifier: Apache-2.0
"""pytest plugin to track file descriptor counts (/proc/self/fd) across test files and individual tests."""

import os
import resource
import pytest
from pathlib import Path


def _count_fds() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


class FDTrackerPlugin:
    def __init__(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        self.ulimit_soft = soft
        self.ulimit_hard = hard
        self.current_file = None
        self.file_start_fds = 0
        self.file_stats = []  # list of (file, start_fds, end_fds, delta)
        self.test_stats = []  # list of (test_id, delta)

    def pytest_sessionstart(self, session):
        init_fds = _count_fds()
        print(f"\n[FD-TRACKER] SESSION START: ulimit -n (soft={self.ulimit_soft}, hard={self.ulimit_hard}), active FDs={init_fds}")

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(self, item, nextitem):
        item_file = str(item.fspath)
        if item_file != self.current_file:
            if self.current_file is not None:
                end_fds = _count_fds()
                delta = end_fds - self.file_start_fds
                self.file_stats.append((self.current_file, self.file_start_fds, end_fds, delta))
                print(f"\n[FD-TRACKER] FILE END: {Path(self.current_file).name} (start={self.file_start_fds}, end={end_fds}, delta={delta:+d})")

            self.current_file = item_file
            self.file_start_fds = _count_fds()
            print(f"\n[FD-TRACKER] FILE START: {Path(self.current_file).name} (start FDs={self.file_start_fds})")

        before_test = _count_fds()
        yield
        after_test = _count_fds()
        test_delta = after_test - before_test
        if test_delta > 0:
            self.test_stats.append((item.nodeid, test_delta))

        if nextitem is None:
            end_fds = _count_fds()
            delta = end_fds - self.file_start_fds
            self.file_stats.append((self.current_file, self.file_start_fds, end_fds, delta))
            print(f"\n[FD-TRACKER] FILE END: {Path(self.current_file).name} (start={self.file_start_fds}, end={end_fds}, delta={delta:+d})")

    def pytest_sessionfinish(self, session, exitstatus):
        final_fds = _count_fds()
        print("\n" + "=" * 80)
        print("                           FD TRACKER SUMMARY TABLE")
        print("=" * 80)
        print(f"Host ulimit -n soft: {self.ulimit_soft}, hard: {self.ulimit_hard}")
        print(f"Final active FDs: {final_fds}\n")
        print(f"{'Test File':<40} {'Start':>8} {'End':>8} {'Delta':>8}")
        print("-" * 68)
        for f, s, e, d in sorted(self.file_stats, key=lambda x: x[3], reverse=True):
            print(f"{Path(f).name:<40} {s:>8} {e:>8} {d:>+8}")
        print("=" * 80)

        if self.test_stats:
            print("\nTop Leaking Individual Tests:")
            for tid, td in sorted(self.test_stats, key=lambda x: x[1], reverse=True)[:15]:
                print(f"  {td:+3d} FDs: {tid}")
        print("=" * 80 + "\n")


def pytest_configure(config):
    tracker = FDTrackerPlugin()
    config.pluginmanager.register(tracker, "fd_tracker")
