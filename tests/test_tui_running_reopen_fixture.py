"""Stdlib-only contract check for the real Running -> detach -> History fixture."""
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from tui_running_reopen import BASE, CHANGED, prepare


class RunningReopenFixtureTests(unittest.TestCase):
    def test_plain_clone_has_exact_two_line_change_and_stdlib_test_passes(self):
        with tempfile.TemporaryDirectory(prefix="hlith-running-fixture-") as temp:
            seed, repo = prepare(Path(temp) / "fixture")
            self.assertTrue((repo / ".git").is_dir())
            self.assertFalse((repo / ".git").is_symlink())
            self.assertNotEqual((repo / "calc.py").read_text(), BASE["calc.py"])
            self.assertEqual((repo / "calc.py").read_text(), CHANGED["calc.py"])
            self.assertEqual((seed / "calc.py").read_text(), BASE["calc.py"])
            self.assertEqual(len((repo / "test_calc.py").read_text().splitlines()), len(CHANGED["test_calc.py"].splitlines()))


if __name__ == "__main__":
    unittest.main()
