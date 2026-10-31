"""Local build gate requiring the actual Windows security regression suite."""
import ast
from pathlib import Path
import sys
import unittest


def main():
    root = Path(__file__).resolve().parent
    if sys.platform != "win32":
        print("Build gate denied: Windows handle tests must run on Windows.")
        return 2
    for path in (root / "backend").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    suite = unittest.defaultTestLoader.discover(str(root / "tests"))
    if suite.countTestCases() < 31:
        print("Build gate denied: security regression tests are missing.")
        return 2
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print("Build gate denied: a required Windows test was skipped.")
        return 2
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
