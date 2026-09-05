"""Guards against the test count stated in README.md, the docs, and the
screenshot explanations drifting from what pytest actually collects --
the same kind of drift tests/test_reference_db.py guards against, just
for the suite's own size instead of the fingerprint database. Re-collects
the whole suite fresh on every run (this file included) so the figure
checked here is never stale from its own addition."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOC_FILES = [
    ROOT / "README.md",
    ROOT / "docs" / "IMPLEMENTATION.md",
    ROOT / "docs" / "PROJECT_REPORT.md",
    ROOT / "screenshots" / "EXPLANATIONS.md",
]

_STATED_COUNT_RE = re.compile(r"(\d+)\s+(?:automated\s+)?tests?\b|(\d+)\s+passed\b")


def _actual_test_count() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    match = re.search(r"(\d+) tests collected", result.stdout)
    assert match, f"could not parse a collected count from:\n{result.stdout}\n{result.stderr}"
    return int(match.group(1))


def _stated_counts(path: Path) -> list[int]:
    text = path.read_text(encoding="utf-8")
    return [int(m.group(1) or m.group(2)) for m in _STATED_COUNT_RE.finditer(text)]


def test_every_doc_states_at_least_one_test_count():
    for path in DOC_FILES:
        assert _stated_counts(path), (
            f"found no '<number> tests'/'<number> passed' figure in "
            f"{path.relative_to(ROOT)} -- did the wording change?"
        )


def test_every_stated_test_count_matches_pytest_collection():
    actual = _actual_test_count()
    for path in DOC_FILES:
        for stated in _stated_counts(path):
            assert stated == actual, (
                f"{path.relative_to(ROOT)} states {stated} tests, but "
                f"pytest actually collects {actual}"
            )
