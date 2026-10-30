#!/usr/bin/env python3
"""Regression tests for 1.6a(b): the claimed step page must exist as a file.

`python3 -m unittest discover -s scripts/tests` (from `core-v2/`).

The bug (step 1.6 red): the agent answered `STEP 1 OK page=1` without calling
any ksg tool — no page-1.json was ever written — and the orchestrator took
the line at face value. Now demo_orchestrator.sh sources
scripts/lib/verify_step_page.sh and rejects a claimed page with no file
behind it. These tests call the REAL lib function (no reimplementation).
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parent.parent / "lib" / "verify_step_page.sh"


def verify(work, page):
    """Run the real verify_step_page() from the lib file."""
    r = subprocess.run(
        ["bash", "-c", '. "$1"; verify_step_page "$2" "$3"',
         "test-harness", str(LIB), str(work), str(page)],
        capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def make_box(work, name="c-abc123", pages=(1,), current=True):
    box = Path(work) / name
    (box / "h").mkdir(parents=True)
    for p in pages:
        (box / f"page-{p}.json").write_text('{"page": %d}' % p)
    if current:
        (Path(work) / ".current").write_text(name)
    return box


class VerifyStepPageTest(unittest.TestCase):
    def test_claimed_page_present_is_ok(self):
        with tempfile.TemporaryDirectory() as d:
            box = make_box(d, pages=(1, 2))
            rc, out = verify(d, "1")
            self.assertEqual(rc, 0)
            self.assertEqual(out, str(box))

    def test_claimed_page_missing_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            make_box(d, pages=(1,))
            # agent claims page=2, but only page-1.json exists
            rc, _ = verify(d, "2")
            self.assertNotEqual(rc, 0)

    def test_no_current_falls_back_to_newest_box(self):
        with tempfile.TemporaryDirectory() as d:
            make_box(d, name="c-old", pages=(9,), current=False)
            import time
            time.sleep(0.02)
            make_box(d, name="c-new", pages=(4,), current=False)
            rc, out = verify(d, "4")
            self.assertEqual(rc, 0)
            self.assertTrue(out.endswith("c-new"))

    def test_no_box_at_all_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _ = verify(d, "1")
            self.assertNotEqual(rc, 0)

    def test_empty_page_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            make_box(d, pages=(1,))
            rc, _ = verify(d, "")
            self.assertNotEqual(rc, 0)

    def test_stale_current_falls_back_to_newest_box(self):
        # .current points at a removed box: newest c-* wins.
        with tempfile.TemporaryDirectory() as d:
            make_box(d, name="c-gone", pages=(1,), current=True)
            import shutil, time
            shutil.rmtree(os.path.join(d, "c-gone"))
            time.sleep(0.02)
            make_box(d, name="c-fresh", pages=(5,), current=False)
            rc, out = verify(d, "5")
            self.assertEqual(rc, 0)
            self.assertTrue(out.endswith("c-fresh"))


if __name__ == "__main__":
    unittest.main()
