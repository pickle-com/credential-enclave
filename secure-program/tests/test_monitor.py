"""The comparison of the monitor (secure-program/monitor.py): which result an entry of the release
key gets, and which exit status the run ends with.

    python3 -m unittest discover -s secure-program/tests -p 'test_*.py'
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import monitor  # noqa: E402


def entry(digest: str, *, index: int = 1, same_key: bool = True) -> monitor.Entry:
    return monitor.Entry(index=index, digest=digest, integrated_time=1790000000, same_key=same_key)


class CompareTest(unittest.TestCase):
    def test_an_entry_of_a_release_is_explained(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0", "bb": "secure-program-v42"})
        comparison = monitor.compare([entry("aa"), entry("bb", index=2)], statements)
        self.assertEqual([release for _, release in comparison.explained], ["v2.3.0", "secure-program-v42"])
        self.assertEqual(comparison.exit_status(0), monitor.EXIT_EXPLAINED)

    def test_an_entry_of_no_release_is_unexplained_when_every_statement_was_read(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"}, absent=["v1.5.1"])
        comparison = monitor.compare([entry("aa"), entry("cc", index=2)], statements)
        self.assertEqual([item.digest for item in comparison.unexplained], ["cc"])
        self.assertEqual(comparison.not_checked, [])
        self.assertEqual(comparison.exit_status(0), monitor.EXIT_UNEXPLAINED)

    def test_an_unmatched_entry_is_not_checked_while_a_statement_could_not_be_read(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"}, unread={"v1.3.0": "HTTP Error 504"})
        comparison = monitor.compare([entry("aa"), entry("cc", index=2)], statements)
        self.assertEqual(comparison.unexplained, [])
        self.assertEqual([item.digest for item in comparison.not_checked], ["cc"])
        self.assertEqual(comparison.exit_status(0), monitor.EXIT_INCOMPLETE)

    def test_an_unread_statement_of_a_release_without_an_entry_leaves_the_run_complete(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"}, unread={"v1.0.0": "timed out"})
        comparison = monitor.compare([entry("aa")], statements)
        self.assertEqual(comparison.exit_status(0), monitor.EXIT_EXPLAINED)

    def test_an_entry_of_another_key_is_unexplained_even_when_its_statement_is_known(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"}, unread={"v1.3.0": "timed out"})
        comparison = monitor.compare([entry("aa", same_key=False)], statements)
        self.assertEqual(len(comparison.other_key), 1)
        self.assertEqual(comparison.exit_status(0), monitor.EXIT_UNEXPLAINED)

    def test_an_entry_that_could_not_be_read_leaves_the_run_incomplete(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"})
        comparison = monitor.compare([entry("aa")], statements)
        self.assertEqual(comparison.exit_status(1), monitor.EXIT_INCOMPLETE)

    def test_an_unexplained_entry_outranks_an_incomplete_comparison(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"})
        comparison = monitor.compare([entry("cc")], statements)
        self.assertEqual(comparison.exit_status(1), monitor.EXIT_UNEXPLAINED)


class RenderTest(unittest.TestCase):
    def test_the_report_names_an_unread_statement_apart_from_an_unexplained_entry(self) -> None:
        statements = monitor.Statements(known={"aa": "v2.3.0"}, unread={"v1.3.0": "HTTP Error 504"})
        comparison = monitor.compare([entry("aa"), entry("cc", index=2)], statements)
        report = "\n".join(monitor.render(2, comparison, statements, []))
        unexplained = report.split("## Entries that no release explains")[1].split("##")[0]
        self.assertIn("None.", unexplained)
        self.assertIn("## Not checked in this run", report)
        self.assertIn("`v1.3.0`: HTTP Error 504", report)


if __name__ == "__main__":
    unittest.main()
