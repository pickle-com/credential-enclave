"""The element of an enclave release in the list of accepted measurements
(secure-program/accept_release.py): what the command writes into the program, and which exit
status the comparison with a measurements file ends with.

    python3 -m unittest discover -s secure-program/tests -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import accept_release  # noqa: E402

PROGRAM = Path(__file__).resolve().parents[1] / "secure-program.js"
# The measurement of a build of release v2.4.0 made before its tag (two machines gave the same
# three values). The values the program lists are read from the measurements.json of the release.
MEASURED = {
    "release": "v2.4.0",
    "git_commit": "ae0f7cf9f83e18579d0e32962c56e4b1a573f1d0",
    "pcr0": "0c892a8673c6015572f9fa6b23bd9e2f95c9485e8aee702fcb8007789dd57b081f4a252ab68b22e40285030721484c36",
    "pcr1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
    "pcr2": "fef17df65a52e302a32c419df2815377991faf79f7d8cc983a6fdec3d1d3e0b15d18f8ffea92a6da5bf1c49e69b8debd",
    "inputs": {},
}


class AcceptReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        # The program as it is checked in, without an element of the release of the test.
        source = PROGRAM.read_text(encoding="utf-8")
        held = accept_release.element_of(source, MEASURED["release"])
        if held is not None:
            start, end = accept_release.list_bounds(source)
            body = source[start:end]
            source = source[:start] + body[:body.index("    {\n      release: \"" + MEASURED["release"] + "\"")] + source[end:]
        self.source = Path(self.folder.name) / "secure-program.js"
        self.source.write_text(source, encoding="utf-8")
        self.listed = [item["release"] for item in accept_release.listed_releases(source)]

    def measurements(self, **changed: object) -> str:
        path = Path(self.folder.name) / "measurements.json"
        path.write_text(json.dumps({**MEASURED, **changed}), encoding="utf-8")
        return str(path)

    def run_command(self, *arguments: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = accept_release.main(["--source", str(self.source), *arguments])
        return status, out.getvalue(), err.getvalue()

    def test_the_element_of_a_release_is_put_at_the_end_of_the_list_and_compared(self) -> None:
        status, out, _ = self.run_command("--check", "--measurements", self.measurements())
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        status, out, _ = self.run_command("--measurements", self.measurements())
        self.assertEqual(status, 0)
        self.assertIn("release v2.4.0: pcr0 " + MEASURED["pcr0"], out)
        written = self.source.read_text(encoding="utf-8")
        listed = accept_release.listed_releases(written)
        self.assertEqual([item["release"] for item in listed], self.listed + ["v2.4.0"])
        self.assertEqual({name: listed[-1][name] for name in ("pcr0", "pcr1", "pcr2")},
                         {name: MEASURED[name] for name in ("pcr0", "pcr1", "pcr2")})
        # The element has the form of the elements before it, and the comment that marked its
        # place is gone.
        self.assertIn(
            "    // pickle-com/credential-enclave v2.4.0 (commit " + MEASURED["git_commit"] + ").\n"
            "    {\n      release: \"v2.4.0\",\n      pcr0: \"" + MEASURED["pcr0"] + "\",\n      pcr1: \"" + MEASURED["pcr1"] +
            "\",\n      pcr2: \"" + MEASURED["pcr2"] + "\",\n      log_store: true,\n    },\n  ];\n", written)
        self.assertNotIn("The place of the element of release v2.4.0", written)
        # The comparison alone, and the same command once more: the list is left as it is.
        self.assertEqual(self.run_command("--check", "--measurements", self.measurements())[0], 0)
        self.assertEqual(self.run_command("--measurements", self.measurements())[0], 0)
        self.assertEqual(self.source.read_text(encoding="utf-8"), written)

    def test_a_list_that_holds_other_values_for_the_release_is_not_equal_and_is_not_written(self) -> None:
        self.assertEqual(self.run_command("--measurements", self.measurements())[0], 0)
        written = self.source.read_text(encoding="utf-8")
        other = self.measurements(pcr0="1" + MEASURED["pcr0"][1:])
        status, out, err = self.run_command("--check", "--measurements", other)
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertIn("pcr0 of release v2.4.0", err)
        self.assertEqual(self.run_command("--measurements", other)[0], 2)
        self.assertEqual(self.source.read_text(encoding="utf-8"), written)

    def test_a_file_that_has_not_the_form_writes_nothing(self) -> None:
        before = self.source.read_text(encoding="utf-8")
        for changed in (
            {"release": "2.4.0"}, {"release": "v2.4"}, {"git_commit": "ae0f7cf"}, {"pcr0": MEASURED["pcr0"].upper()},
            {"pcr1": MEASURED["pcr1"][:95]}, {"pcr2": None},
        ):
            self.assertEqual(self.run_command("--measurements", self.measurements(**changed))[0], 2, changed)
            self.assertEqual(self.source.read_text(encoding="utf-8"), before, changed)
        # The three values of a release the list holds, under another release name.
        first = accept_release.listed_releases(before)[0]
        again = self.measurements(release="v9.9.9", pcr0=first["pcr0"], pcr1=first["pcr1"], pcr2=first["pcr2"])
        self.assertEqual(self.run_command("--measurements", again)[0], 2)
        self.assertEqual(self.source.read_text(encoding="utf-8"), before)

    def test_a_release_without_a_marked_place_becomes_the_last_element(self) -> None:
        status, _, _ = self.run_command("--measurements", self.measurements(release="v2.5.0"))
        self.assertEqual(status, 0)
        written = self.source.read_text(encoding="utf-8")
        self.assertEqual([item["release"] for item in accept_release.listed_releases(written)], self.listed + ["v2.5.0"])


if __name__ == "__main__":
    unittest.main()
