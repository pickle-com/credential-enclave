"""The comparisons of the monitor (secure-program/monitor.py): which result an entry of the release
key gets, which result the transparency logs of the trusted root of Sigstore get, and which exit
status a run ends with.

    python3 -m unittest discover -s secure-program/tests -p 'test_*.py'
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

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


class RunTest(unittest.TestCase):
    def test_an_unexpected_failure_is_an_incomplete_run_and_not_an_unexplained_entry(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "report.md"
            with mock.patch.object(monitor, "main", side_effect=KeyError("body")):
                status = monitor.run(["--repository", "owner/name", "--report", str(report)])
            self.assertEqual(status, monitor.EXIT_INCOMPLETE)
            self.assertNotEqual(status, monitor.EXIT_UNEXPLAINED)
            self.assertIn("stopped before it finished the comparison", report.read_text())

    def test_an_unexpected_failure_of_the_trusted_root_form_is_an_incomplete_run(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "trusted-root.md"
            with mock.patch.object(monitor, "compare_trusted_root", side_effect=KeyError("tlogs")):
                status = monitor.run(["--trusted-root", "--report", str(report)])
            self.assertEqual(status, monitor.EXIT_INCOMPLETE)
            text = report.read_text()
            self.assertTrue(text.startswith("# Trusted root of Sigstore: transparency logs\n"), text)
            self.assertIn("stopped before it finished the comparison", text)


V1 = "https://rekor.sigstore.dev"
V2 = "https://log2025-1.rekor.sigstore.dev"
NEXT = "https://log2027-1.rekor.sigstore.dev"
NOW = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
LATER = "2036-01-01T00:00:00Z"


def log(number: int, address: str, *, end: str | None = None) -> dict:
    """A transparency log as a trusted root states it. `number` makes its key and its log
    identifier: 32 bytes of that value."""
    valid_for = {"start": "2021-01-12T11:53:27Z"}
    if end is not None:
        valid_for["end"] = end
    return {
        "baseUrl": address,
        "hashAlgorithm": "SHA2_256",
        "publicKey": {
            "rawBytes": base64.b64encode(bytes([number]) * 32).decode(),
            "keyDetails": "PKIX_ED25519",
            "validFor": valid_for,
        },
        "logId": {"keyId": base64.b64encode(bytes([number]) * 32).decode()},
    }


def identifier(number: int) -> str:
    return (bytes([number]) * 32).hex()


def trusted_root(*logs: dict, authorities: int = 2) -> bytes:
    """A trusted root that names `logs`, and other parts the monitor does not compare."""
    root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": list(logs),
        "certificateAuthorities": [{"uri": f"https://fulcio.example/{n}"} for n in range(authorities)],
    }
    return json.dumps(root).encode()


def differences(distributed: bytes, known: bytes) -> list[tuple[str, str, str]]:
    found = monitor.log_differences(
        monitor.transparency_logs(distributed, "the distributed trusted root"),
        monitor.transparency_logs(known, "the copy"),
    )
    return [(item.address, item.identifier, item.difference) for item in found]


class LogDifferencesTest(unittest.TestCase):
    def test_the_logs_of_the_copy_of_this_repository_are_read(self) -> None:
        copy = monitor.TRUSTED_ROOT_COPY.read_bytes()
        logs = monitor.transparency_logs(copy, "the copy")
        self.assertEqual(
            {entry["baseUrl"]: key for key, entry in logs.items()},
            {
                V1: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                V2: "cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0",
            },
        )
        self.assertEqual(differences(copy, copy), [])

    def test_a_trusted_root_with_the_same_logs_does_not_differ_whatever_its_other_parts(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        # Another order of the logs, and other certificate authorities.
        self.assertEqual(differences(trusted_root(log(2, V2), log(1, V1), authorities=3), known), [])

    def test_a_log_the_copy_does_not_name_differs(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        distributed = trusted_root(log(1, V1), log(2, V2), log(3, NEXT))
        self.assertEqual(differences(distributed, known), [(NEXT, identifier(3), "the copy does not name this log")])
        # A new log that is stated with the end of its validity says so.
        distributed = trusted_root(log(1, V1), log(2, V2), log(3, NEXT, end="2028-01-01T00:00:00Z"))
        self.assertEqual(
            differences(distributed, known),
            [(NEXT, identifier(3), "the copy does not name this log (the end of its validity: `2028-01-01T00:00:00Z`)")],
        )

    def test_an_end_of_the_validity_of_a_log_differs(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        distributed = trusted_root(log(1, V1, end="2027-11-01T00:00:00Z"), log(2, V2))
        self.assertEqual(
            differences(distributed, known),
            [(V1, identifier(1), "the end of its validity is `2027-11-01T00:00:00Z` (the copy: `not stated`)")],
        )
        # The copy that states the same end does not differ, and one that states another does.
        self.assertEqual(differences(distributed, distributed), [])
        other = trusted_root(log(1, V1, end="2027-12-01T00:00:00Z"), log(2, V2))
        self.assertEqual(
            differences(distributed, other),
            [(V1, identifier(1), "the end of its validity is `2027-11-01T00:00:00Z` (the copy: `2027-12-01T00:00:00Z`)")],
        )

    def test_a_log_the_trusted_root_no_longer_names_differs(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        self.assertEqual(
            differences(trusted_root(log(1, V1)), known),
            [(V2, identifier(2), "the trusted root no longer names this log")],
        )

    def test_another_value_of_a_log_differs(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        moved = log(2, "https://log2025-1.rekor.example")
        found = differences(trusted_root(log(1, V1), moved), known)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][:2], ("https://log2025-1.rekor.example", identifier(2)))
        self.assertTrue(found[0][2].startswith("another value than in the copy: `{"), found[0][2])

    def test_a_trusted_root_of_another_shape_is_not_compared(self) -> None:
        twice = trusted_root(log(1, V1), log(1, V2))
        for root in [b"", b"[]", b"{}", b'{"tlogs": {}}', b'{"tlogs": [{}]}', b'{"tlogs": [{"logId": {"keyId": "?"}}]}', twice]:
            with self.assertRaises(ValueError, msg=root):
                monitor.transparency_logs(root, "the trusted root")


class Repository:
    """A stand-in for the TUF repository: the documents it serves, by address."""

    def __init__(self, root: bytes, *, expires: str = LATER, further: tuple[str, ...] = ()) -> None:
        digest = hashlib.sha256(root).hexdigest()
        listed = {monitor.TRUSTED_ROOT_TARGET: {"length": len(root), "hashes": {"sha256": digest}}}
        listed.update({name: {"length": 1, "hashes": {"sha256": "00" * 32}} for name in further})
        listed["rekor.pub"] = {"length": 178, "hashes": {"sha256": "11" * 32}}
        self.documents: dict[str, bytes] = {}
        self.put("timestamp.json", "timestamp", 9, expires, {"meta": {"snapshot.json": {"version": 5}}})
        self.put("5.snapshot.json", "snapshot", 5, LATER, {"meta": {"targets.json": {"version": 3}}})
        self.put("3.targets.json", "targets", 3, LATER, {"targets": listed})
        self.documents[f"{monitor.TUF_REPOSITORY}/targets/{digest}.{monitor.TRUSTED_ROOT_TARGET}"] = root
        self.asked: list[str] = []

    def put(self, name: str, role: str, version: int, expires: str, values: dict) -> None:
        signed = {"_type": role, "spec_version": "1.0", "version": version, "expires": expires, **values}
        self.documents[f"{monitor.TUF_REPOSITORY}/{name}"] = json.dumps({"signed": signed, "signatures": []}).encode()

    def get(self, method: str, url: str, body: dict | None = None, headers: dict | None = None) -> bytes:
        self.asked.append(url)
        if method != "GET" or url not in self.documents:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        return self.documents[url]


class DistributedTrustedRootTest(unittest.TestCase):
    def read(self, repository: Repository) -> monitor.Distributed:
        with mock.patch.object(monitor, "http_with_retries", side_effect=repository.get):
            return monitor.distributed_trusted_root(NOW)

    def test_the_trusted_root_is_the_target_the_metadata_names(self) -> None:
        root = trusted_root(log(1, V1))
        repository = Repository(root)
        distributed = self.read(repository)
        self.assertEqual(distributed.content, root)
        self.assertEqual(distributed.versions, {"timestamp": 9, "snapshot": 5, "targets": 3})
        self.assertEqual(distributed.other_targets, [])
        base = monitor.TUF_REPOSITORY
        self.assertEqual(
            repository.asked,
            [
                f"{base}/timestamp.json",
                f"{base}/5.snapshot.json",
                f"{base}/3.targets.json",
                f"{base}/targets/{hashlib.sha256(root).hexdigest()}.trusted_root.json",
            ],
        )

    def test_a_further_target_that_is_named_a_trusted_root_is_reported(self) -> None:
        repository = Repository(trusted_root(log(1, V1)), further=("trusted_root.v0.2.json",))
        self.assertEqual(self.read(repository).other_targets, ["trusted_root.v0.2.json"])

    def test_a_file_that_is_not_the_one_the_metadata_names_is_not_read(self) -> None:
        root = trusted_root(log(1, V1))
        repository = Repository(root)
        address = f"{monitor.TUF_REPOSITORY}/targets/{hashlib.sha256(root).hexdigest()}.trusted_root.json"
        for served in [trusted_root(log(1, V1), log(3, NEXT)), root + b" "]:
            repository.documents[address] = served
            with self.assertRaises(ValueError):
                self.read(repository)

    def test_metadata_past_its_time_or_of_another_version_or_shape_is_no_answer(self) -> None:
        root = trusted_root(log(1, V1))
        with self.assertRaises(ValueError):
            self.read(Repository(root, expires="2026-11-23T12:00:00Z"))
        self.read(Repository(root, expires="2026-11-23T12:00:01Z"))
        # The snapshot the timestamp names is version 5, and the file served under it says 6.
        repository = Repository(root)
        repository.put("5.snapshot.json", "snapshot", 6, LATER, {"meta": {"targets.json": {"version": 3}}})
        with self.assertRaises(ValueError):
            self.read(repository)
        # Metadata of another role, without the version of the next file, and without a
        # trusted root among its targets.
        for name, role, version, values in [
            ("timestamp.json", "snapshot", 9, {"meta": {"snapshot.json": {"version": 5}}}),
            ("timestamp.json", "timestamp", 9, {"meta": {}}),
            ("5.snapshot.json", "snapshot", 5, {"meta": {"targets.json": {"version": "3"}}}),
            ("3.targets.json", "targets", 3, {"targets": {}}),
            ("3.targets.json", "targets", 3, {"targets": {"trusted_root.json": {"hashes": {"sha256": "../x"}}}}),
        ]:
            repository = Repository(root)
            repository.put(name, role, version, LATER, values)
            with self.assertRaises(ValueError, msg=name):
                self.read(repository)

    def test_a_request_that_fails_is_its_own_error(self) -> None:
        repository = Repository(trusted_root(log(1, V1)))
        del repository.documents[f"{monitor.TUF_REPOSITORY}/5.snapshot.json"]
        with self.assertRaises(urllib.error.HTTPError):
            self.read(repository)


class CompareTrustedRootTest(unittest.TestCase):
    def compare(self, repository: Repository, known: bytes) -> tuple[int, str]:
        """The exit status and the report of the trusted root form, with `known` as the copy of
        this repository."""
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder) / "sigstore-trusted-root.json"
            copy.write_bytes(known)
            report = Path(folder) / "trusted-root.md"
            with mock.patch.object(monitor, "http_with_retries", side_effect=repository.get), mock.patch.object(
                monitor, "TRUSTED_ROOT_COPY", copy
            ), mock.patch("builtins.print"):
                status = monitor.run(["--trusted-root", "--report", str(report)])
            return status, report.read_text()

    def test_the_logs_of_the_copy_end_the_run_with_the_status_of_known_logs(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        status, report = self.compare(Repository(trusted_root(log(1, V1), log(2, V2), authorities=5)), known)
        self.assertEqual(status, monitor.EXIT_KNOWN_LOGS)
        self.assertIn("The transparency logs of the trusted root are the ones of the copy.", report)
        self.assertIn("The signatures of the metadata were not checked.", report)
        self.assertNotIn("## What differs", report)

    def test_other_logs_end_the_run_with_the_status_of_other_logs_and_are_named(self) -> None:
        known = trusted_root(log(1, V1), log(2, V2))
        distributed = trusted_root(log(1, V1, end="2027-11-01T00:00:00Z"), log(2, V2), log(3, NEXT))
        status, report = self.compare(Repository(distributed), known)
        self.assertEqual(status, monitor.EXIT_OTHER_LOGS)
        self.assertIn(f"| {NEXT} | `{identifier(3)}` | the copy does not name this log |", report)
        self.assertIn(
            f"| {V1} | `{identifier(1)}` | the end of its validity is `2027-11-01T00:00:00Z` (the copy: `not stated`) |",
            report,
        )
        self.assertIn(hashlib.sha256(distributed).hexdigest(), report)
        self.assertIn(hashlib.sha256(known).hexdigest(), report)

    def test_a_further_trusted_root_target_ends_the_run_with_the_status_of_other_logs(self) -> None:
        known = trusted_root(log(1, V1))
        status, report = self.compare(Repository(known, further=("trusted_root.v0.2.json",)), known)
        self.assertEqual(status, monitor.EXIT_OTHER_LOGS)
        self.assertIn("a further trusted root under the name `trusted_root.v0.2.json`", report)

    def test_a_repository_that_cannot_be_read_leaves_the_run_incomplete(self) -> None:
        known = trusted_root(log(1, V1))
        gone = Repository(known)
        gone.documents.clear()
        expired = Repository(known, expires="2020-01-01T00:00:00Z")
        misshapen = Repository(b'{"tlogs": 5}')
        for repository in [gone, expired, misshapen]:
            status, report = self.compare(repository, known)
            self.assertEqual(status, monitor.EXIT_INCOMPLETE)
            self.assertIn("The trusted root could not be read from the TUF repository", report)
            self.assertNotIn("## What differs", report)

    def test_a_copy_of_another_shape_leaves_the_run_incomplete(self) -> None:
        status, report = self.compare(Repository(trusted_root(log(1, V1))), b'{"tlogs": 5}')
        self.assertEqual(status, monitor.EXIT_INCOMPLETE)
        self.assertIn("stopped before it finished the comparison", report)


if __name__ == "__main__":
    unittest.main()
