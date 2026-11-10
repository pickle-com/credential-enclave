"""The monitor of the public transparency log (docs/protocol.md, "The secure program release").

    python3 secure-program/monitor.py --repository OWNER/NAME --report PATH

Every entry of Rekor (rekor.sigstore.dev) that the release key of the operator signed must be the
statement of a release of this repository: an enclave release (a `v*` tag, whose statement is the
bytes of the `measurements.json` of its GitHub release) or a secure program release (a
`secure-program-v*` tag, whose statement is `statement.py` of that tag). The script asks the log for
the entries of the release key, hashes the known statements, compares, and writes a Markdown report.

The exit status tells three results apart:

    0  every entry of the release key is the statement of a release
    1  an entry is the statement of no release, or carries another public key
    2  the comparison is not complete: the log could not be searched, an entry could not be read,
       an entry matches no statement that was read while the statement of at least one release
       could not be read (that entry may belong to that release), or the script stopped on an
       error it did not expect

A statement that could not be read is not the same as an entry that no release explains: the script
reads a statement again before it gives up (`READ_ATTEMPTS`), and an entry that it could not compare
with every release is reported as not checked, not as unknown. Standard library only. The structural
guarantee of the apps does not rest on this monitor: an app loads a program only with its own
verification of the entry. The monitor tells people about an entry that no release explains.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import statement as statement_module

REKOR = "https://rekor.sigstore.dev"
GITHUB_API = "https://api.github.com"
RELEASE_KEY = Path(__file__).resolve().parents[1] / "enclave" / "release" / "release-key.pem"
STATEMENT_ASSET = "measurements.json"
TIMEOUT_SECONDS = 60
# A request that failed for a reason that can pass (a gateway error, a timeout) is sent again:
# this many attempts in all, with these pauses between them.
READ_ATTEMPTS = 4
RETRY_PAUSES_SECONDS = (2, 5, 15)

EXIT_EXPLAINED = 0
EXIT_UNEXPLAINED = 1
EXIT_INCOMPLETE = 2


class _DropAuthorizationOnRedirect(urllib.request.HTTPRedirectHandler):
    """GitHub answers the request for a release asset with a redirect to a signed address on
    another host. The token of the API must not travel to that host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_host = urllib.parse.urlsplit(req.full_url).hostname
            new_host = urllib.parse.urlsplit(newurl).hostname
            if old_host != new_host:
                new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_DropAuthorizationOnRedirect)


def git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], check=True, capture_output=True, text=True).stdout.strip()


def http(method: str, url: str, body: dict | None = None, headers: dict | None = None) -> bytes:
    """One request. Raises urllib.error.HTTPError with the status of a 4xx or 5xx answer."""
    data = None if body is None else json.dumps(body).encode()
    request_headers = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read()


def http_with_retries(method: str, url: str, body: dict | None = None, headers: dict | None = None) -> bytes:
    """The request, sent again after a failure that can pass. A 404 is an answer, not a failure
    that can pass: it is raised at once."""
    for attempt in range(READ_ATTEMPTS):
        try:
            return http(method, url, body, headers)
        except urllib.error.HTTPError as error:
            if error.code == 404 or attempt == READ_ATTEMPTS - 1:
                raise
        except (urllib.error.URLError, OSError):
            if attempt == READ_ATTEMPTS - 1:
                raise
        time.sleep(RETRY_PAUSES_SECONDS[min(attempt, len(RETRY_PAUSES_SECONDS) - 1)])
    raise AssertionError("unreachable")


def enclave_statement(repository: str, tag: str, token: str) -> bytes | None:
    """The bytes of `measurements.json` of the GitHub release of the tag, or None when the tag has
    no GitHub release or the release has no such file. Raises when the answer could not be read.

    With a token the script asks the API of GitHub (the release of the tag, then the asset); without
    one it reads the public download address, which needs no account."""
    if not token:
        url = f"https://github.com/{repository}/releases/download/{tag}/{STATEMENT_ASSET}"
        try:
            return http_with_retries("GET", url)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
    authorization = {"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}
    try:
        release = json.loads(
            http_with_retries(
                "GET",
                f"{GITHUB_API}/repos/{repository}/releases/tags/{urllib.parse.quote(tag, safe='')}",
                headers={"Accept": "application/vnd.github+json", **authorization},
            )
        )
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    for asset in release.get("assets", []):
        if asset.get("name") == STATEMENT_ASSET:
            return http_with_retries(
                "GET", asset["url"], headers={"Accept": "application/octet-stream", **authorization}
            )
    return None


@dataclass
class Statements:
    """What the releases of the repository say: the SHA-256 hex of every statement that was read
    (-> its release), the tags that have no statement, and the tags whose statement could not be
    read in this run (-> the reason)."""

    known: dict[str, str] = field(default_factory=dict)
    absent: list[str] = field(default_factory=list)
    unread: dict[str, str] = field(default_factory=dict)


def release_statements(repository: str, token: str) -> Statements:
    statements = Statements()
    for tag in git("tag", "--list", "secure-program-v*").split():
        commit = git("rev-parse", f"{tag}^{{commit}}")
        source = subprocess.run(
            ["git", "show", f"{tag}:{statement_module.PATH}"], check=True, capture_output=True
        ).stdout
        statement = statement_module.canonical_statement(
            release=tag,
            version=statement_module.declared_version(source),
            sha256_hex=hashlib.sha256(source).hexdigest(),
            git_commit=commit,
        )
        statements.known[hashlib.sha256(statement).hexdigest()] = tag
    for tag in git("tag", "--list", "v*").split():
        try:
            measurements = enclave_statement(repository, tag, token)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            statements.unread[tag] = str(error)
            continue
        if measurements is None:
            statements.absent.append(tag)
        else:
            statements.known[hashlib.sha256(measurements).hexdigest()] = tag
    return statements


@dataclass
class Entry:
    """One entry of the log under the release key. `digest` is the SHA-256 hex of the statement it
    signs; `same_key` is false when the entry carries another public key than the release key."""

    index: int | str
    digest: str
    integrated_time: int | str
    same_key: bool


@dataclass
class Comparison:
    explained: list[tuple[Entry, str]] = field(default_factory=list)
    unexplained: list[Entry] = field(default_factory=list)
    other_key: list[Entry] = field(default_factory=list)
    not_checked: list[Entry] = field(default_factory=list)

    def exit_status(self, unreadable_entries: int) -> int:
        if self.unexplained or self.other_key:
            return EXIT_UNEXPLAINED
        if self.not_checked or unreadable_entries:
            return EXIT_INCOMPLETE
        return EXIT_EXPLAINED


def compare(entries: list[Entry], statements: Statements) -> Comparison:
    """An entry whose statement is the statement of a release is explained. An entry that matches no
    statement is unexplained only when every release statement was read: while the statement of a
    release could not be read, such an entry is not checked (it may be the entry of that release)."""
    comparison = Comparison()
    for entry in entries:
        if not entry.same_key:
            comparison.other_key.append(entry)
        elif entry.digest in statements.known:
            comparison.explained.append((entry, statements.known[entry.digest]))
        elif statements.unread:
            comparison.not_checked.append(entry)
        else:
            comparison.unexplained.append(entry)
    return comparison


def log_entries(pem: bytes) -> tuple[list[Entry], list[str]]:
    """The entries of the release key, and the identifiers of the entries that could not be read
    (with the reason). Raises when the log could not be searched."""
    uuids = json.loads(
        http_with_retries(
            "POST",
            f"{REKOR}/api/v1/index/retrieve",
            {"publicKey": {"format": "x509", "content": base64.b64encode(pem).decode()}},
        )
    )
    if not isinstance(uuids, list):
        raise ValueError("the answer of the log is not a list of entries")
    entries: list[Entry] = []
    unreadable: list[str] = []
    for uuid in uuids:
        try:
            answer = json.loads(http_with_retries("GET", f"{REKOR}/api/v1/log/entries/{uuid}"))
        except (urllib.error.URLError, OSError, ValueError) as error:
            unreadable.append(f"`{uuid}`: {error}")
            continue
        try:
            for logged in answer.values():
                body = json.loads(base64.b64decode(logged["body"]))
                signature = body.get("spec", {}).get("signature", {})
                logged_key = base64.b64decode(signature.get("publicKey", {}).get("content", ""))
                entries.append(
                    Entry(
                        index=logged.get("logIndex", "?"),
                        digest=body.get("spec", {}).get("data", {}).get("hash", {}).get("value", ""),
                        integrated_time=logged.get("integratedTime", "?"),
                        same_key=logged_key.strip() == pem.strip(),
                    )
                )
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            unreadable.append(f"`{uuid}`: the entry has another shape than expected ({type(error).__name__}: {error})")
    return entries, unreadable


def _link(entry: Entry) -> str:
    return f"https://search.sigstore.dev/?logIndex={entry.index}"


def render(
    total: int, comparison: Comparison, statements: Statements, unreadable: list[str]
) -> list[str]:
    report = ["# Transparency log monitor", "", f"Entries of the release key: {total}", ""]
    report += ["## Entries of a release", "", "| Log index | Release | Integrated time | Link |", "| --- | --- | --- | --- |"]
    report += [
        f"| {entry.index} | `{release}` | {entry.integrated_time} | {_link(entry)} |"
        for entry, release in comparison.explained
    ]
    report += ["", "## Entries that no release explains", ""]
    if comparison.unexplained or comparison.other_key:
        report += ["| Log index | Statement hash | Integrated time | Link |", "| --- | --- | --- | --- |"]
        report += [
            f"| {entry.index} | `{entry.digest}` | {entry.integrated_time} | {_link(entry)} |"
            for entry in comparison.unexplained
        ]
        report += [
            f"| {entry.index} | `{entry.digest}` | {entry.integrated_time} | another public key, {_link(entry)} |"
            for entry in comparison.other_key
        ]
    else:
        report.append("None.")
    if comparison.not_checked or unreadable or statements.unread:
        report += ["", "## Not checked in this run", ""]
        if statements.unread:
            report.append(
                "The statement of these releases could not be read, so an entry that matches no other"
                " release was not compared with them:"
            )
            report.append("")
            report += [f"- `{tag}`: {reason}" for tag, reason in statements.unread.items()]
            report.append("")
        if comparison.not_checked:
            report += ["| Log index | Statement hash | Integrated time | Link |", "| --- | --- | --- | --- |"]
            report += [
                f"| {entry.index} | `{entry.digest}` | {entry.integrated_time} | {_link(entry)} |"
                for entry in comparison.not_checked
            ]
            report.append("")
        report += [f"- entry {reason}" for reason in unreadable]
    if statements.absent:
        report += ["", "## Tags without a release statement", ""]
        report += [f"- `{tag}`: no `{STATEMENT_ASSET}` on a GitHub release of the tag" for tag in statements.absent]
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Compares the entries of the release key with the releases.")
    parser.add_argument("--repository", required=True, help="OWNER/NAME of this repository on GitHub")
    parser.add_argument("--report", required=True, help="the Markdown report to write")
    arguments = parser.parse_args(argv)
    pem = RELEASE_KEY.read_bytes()
    token = os.environ.get("GH_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
    try:
        entries, unreadable = log_entries(pem)
    except (urllib.error.URLError, OSError, ValueError) as error:
        report = ["# Transparency log monitor", "", f"The log could not be searched for the release key: {error}"]
        Path(arguments.report).write_text("\n".join(report) + "\n")
        print("\n".join(report))
        return EXIT_INCOMPLETE
    statements = release_statements(arguments.repository, token)
    comparison = compare(entries, statements)
    report = render(len(entries) + len(unreadable), comparison, statements, unreadable)
    Path(arguments.report).write_text("\n".join(report) + "\n")
    print("\n".join(report))
    return comparison.exit_status(len(unreadable))


def run(argv: list[str]) -> int:
    """`main`, with a failure that is not a result of the comparison reported as an incomplete
    comparison. The exit status 1 means one thing only, an entry that no release explains: a run
    that stopped on an error it did not expect (a `git` command that failed, an answer of another
    shape) must not end with that status, which is also the status of an uncaught Python error."""
    try:
        return main(argv)
    except Exception as error:  # noqa: BLE001 - every unexpected failure is an incomplete run
        report = [
            "# Transparency log monitor",
            "",
            f"The monitor stopped before it finished the comparison: {type(error).__name__}: {error}",
        ]
        print("\n".join(report))
        traceback.print_exc()
        if "--report" in argv[:-1]:
            Path(argv[argv.index("--report") + 1]).write_text("\n".join(report) + "\n")
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
