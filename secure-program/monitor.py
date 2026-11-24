"""The monitor of the public transparency log (docs/protocol.md, "The secure program release").

    python3 secure-program/monitor.py --repository OWNER/NAME --report PATH
    python3 secure-program/monitor.py --trusted-root --report PATH

The first form compares the entries of the release key with the releases. Every entry of Rekor
(rekor.sigstore.dev) that the release key of the operator signed must be the statement of a release
of this repository: an enclave release (a `v*` tag, whose statement is the bytes of the
`measurements.json` of its GitHub release) or a secure program release (a `secure-program-v*` tag,
whose statement is `statement.py` of that tag). The script asks the log for the entries of the
release key, hashes the known statements, compares, and writes a Markdown report.

The exit status tells three results apart:

    0  every entry of the release key is the statement of a release
    1  an entry is the statement of no release, or carries another public key
    2  the comparison is not complete: the log could not be searched, an entry could not be read,
       an entry matches no statement that was read while the statement of at least one release
       could not be read (that entry may belong to that release), or the script stopped on an
       error it did not expect

A statement that could not be read is not the same as an entry that no release explains: the script
reads a statement again before it gives up (`READ_ATTEMPTS`), and an entry that it could not compare
with every release is reported as not checked, not as unknown.

The second form compares the transparency logs and the certificate authorities of the trusted root
of the public instance of Sigstore with the ones this repository knows (docs/protocol.md 9.3 and
10.3). A node takes the public build proof of another release only under values that are compiled
into it: the two certificates of the certificate authority of Sigstore, under which the certificate
of the proof was issued, and the key of the transparency log `rekor.sigstore.dev`, which recorded
the proof. A test ties those values to the copy of the trusted root in
`protocol/tests/fixtures/sigstore-trusted-root.json` (`enclave/src/lineage.rs`). A release that is
built after the certificate authority changed its certificates, or after that log stopped taking
entries or changed its key, has no proof a node in service takes, so a release that holds the new
values has to be built and deployed while the proofs of new releases still verify under the values
of the nodes in service. The script reads the trusted root that the TUF repository of Sigstore
distributes and compares its `tlogs` and its `certificateAuthorities` with the ones of that copy: a
log under its log identifier, a certificate authority under the certificates of its chain. The exit
status:

    0  the transparency logs and the certificate authorities of the trusted root are the ones of
       the copy
    1  the trusted root names a log or a certificate authority the copy does not name, no longer
       names one of the copy, states another value for one (the end of its validity among them),
       or the TUF repository distributes a further trusted root under another name
    2  the comparison is not complete: the TUF repository could not be read, its metadata is past
       its time, the trusted root is not the file its metadata names or has another shape than
       expected, or the script stopped on an error it did not expect

The other parts of the trusted root (the certificate transparency logs, the timestamp authorities)
are not compared: no check of a public build proof reads them (docs/protocol.md 9.4).

The script reads the metadata of the TUF repository without a check of its signatures, as it reads
the entries of the log without a check of the signatures of the log: it follows the versions and
the hash the metadata states, and it takes metadata that is past its time for no answer.

Standard library only. The structural guarantee of the apps and of the nodes does not rest on this
monitor: an app loads a program only with its own verification of the entry, and a node takes a
public build proof only under the certificates and the log key that are compiled into it. The
monitor tells people about an entry that no release explains, and about a trusted root whose logs
or certificate authorities this repository does not know.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import statement as statement_module

REKOR = "https://rekor.sigstore.dev"
GITHUB_API = "https://api.github.com"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_KEY = REPOSITORY_ROOT / "enclave" / "release" / "release-key.pem"
STATEMENT_ASSET = "measurements.json"
# The TUF repository of the public instance of Sigstore, and the target that is its trusted root.
TUF_REPOSITORY = "https://tuf-repo-cdn.sigstore.dev"
TRUSTED_ROOT_TARGET = "trusted_root.json"
# The copy of that trusted root this repository holds: a test of the node program ties the two
# certificates of the certificate authority and the key of the transparency log that the node
# program compiles in to it (enclave/src/lineage.rs).
TRUSTED_ROOT_COPY = REPOSITORY_ROOT / "protocol" / "tests" / "fixtures" / "sigstore-trusted-root.json"
TRUSTED_ROOT_COPY_NAME = "protocol/tests/fixtures/sigstore-trusted-root.json"
TRUSTED_ROOT_TITLE = "# Trusted root of Sigstore: transparency logs and certificate authorities"
TIMEOUT_SECONDS = 60
# A request that failed for a reason that can pass (a gateway error, a timeout) is sent again:
# this many attempts in all, with these pauses between them.
READ_ATTEMPTS = 4
RETRY_PAUSES_SECONDS = (2, 5, 15)

EXIT_EXPLAINED = 0
EXIT_UNEXPLAINED = 1
EXIT_INCOMPLETE = 2
# The comparison of the trusted root: its transparency logs and its certificate authorities are
# the ones of the copy, or not.
EXIT_KNOWN_ROOT = 0
EXIT_OTHER_ROOT = 1


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


@dataclass
class Distributed:
    """The trusted root the TUF repository distributes: its bytes, the versions of the metadata
    that name it (`timestamp`, `snapshot`, `targets`), and the other targets of the repository
    whose name says that they are a trusted root."""

    content: bytes
    versions: dict[str, int]
    other_targets: list[str]


def _signed(role: str, document: bytes, now: datetime, version: int | None = None) -> dict:
    """The `signed` part of the metadata of `role`. Raises ValueError when the document has another
    shape, is the metadata of another role or of another version than the one that was asked for,
    or is past its time: metadata that is past its time says nothing about what the repository
    distributes now."""
    metadata = json.loads(document)
    signed = metadata.get("signed") if isinstance(metadata, dict) else None
    if not isinstance(signed, dict) or signed.get("_type") != role:
        raise ValueError(f"the {role} metadata of the TUF repository has another shape than expected")
    if version is not None and signed.get("version") != version:
        raise ValueError(f"the {role} metadata of the TUF repository is not version {version}")
    try:
        expires = datetime.strptime(signed["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"the {role} metadata of the TUF repository states no end of its time") from error
    if now >= expires:
        raise ValueError(f"the {role} metadata of the TUF repository is past its time ({signed['expires']})")
    return signed


def _named_version(signed: dict, name: str) -> int:
    """The version of the metadata file `name` that `signed` names."""
    meta = signed.get("meta")
    version = meta.get(name, {}).get("version") if isinstance(meta, dict) else None
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError(f"the {signed.get('_type')} metadata of the TUF repository names no version of {name}")
    return version


def distributed_trusted_root(now: datetime) -> Distributed:
    """Reads the trusted root the TUF repository distributes at `now`: the timestamp names the
    version of the snapshot, the snapshot the version of the targets, and the targets the hash and
    the length of the trusted root, which the repository serves under that hash. No signature of
    the metadata is checked. Raises ValueError when the metadata is not what this chain expects or
    the trusted root is not the file the metadata names, and the error of a request that failed."""
    timestamp = _signed("timestamp", http_with_retries("GET", f"{TUF_REPOSITORY}/timestamp.json"), now)
    snapshot_version = _named_version(timestamp, "snapshot.json")
    snapshot = _signed(
        "snapshot",
        http_with_retries("GET", f"{TUF_REPOSITORY}/{snapshot_version}.snapshot.json"),
        now,
        snapshot_version,
    )
    targets_version = _named_version(snapshot, "targets.json")
    targets = _signed(
        "targets",
        http_with_retries("GET", f"{TUF_REPOSITORY}/{targets_version}.targets.json"),
        now,
        targets_version,
    )
    listed = targets.get("targets")
    target = listed.get(TRUSTED_ROOT_TARGET) if isinstance(listed, dict) else None
    hashes = target.get("hashes") if isinstance(target, dict) else None
    digest = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"the targets metadata of the TUF repository names no {TRUSTED_ROOT_TARGET}")
    content = http_with_retries("GET", f"{TUF_REPOSITORY}/targets/{digest}.{TRUSTED_ROOT_TARGET}")
    if hashlib.sha256(content).hexdigest() != digest or len(content) != target.get("length"):
        raise ValueError("the trusted root of the TUF repository is not the file its metadata names")
    others = sorted(name for name in listed if name != TRUSTED_ROOT_TARGET and "trusted_root" in name)
    versions = {"timestamp": timestamp.get("version"), "snapshot": snapshot_version, "targets": targets_version}
    return Distributed(content=content, versions=versions, other_targets=others)


def transparency_logs(root: bytes, name: str) -> dict[str, dict]:
    """The transparency logs a trusted root names (`tlogs`), by log identifier: the lower-case
    hexadecimal of `logId.keyId`. Raises ValueError, with `name` for the trusted root, when it has
    another shape than expected or names one log identifier twice."""
    try:
        logs = json.loads(root)["tlogs"]
        if not isinstance(logs, list):
            raise TypeError("`tlogs` is not a list")
        by_identifier: dict[str, dict] = {}
        for log in logs:
            identifier = base64.b64decode(log["logId"]["keyId"], validate=True).hex()
            if not identifier or identifier in by_identifier or not isinstance(log["baseUrl"], str):
                raise ValueError(f"the log {identifier or 'without an identifier'}")
            by_identifier[identifier] = log
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"{name} has another shape than expected ({type(error).__name__}: {error})") from error
    return by_identifier


def certificate_authorities(root: bytes, name: str) -> dict[str, dict]:
    """The certificate authorities a trusted root names (`certificateAuthorities`), by their
    certificate chain: the lower-case hexadecimal SHA-256 of the DER of every certificate of
    `certChain.certificates`, in the order of the trusted root, joined by one space. Raises
    ValueError, with `name` for the trusted root, when it has another shape than expected or names
    one chain twice."""
    try:
        authorities = json.loads(root)["certificateAuthorities"]
        if not isinstance(authorities, list):
            raise TypeError("`certificateAuthorities` is not a list")
        by_chain: dict[str, dict] = {}
        for authority in authorities:
            certificates = authority["certChain"]["certificates"]
            if not isinstance(certificates, list) or not certificates:
                raise ValueError("a certificate authority without a certificate")
            digests: list[str] = []
            for certificate in certificates:
                der = base64.b64decode(certificate["rawBytes"], validate=True)
                if not der:
                    raise ValueError("a certificate without bytes")
                digests.append(hashlib.sha256(der).hexdigest())
            chain = " ".join(digests)
            if chain in by_chain or not isinstance(authority["uri"], str):
                raise ValueError(f"the certificate authority of the certificates {chain}")
            by_chain[chain] = authority
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"{name} has another shape than expected ({type(error).__name__}: {error})") from error
    return by_chain


def _validity_of_log(log: dict) -> dict | None:
    """The validity of the key of a log (`publicKey.validFor`), when the trusted root states it."""
    key = log.get("publicKey")
    valid_for = key.get("validFor") if isinstance(key, dict) else None
    return valid_for if isinstance(valid_for, dict) else None


def _validity_of_authority(authority: dict) -> dict | None:
    """The validity of a certificate authority (`validFor`), when the trusted root states it."""
    valid_for = authority.get("validFor")
    return valid_for if isinstance(valid_for, dict) else None


@dataclass
class Difference:
    """One difference between a transparency log or a certificate authority of the trusted root
    that is distributed and the same one of the copy of this repository. `address` is the address
    the trusted root states for it. `identifier` is the log identifier of a log, and the
    certificates of the chain of a certificate authority."""

    address: str
    identifier: str
    difference: str


def _differences(
    distributed: dict[str, dict],
    known: dict[str, dict],
    *,
    noun: str,
    address: str,
    validity: Callable[[dict], dict | None],
) -> list[Difference]:
    """What the items of one part of the distributed trusted root state otherwise than those of
    the copy, in the order of their identifiers: an item the copy does not name, an item of the
    copy that the trusted root no longer names, an end of the validity that the copy does not state
    (or states otherwise), and every other value of an item that differs. `noun` names an item in
    the texts, `address` is the key of its address, and `validity` gives the object that holds the
    end of its validity."""

    def end(item: dict) -> str | None:
        valid_for = validity(item)
        return valid_for.get("end") if valid_for is not None else None

    def without_end(item: dict) -> dict:
        copy = json.loads(json.dumps(item))
        valid_for = validity(copy)
        if valid_for is not None:
            valid_for.pop("end", None)
        return copy

    differences: list[Difference] = []
    for identifier in sorted(distributed.keys() | known.keys()):
        theirs, ours = distributed.get(identifier), known.get(identifier)
        texts: list[str] = []
        if ours is None:
            stated = end(theirs)
            texts.append(
                f"the copy does not name this {noun}" + (f" (the end of its validity: `{stated}`)" if stated else "")
            )
        elif theirs is None:
            texts.append(f"the trusted root no longer names this {noun}")
        else:
            if end(theirs) != end(ours):
                texts.append(
                    f"the end of its validity is `{end(theirs) or 'not stated'}`"
                    f" (the copy: `{end(ours) or 'not stated'}`)"
                )
            if without_end(theirs) != without_end(ours):
                texts.append(f"another value than in the copy: `{json.dumps(theirs, sort_keys=True)}`")
        stated_address = (theirs or ours)[address]
        differences += [Difference(address=stated_address, identifier=identifier, difference=text) for text in texts]
    return differences


def log_differences(distributed: dict[str, dict], known: dict[str, dict]) -> list[Difference]:
    """What the transparency logs of the distributed trusted root state otherwise than those of
    the copy, in the order of the log identifiers: a log the copy does not name, a log of the copy
    that the trusted root no longer names, an end of the validity of a log that the copy does not
    state (or states otherwise), and every other value of a log that differs."""
    return _differences(distributed, known, noun="log", address="baseUrl", validity=_validity_of_log)


def authority_differences(distributed: dict[str, dict], known: dict[str, dict]) -> list[Difference]:
    """What the certificate authorities of the distributed trusted root state otherwise than those
    of the copy, in the order of the certificates of their chains: a certificate authority the copy
    does not name, one of the copy that the trusted root no longer names, an end of the validity of
    one that the copy does not state (or states otherwise), and every other value of one that
    differs. A certificate authority whose chain holds another certificate is another certificate
    authority: the one of the copy is no longer named, and the copy does not name the new one."""
    return _differences(
        distributed, known, noun="certificate authority", address="uri", validity=_validity_of_authority
    )


def render_trusted_root(
    distributed: Distributed, known: bytes, logs: list[Difference], authorities: list[Difference]
) -> list[str]:
    versions = distributed.versions
    report = [
        TRUSTED_ROOT_TITLE,
        "",
        f"Read from the TUF repository {TUF_REPOSITORY}: the target `{TRUSTED_ROOT_TARGET}`"
        f" (SHA-256 `{hashlib.sha256(distributed.content).hexdigest()}`) of the targets metadata of"
        f" version {versions['targets']} (snapshot {versions['snapshot']}, timestamp {versions['timestamp']})."
        " The signatures of the metadata were not checked.",
        "",
        f"Compared with `{TRUSTED_ROOT_COPY_NAME}` (SHA-256 `{hashlib.sha256(known).hexdigest()}`).",
        "",
    ]
    if not logs and not authorities and not distributed.other_targets:
        report.append(
            "The transparency logs and the certificate authorities of the trusted root are the ones of the copy."
        )
        return report
    report += ["## What differs", ""]
    if logs:
        report += ["| Log | Log identifier | Difference |", "| --- | --- | --- |"]
        report += [f"| {item.address} | `{item.identifier}` | {item.difference} |" for item in logs]
        report.append("")
    if authorities:
        report += [
            "| Certificate authority | Certificates of its chain (SHA-256 of the DER) | Difference |",
            "| --- | --- | --- |",
        ]
        report += [
            f"| {item.address} | {' '.join(f'`{digest}`' for digest in item.identifier.split(' '))} | {item.difference} |"
            for item in authorities
        ]
        report.append("")
    if distributed.other_targets:
        report += [
            f"- the TUF repository distributes a further trusted root under the name `{name}`"
            for name in distributed.other_targets
        ]
        report.append("")
    report += [
        "## What follows",
        "",
        "A node takes the public build proof of another release only under values that are compiled"
        " into it: the two certificates of the certificate authority of Sigstore and the key of the"
        " transparency log `rekor.sigstore.dev` (docs/protocol.md 9.3, docs/enclave.md 11.1). A"
        " release that is built after the certificate authority changed its certificates, or after"
        " that log stopped taking entries or changed its key, has no proof a node in service takes"
        " (docs/protocol.md 10.3), so a release that holds the new values is built and deployed"
        " while the proofs of new releases still verify under the values of the nodes in service."
        f" Read the trusted root again, replace `{TRUSTED_ROOT_COPY_NAME}`, and bring the files of"
        " `enclave/release/` and the test of `enclave/src/lineage.rs` in step with it.",
    ]
    return report


def compare_trusted_root(report_path: str) -> int:
    """The second form of the script: compares the transparency logs and the certificate
    authorities of the trusted root the TUF repository distributes with the ones of the copy of
    this repository, and writes the report."""
    heading = [TRUSTED_ROOT_TITLE, ""]
    try:
        distributed = distributed_trusted_root(datetime.now(timezone.utc))
        name = "the trusted root of the TUF repository"
        logs = transparency_logs(distributed.content, name)
        authorities = certificate_authorities(distributed.content, name)
    except (urllib.error.URLError, OSError, ValueError) as error:
        report = heading + [f"The trusted root could not be read from the TUF repository {TUF_REPOSITORY}: {error}"]
        Path(report_path).write_text("\n".join(report) + "\n")
        print("\n".join(report))
        return EXIT_INCOMPLETE
    known = TRUSTED_ROOT_COPY.read_bytes()
    copy = f"`{TRUSTED_ROOT_COPY_NAME}`"
    other_logs = log_differences(logs, transparency_logs(known, copy))
    other_authorities = authority_differences(authorities, certificate_authorities(known, copy))
    report = render_trusted_root(distributed, known, other_logs, other_authorities)
    Path(report_path).write_text("\n".join(report) + "\n")
    print("\n".join(report))
    differs = other_logs or other_authorities or distributed.other_targets
    return EXIT_OTHER_ROOT if differs else EXIT_KNOWN_ROOT


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Compares the entries of the release key with the releases, or the transparency"
        " logs and the certificate authorities of the trusted root of Sigstore with the ones this"
        " repository knows."
    )
    parser.add_argument("--repository", help="OWNER/NAME of this repository on GitHub")
    parser.add_argument(
        "--trusted-root",
        action="store_true",
        help="compare the transparency logs and the certificate authorities of the trusted root of"
        " Sigstore instead of the entries",
    )
    parser.add_argument("--report", required=True, help="the Markdown report to write")
    arguments = parser.parse_args(argv)
    if arguments.trusted_root:
        return compare_trusted_root(arguments.report)
    if not arguments.repository:
        parser.error("--repository is required unless --trusted-root is given")
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
    comparison. The exit status 1 means one thing only in each form, an entry that no release
    explains or a trusted root whose logs or certificate authorities are not the ones of the copy:
    a run that stopped on an error it did not expect (a `git` command that failed, an answer of
    another shape) must not end with that status, which is also the status of an uncaught Python
    error."""
    try:
        return main(argv)
    except Exception as error:  # noqa: BLE001 - every unexpected failure is an incomplete run
        report = [
            TRUSTED_ROOT_TITLE if "--trusted-root" in argv else "# Transparency log monitor",
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
