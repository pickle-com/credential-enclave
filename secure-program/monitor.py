"""The monitor of the public transparency log (docs/protocol.md, "The secure program release").

    python3 secure-program/monitor.py --repository OWNER/NAME --report PATH

Every entry of Rekor (rekor.sigstore.dev) that the release key of the operator signed must be the
statement of a release of this repository: an enclave release (a `v*` tag, whose statement is the
bytes of the `measurements.json` of its GitHub release) or a secure program release (a
`secure-program-v*` tag, whose statement is `statement.py` of that tag). The script asks the log for
the entries of the release key, hashes the known statements, compares, and writes a Markdown report.
The exit status is 1 when an entry is unknown or the log could not be read, otherwise 0. Standard
library only. The structural guarantee of the apps does not rest on this monitor: an app loads a
program only with its own verification of the entry. The monitor tells people about an entry that
no release explains.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import statement as statement_module

REKOR = "https://rekor.sigstore.dev"
RELEASE_KEY = Path(__file__).resolve().parents[1] / "enclave" / "release" / "release-key.pem"
TIMEOUT_SECONDS = 60


def git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], check=True, capture_output=True, text=True).stdout.strip()


def http(method: str, url: str, body: dict | None = None) -> bytes:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read()


def known_statements(repository: str, report: list[str]) -> dict[str, str]:
    """SHA-256 hex of every known statement -> the release it belongs to."""
    known: dict[str, str] = {}
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
        known[hashlib.sha256(statement).hexdigest()] = tag
    for tag in git("tag", "--list", "v*").split():
        url = f"https://github.com/{repository}/releases/download/{tag}/measurements.json"
        try:
            measurements = http("GET", url)
        except (urllib.error.URLError, OSError) as error:
            report.append(f"- `{tag}`: no `measurements.json` on its GitHub release ({error})")
            continue
        known[hashlib.sha256(measurements).hexdigest()] = tag
    return known


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Compares the entries of the release key with the releases.")
    parser.add_argument("--repository", required=True, help="OWNER/NAME of this repository on GitHub")
    parser.add_argument("--report", required=True, help="the Markdown report to write")
    arguments = parser.parse_args(argv)
    pem = RELEASE_KEY.read_bytes()
    report: list[str] = ["# Transparency log monitor", ""]
    failed = False
    try:
        uuids = json.loads(
            http(
                "POST",
                f"{REKOR}/api/v1/index/retrieve",
                {"publicKey": {"format": "x509", "content": base64.b64encode(pem).decode()}},
            )
        )
    except (urllib.error.URLError, OSError, ValueError) as error:
        report.append(f"The log could not be searched for the release key: {error}")
        Path(arguments.report).write_text("\n".join(report) + "\n")
        return 1
    missing_tags: list[str] = []
    known = known_statements(arguments.repository, missing_tags)
    known_rows: list[str] = []
    unknown_rows: list[str] = []
    for uuid in uuids if isinstance(uuids, list) else []:
        try:
            entries = json.loads(http("GET", f"{REKOR}/api/v1/log/entries/{uuid}"))
        except (urllib.error.URLError, OSError, ValueError) as error:
            unknown_rows.append(f"| ? | ? | ? | entry `{uuid}` could not be read: {error} |")
            failed = True
            continue
        for entry in entries.values():
            body = json.loads(base64.b64decode(entry["body"]))
            signature = body.get("spec", {}).get("signature", {})
            logged_key = base64.b64decode(signature.get("publicKey", {}).get("content", ""))
            digest = body.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
            index = entry.get("logIndex")
            link = f"https://search.sigstore.dev/?logIndex={index}"
            if logged_key.strip() != pem.strip():
                unknown_rows.append(f"| {index} | `{digest}` | {entry.get('integratedTime')} | another public key, {link} |")
                failed = True
            elif digest in known:
                known_rows.append(f"| {index} | `{known[digest]}` | {entry.get('integratedTime')} | {link} |")
            else:
                unknown_rows.append(f"| {index} | `{digest}` | {entry.get('integratedTime')} | {link} |")
                failed = True
    report.append(f"Entries of the release key: {len(uuids) if isinstance(uuids, list) else 0}")
    report.append("")
    report.append("## Known entries")
    report.append("")
    report.append("| Log index | Release | Integrated time | Link |")
    report.append("| --- | --- | --- | --- |")
    report.extend(known_rows)
    report.append("")
    report.append("## Unknown entries")
    report.append("")
    if unknown_rows:
        report.append("| Log index | Statement hash | Integrated time | Link |")
        report.append("| --- | --- | --- | --- |")
        report.extend(unknown_rows)
    else:
        report.append("None.")
    if missing_tags:
        report.append("")
        report.append("## Tags without a release statement")
        report.append("")
        report.extend(missing_tags)
    Path(arguments.report).write_text("\n".join(report) + "\n")
    print("\n".join(report))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
