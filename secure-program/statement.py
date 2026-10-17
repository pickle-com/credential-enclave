"""The release statement of a secure-program-v* tag (docs/protocol.md, "The secure program release").

    python3 secure-program/statement.py --tag secure-program-v27 --commit <40 hex> [--source secure-program/secure-program.js]

Writes the canonical bytes of the statement to the standard output: the JSON object with exactly the
keys kind, release, version, sha256, git_commit, repository and path in this order, serialized without
white space, followed by one LF. The version is the `const VERSION = N;` line of the source and must
equal the N of the tag; otherwise the exit status is 2 and nothing is written. The module exposes
`canonical_statement` and `declared_version` for the monitor and for tests. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

KIND = "secure-program"
REPOSITORY = "pickle-com/credential-enclave"
PATH = "secure-program/secure-program.js"
TAG_PREFIX = "secure-program-v"
# The line of the source that declares the version: the first match in multi-line mode.
VERSION_RE = re.compile(r"^\s*const VERSION = (\d+);", re.MULTILINE)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def declared_version(source: bytes) -> int:
    """The version the source declares (`const VERSION = N;`), 0 when the line is absent."""
    match = VERSION_RE.search(source.decode("utf-8", errors="replace"))
    return int(match.group(1)) if match else 0


def canonical_statement(*, release: str, version: int, sha256_hex: str, git_commit: str) -> bytes:
    """The canonical bytes of the statement: seven keys in a fixed order, no white space, one LF."""
    statement = {
        "kind": KIND,
        "release": release,
        "version": version,
        "sha256": sha256_hex,
        "git_commit": git_commit,
        "repository": REPOSITORY,
        "path": PATH,
    }
    return json.dumps(statement, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="The release statement of a secure-program-v* tag.")
    parser.add_argument("--tag", required=True, help="the release tag, secure-program-v{N}")
    parser.add_argument("--commit", required=True, help="the commit the tag points to, 40 lower-case hex")
    parser.add_argument("--source", default=PATH, help=f"the program file (default {PATH})")
    arguments = parser.parse_args(argv)
    if not COMMIT_RE.match(arguments.commit):
        print(f"commit {arguments.commit!r} is not 40 lower-case hex characters", file=sys.stderr)
        return 2
    source = Path(arguments.source).read_bytes()
    version = declared_version(source)
    if arguments.tag != f"{TAG_PREFIX}{version}":
        print(f"tag {arguments.tag} does not match VERSION {version}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(
        canonical_statement(
            release=arguments.tag,
            version=version,
            sha256_hex=hashlib.sha256(source).hexdigest(),
            git_commit=arguments.commit,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
