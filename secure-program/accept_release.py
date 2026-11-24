"""The element of an enclave release in the list of accepted measurements of the secure program.

    python3 secure-program/accept_release.py --measurements measurements.json [--source secure-program/secure-program.js] [--check]

`measurements.json` is the file of that name of the GitHub release of an enclave tag of this
repository: an object with `release`, `git_commit`, `pcr0`, `pcr1` and `pcr2` (README, "A release").
The program accepts the nodes of a release when `const ACCEPTED_RELEASES = [...]` of
`secure-program.js` holds the element of that release (docs/protocol.md 4.5).

Without `--check` the command puts the element of the release into the list, in the form of the
elements before it, and then compares what the list holds with the file. The element takes the
place the list marks for it (a comment that begins "The place of the element of release {release}");
without such a comment it becomes the last element. A list that holds the release with the three
values of the file already is left as it is.

With `--check` the command writes nothing and compares: the list holds an element of the release
of the file, and its three values are the three of the file.

Exit status 0: the list holds the element of the file (one line on the standard output says so).
Exit status 1: the list does not hold the release, or holds it with another value (`--check`).
Exit status 2: an input that has not the form (a release that is not v{major}.{minor}.{patch}, a
value that is not 96 lower-case hexadecimal characters, a commit that is not 40), a source without
the list, or a list that holds the release with other values (nothing is written).
The module exposes `listed_releases` and `with_release` for tests. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PATH = "secure-program/secure-program.js"
LIST_START = "  const ACCEPTED_RELEASES = [\n"
LIST_END = "  ];\n"
RELEASE_RE = re.compile(r"^v\d+\.\d+\.\d+$")
PCR_RE = re.compile(r"^[0-9a-f]{96}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ELEMENT_RE = re.compile(
    r'\{\s*release:\s*"([^"]+)",\s*pcr0:\s*"([0-9a-f]{96})",\s*pcr1:\s*"([0-9a-f]{96})",\s*pcr2:\s*"([0-9a-f]{96})",')


class Refused(Exception):
    """An input that has not the form, or a list that holds the release with other values."""


def list_bounds(source: str) -> tuple[int, int]:
    """The offsets of the text between the opening line of the list and its closing line."""
    start = source.find(LIST_START)
    if start < 0:
        raise Refused("the source holds no list of accepted releases")
    start += len(LIST_START)
    end = source.find(LIST_END, start)
    if end < 0:
        raise Refused("the list of accepted releases does not end")
    return start, end


def listed_releases(source: str) -> list[dict[str, str]]:
    """The elements of the list of accepted releases, in order: release, pcr0, pcr1 and pcr2.
    A line of a comment is no part of an element."""
    start, end = list_bounds(source)
    body = "\n".join(line for line in source[start:end].split("\n") if not line.lstrip().startswith("//"))
    return [
        {"release": match.group(1), "pcr0": match.group(2), "pcr1": match.group(3), "pcr2": match.group(4)}
        for match in ELEMENT_RE.finditer(body)
    ]


def read_measurements(text: str) -> dict[str, str]:
    """The release, the commit and the three values of a measurements.json, checked for their form."""
    try:
        data = json.loads(text)
    except ValueError as error:
        raise Refused(f"the measurements file is no JSON: {error}") from error
    if not isinstance(data, dict):
        raise Refused("the measurements file is no JSON object")
    values = {name: data.get(name) for name in ("release", "git_commit", "pcr0", "pcr1", "pcr2")}
    if not isinstance(values["release"], str) or not RELEASE_RE.match(values["release"]):
        raise Refused(f"release {values['release']!r} is not v{{major}}.{{minor}}.{{patch}}")
    if not isinstance(values["git_commit"], str) or not COMMIT_RE.match(values["git_commit"]):
        raise Refused(f"git_commit {values['git_commit']!r} is not 40 lower-case hexadecimal characters")
    for name in ("pcr0", "pcr1", "pcr2"):
        if not isinstance(values[name], str) or not PCR_RE.match(values[name]):
            raise Refused(f"{name} {values[name]!r} is not 96 lower-case hexadecimal characters")
    return values


def element_of(source: str, release: str) -> dict[str, str] | None:
    """The element of the release in the list, None when the list holds none. A list that holds
    the release more than once is refused."""
    found = [item for item in listed_releases(source) if item["release"] == release]
    if len(found) > 1:
        raise Refused(f"the list holds release {release} {len(found)} times")
    return found[0] if found else None


def same(element: dict[str, str], measured: dict[str, str]) -> bool:
    return all(element[name] == measured[name] for name in ("pcr0", "pcr1", "pcr2"))


def with_release(source: str, measured: dict[str, str]) -> str:
    """The source with the element of the measured release in its list. A list that holds the
    release with the same values is returned as it is, and one that holds it with other values,
    or holds the three values under another release, is refused."""
    held = element_of(source, measured["release"])
    if held is not None:
        if same(held, measured):
            return source
        raise Refused(f"the list holds release {measured['release']} with other values")
    for item in listed_releases(source):
        if same(item, measured):
            raise Refused(f"the list holds the three values under release {item['release']}")
    start, end = list_bounds(source)
    body = source[start:end]
    element = (
        f"    // pickle-com/credential-enclave {measured['release']} (commit {measured['git_commit']}).\n"
        "    {\n"
        f"      release: \"{measured['release']}\",\n"
        f"      pcr0: \"{measured['pcr0']}\",\n"
        f"      pcr1: \"{measured['pcr1']}\",\n"
        f"      pcr2: \"{measured['pcr2']}\",\n"
        "      log_store: true,\n"
        "    },\n"
    )
    # The place the list marks for the element: the comment that begins with these words, up to
    # the end of the list.
    marker = f"    // The place of the element of release {measured['release']}"
    place = body.find(marker)
    if place >= 0:
        rest = body[place:]
        if any(line.strip() != "" and not line.lstrip().startswith("//") for line in rest.split("\n")):
            raise Refused("an element follows the place the list marks for the release")
        body = body[:place]
    return source[:start] + body + element + source[end:]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="The element of an enclave release in the list of accepted measurements.")
    parser.add_argument("--measurements", required=True, help="the measurements.json of the GitHub release of the enclave tag")
    parser.add_argument("--source", default=PATH, help=f"the program file (default {PATH})")
    parser.add_argument("--check", action="store_true", help="write nothing: compare the list with the file")
    arguments = parser.parse_args(argv)
    path = Path(arguments.source)
    try:
        measured = read_measurements(Path(arguments.measurements).read_text(encoding="utf-8"))
        source = path.read_text(encoding="utf-8")
        if not arguments.check:
            written = with_release(source, measured)
            if written != source:
                path.write_text(written, encoding="utf-8")
            source = path.read_text(encoding="utf-8")
        held = element_of(source, measured["release"])
    except Refused as error:
        print(str(error), file=sys.stderr)
        return 2
    if held is None:
        print(f"the list holds no release {measured['release']}", file=sys.stderr)
        return 1
    if not same(held, measured):
        for name in ("pcr0", "pcr1", "pcr2"):
            if held[name] != measured[name]:
                print(f"{name} of release {measured['release']} in the list is {held[name]}, in the file {measured[name]}", file=sys.stderr)
        return 1
    print(f"release {measured['release']}: pcr0 {held['pcr0']}, pcr1 {held['pcr1']}, pcr2 {held['pcr2']}: "
          f"the list of {arguments.source} holds the three values of {arguments.measurements}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
