#!/usr/bin/env python3
"""Makes protocol/vectors/release-proofs.json: release proofs with the verdict of each.

Release proofs are the public build proof of a measurement (docs/protocol.md section 9):
{"statement": b64u(release statement), "attestation": Sigstore bundle}. Two programs verify
them, the node (protocol/src/release_proofs.rs) and the secure program of the app
(secure-program/secure-program.js), and both give the verdict of this file on every case.

    python3 protocol/vectors/release_proofs.py            writes the file
    python3 protocol/vectors/release_proofs.py --check    fails when the file differs

The cases are of two kinds.

- The proofs of published releases: the files of protocol/vectors/published/, which are the
  assets measurements.json and release-statement.sigstore.json of a GitHub release of this
  repository, and such proofs with one value changed. They are verified with the certificates
  of Sigstore and the key of Rekor. No key of this file signs them, so a changed value is
  refused by the first check it breaks.
- Proofs this file makes with keys of its own: a certificate authority of a root and an
  intermediate certificate, a transparency log of the form Rekor v1 and the key of each
  workflow run. Every part of such a case is signed and recorded as for proofs that hold,
  except the one value the case changes, so the check the case names is the one it fails.

Every private key is derived from a fixed label and every ECDSA signature is deterministic
(RFC 6979), so a second run writes the same bytes. The keys are trusted by nothing but the
cases of this file that name them.

The file shares no code with either verifier. It needs Python 3.11 or later and the package
`cryptography` 43 or later, linked with OpenSSL 3.2 or later (for the deterministic signatures).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parent.parent
OUTPUT = HERE / "release-proofs.json"
PUBLISHED = HERE / "published"
RELEASE_VALUES = REPOSITORY_ROOT / "enclave" / "release"

# ---- Bytes ----


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def fixed(label: str, length: int = 32) -> bytes:
    """Bytes for a label: the same on every run."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            b"credential-enclave release proofs vectors v1\n"
            + label.encode()
            + b"\n"
            + bytes([counter])
        ).digest()
        counter += 1
    return out[:length]


def compact(value) -> str:
    """JSON without white space, as `jq --compact-output` and JSON.stringify write it."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


# ---- Keys and signatures ----

CURVES = {
    "p256": (
        ec.SECP256R1(),
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
    "p384": (
        ec.SECP384R1(),
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    ),
}
HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


class Key:
    """An ECDSA key pair whose private key follows from a label."""

    def __init__(self, label: str, curve: str = "p256"):
        named, order = CURVES[curve]
        scalar = int.from_bytes(fixed("key " + label, 64), "big") % (order - 1) + 1
        self.curve = curve
        self.private = ec.derive_private_key(scalar, named)
        self.spki = self.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        point = self.private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        # The subject key identifier of a certificate of this key.
        self.identifier = hashlib.sha1(point).digest()

    def sign(self, message: bytes, hash_name: str = "sha256") -> bytes:
        """The ASN.1 DER signature of the key over a message."""
        return self.private.sign(
            message, ec.ECDSA(HASHES[hash_name](), deterministic_signing=True)
        )


# ---- DER ----


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    digits = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(digits)]) + digits


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_length(len(content)) + content


def der_sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def der_integer(value: int) -> bytes:
    digits = value.to_bytes(value.bit_length() // 8 + 1, "big")
    return tlv(0x02, digits)


def der_oid(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    content = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        digits = [part & 0x7F]
        part >>= 7
        while part:
            digits.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        content += bytes(digits)
    return tlv(0x06, content)


def der_utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode())


def der_printable(text: str) -> bytes:
    return tlv(0x13, text.encode("ascii"))


def der_boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")


def der_octets(content: bytes) -> bytes:
    return tlv(0x04, content)


def der_bits(content: bytes) -> bytes:
    return tlv(0x03, b"\x00" + content)


def der_explicit(number: int, content: bytes) -> bytes:
    return tlv(0xA0 | number, content)


def der_utc_time(seconds: int) -> bytes:
    """A UTCTime of seconds since 1970."""
    from datetime import datetime, timezone

    moment = datetime.fromtimestamp(seconds, timezone.utc)
    return tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())


def der_generalized_time(seconds: int) -> bytes:
    """A GeneralizedTime of seconds since 1970."""
    from datetime import datetime, timezone

    moment = datetime.fromtimestamp(seconds, timezone.utc)
    return tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode())


OID = {
    "ecdsa-sha256": "1.2.840.10045.4.3.2",
    "ecdsa-sha384": "1.2.840.10045.4.3.3",
    "organization": "2.5.4.10",
    "common-name": "2.5.4.3",
    "key-usage": "2.5.29.15",
    "extended-key-usage": "2.5.29.37",
    "code-signing": "1.3.6.1.5.5.7.3.3",
    "basic-constraints": "2.5.29.19",
    "subject-key-identifier": "2.5.29.14",
    "authority-key-identifier": "2.5.29.35",
    "subject-alternative-name": "2.5.29.17",
    "fulcio": "1.3.6.1.4.1.57264.1",
}


def der_name(organization: str, common_name: str) -> bytes:
    return der_sequence(
        der_set(der_sequence(der_oid(OID["organization"]), der_printable(organization))),
        der_set(der_sequence(der_oid(OID["common-name"]), der_printable(common_name))),
    )


def der_extension(name: str, value: bytes, critical: bool = False) -> bytes:
    oid = der_oid(OID[name] if name in OID else name)
    parts = [oid] + ([der_boolean(True)] if critical else []) + [der_octets(value)]
    return der_sequence(*parts)


def pem(label: str, der: bytes) -> str:
    text = b64(der)
    lines = "\n".join(text[at : at + 64] for at in range(0, len(text), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def certificate(
    *,
    key: Key,
    signer: Key,
    subject: bytes,
    issuer: bytes,
    not_before: int,
    not_after: int,
    extensions: list[bytes],
    serial: str,
    hash_name: str = "sha384",
    time=der_utc_time,
) -> bytes:
    """An X.509 certificate of version 3 in DER."""
    algorithm = der_sequence(der_oid(OID["ecdsa-" + hash_name]))
    number = int.from_bytes(fixed("serial " + serial, 20), "big") >> 1 | 1 << 152
    signed = der_sequence(
        der_explicit(0, der_integer(2)),
        der_integer(number),
        algorithm,
        issuer,
        der_sequence(time(not_before), time(not_after)),
        subject,
        key.spki,
        der_explicit(3, der_sequence(*extensions)),
    )
    return der_sequence(signed, algorithm, der_bits(signer.sign(signed, hash_name)))


# ---- The certificate authority ----

KEY_USAGE_SIGN_CERTIFICATES = bytes.fromhex("03020106")
KEY_USAGE_SIGN = bytes.fromhex("03020780")
CODE_SIGNING = der_sequence(der_oid(OID["code-signing"]))


def authority_key(identifier: bytes) -> bytes:
    return der_sequence(tlv(0x80, identifier))


class Authority:
    """A certificate authority of two certificates, as the public instance of Sigstore has: a
    root that signed itself and an intermediate the root signed, both on P-384, with the
    extensions of the two certificates of Sigstore."""

    def __init__(
        self,
        label: str,
        *,
        not_before: int = 1_600_000_000,
        not_after: int = 1_950_000_000,
        intermediate_authority: bool = True,
        root_key: Key | None = None,
    ):
        self.label = label
        self.root_key = root_key or Key(label + " root", "p384")
        self.intermediate_key = Key(label + " intermediate", "p384")
        self.root_name = der_name("vectors.test", "vectors-root")
        self.intermediate_name = der_name("vectors.test", "vectors-intermediate")
        self.root = certificate(
            key=self.root_key,
            signer=self.root_key,
            subject=self.root_name,
            issuer=self.root_name,
            not_before=not_before,
            not_after=not_after,
            serial=label + " root",
            extensions=[
                der_extension("key-usage", KEY_USAGE_SIGN_CERTIFICATES, True),
                der_extension("basic-constraints", der_sequence(der_boolean(True)), True),
                der_extension("subject-key-identifier", der_octets(self.root_key.identifier)),
                der_extension(
                    "authority-key-identifier", authority_key(self.root_key.identifier)
                ),
            ],
        )
        constraints = (
            der_sequence(der_boolean(True), der_integer(0))
            if intermediate_authority
            else der_sequence()
        )
        self.intermediate = certificate(
            key=self.intermediate_key,
            signer=self.root_key,
            subject=self.intermediate_name,
            issuer=self.root_name,
            not_before=not_before,
            not_after=not_after,
            serial=label + " intermediate",
            extensions=[
                der_extension("key-usage", KEY_USAGE_SIGN_CERTIFICATES, True),
                der_extension("extended-key-usage", CODE_SIGNING),
                der_extension("basic-constraints", constraints, True),
                der_extension(
                    "subject-key-identifier", der_octets(self.intermediate_key.identifier)
                ),
                der_extension(
                    "authority-key-identifier", authority_key(self.root_key.identifier)
                ),
            ],
        )

    def issue(
        self,
        key: Key,
        texts: dict[int, str],
        *,
        serial: str,
        not_before: int = 1_795_000_000,
        not_after: int = 1_795_000_600,
        signer: Key | None = None,
        issuer: bytes | None = None,
        authority: bool = False,
        hash_name: str = "sha384",
        more: list[bytes] | None = None,
        time=der_utc_time,
    ) -> bytes:
        """The certificate of a workflow run for a key, with the extensions of a certificate
        Fulcio issues: valid for ten minutes, an empty subject, the workflow of the job as
        the alternative name and the values of the run in the extensions
        1.3.6.1.4.1.57264.1.{number}. The numbers 1 to 6 hold a text as it is, the numbers
        from 8 on the DER of a UTF8String."""
        extensions = [
            der_extension("key-usage", KEY_USAGE_SIGN, True),
            der_extension("extended-key-usage", CODE_SIGNING),
        ]
        if authority:
            extensions.append(
                der_extension("basic-constraints", der_sequence(der_boolean(True)), True)
            )
        extensions.append(
            der_extension(
                "authority-key-identifier", authority_key(self.intermediate_key.identifier)
            )
        )
        if 9 in texts:
            extensions.append(
                der_extension(
                    "subject-alternative-name",
                    der_sequence(tlv(0x86, texts[9].encode())),
                    True,
                )
            )
        for number in sorted(texts):
            value = texts[number].encode() if number < 8 else der_utf8(texts[number])
            extensions.append(der_extension(f"{OID['fulcio']}.{number}", value))
        extensions.extend(more or [])
        return certificate(
            key=key,
            signer=signer or self.intermediate_key,
            subject=der_sequence(),
            issuer=issuer or self.intermediate_name,
            not_before=not_before,
            not_after=not_after,
            serial=serial,
            hash_name=hash_name,
            extensions=extensions,
            time=time,
        )


# ---- The transparency log ----


def tree_hash(leaves: list[bytes]) -> bytes:
    """The hash of the Merkle tree over the hashes of its leaves (RFC 6962 section 2.1)."""
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return sha256(b"\x01" + tree_hash(leaves[:split]) + tree_hash(leaves[split:]))


def audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """The audit path of a leaf, from the leaf upwards (RFC 6962 section 2.1.1)."""
    if len(leaves) == 1:
        return []
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    if index < split:
        return audit_path(index, leaves[:split]) + [tree_hash(leaves[split:])]
    return audit_path(index - split, leaves[split:]) + [tree_hash(leaves[:split])]


class Log:
    """A transparency log of the form Rekor v1: it signs an entry timestamp, holds its entries
    in a Merkle tree and signs the head of that tree."""

    def __init__(self, label: str, origin: str = "rekor.vectors.test - 2605736670972794746"):
        self.key = Key(label)
        self.id = sha256(self.key.spki)
        self.origin = origin

    def promise(self, body: str, integrated_time: int, log_index: int, log_id: bytes | None = None) -> str:
        """The signed entry timestamp for a body (standard base64 text): standard base64."""
        signed = (
            f'{{"body":"{body}","integratedTime":{integrated_time},'
            f'"logID":"{(log_id or self.id).hex()}","logIndex":{log_index}}}'
        )
        return b64(self.key.sign(signed.encode()))

    def checkpoint(
        self,
        size: int,
        root: bytes,
        *,
        signer: "Log | None" = None,
        key_id: bytes | None = None,
        more: str = "",
    ) -> str:
        """The checkpoint of a tree: the note of its head and the line of the log. `signer`
        signs in the place of the log, `key_id` names another key in front of the signature,
        and `more` stands in the note behind the root hash."""
        note = f"{self.origin}\n{size}\n{b64(root)}\n{more}"
        by = signer or self
        signature = (key_id or self.id)[:4] + by.key.sign(note.encode())
        name = self.origin.split(" ")[0]
        return f"{note}\n— {name} {b64(signature)}\n"

    def include(self, body: bytes, index: int, size: int) -> dict:
        """What the log returns to show that it holds an entry: the entry with the decoded
        body `body` is the leaf `index` of a tree of `size` leaves."""
        leaves = [
            sha256(b"\x00" + body) if at == index else sha256(f"leaf {at}".encode())
            for at in range(size)
        ]
        root = tree_hash(leaves)
        return {
            "index": index,
            "size": size,
            "root": root,
            "path": audit_path(index, leaves),
            "checkpoint": self.checkpoint(size, root),
        }


# ---- The constants of the cases ----

ISSUER = "https://token.actions.githubusercontent.com"
REPOSITORY = "https://github.com/pickle-com/credential-enclave"
REPOSITORY_ID = "1400118248"
OWNER = "https://github.com/pickle-com"
OWNER_ID = "151645824"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://pickle.com/credential-enclave/release/v1"

# The two build workflows the trust of the cases names.
BUILDER = {
    "workflow": ".github/workflows/enclave-build.yml",
    "commit": fixed("builder commit", 20).hex(),
}
SECOND_BUILDER = {
    "workflow": ".github/workflows/enclave-build-next.yml",
    "commit": fixed("second builder commit", 20).hex(),
}
RELEASE_WORKFLOW = ".github/workflows/release.yml"

# The release of the cases, the commit of its tag and its measurement.
RELEASE = "v9.9.0"
COMMIT = fixed("release commit", 20).hex()
MEASUREMENT = {
    "pcr0": fixed("pcr0", 48).hex(),
    "pcr1": fixed("pcr1", 48).hex(),
    "pcr2": fixed("pcr2", 48).hex(),
}
ZERO = "0" * 96

# The time the log states for the entry of a case, inside the ten minutes of its certificate.
NOT_BEFORE = 1_795_000_000
NOT_AFTER = 1_795_000_600
INTEGRATED_TIME = 1_795_000_100
LOG_INDEX = 4_100_000_001

AUTHORITY = Authority("authority")
LOG = Log("log")
OTHER_LOG = Log("other log", "other.vectors.test - 7")
OTHER_KEY = Key("other key")


def other_hex(text: str) -> str:
    """The same hexadecimal text with another first character."""
    return ("1" if text[0] == "0" else "0") + text[1:]


# ---- The release statement and its attestation ----


def statement_of(release=RELEASE, measurement=None, more=None, commit=COMMIT) -> bytes:
    """The bytes of a release statement: the file measurements.json of a release, as its
    build writes it."""
    measurement = measurement or MEASUREMENT
    stated = {
        "release": release,
        "git_commit": commit,
        "pcr0": measurement["pcr0"],
        "pcr1": measurement["pcr1"],
        "pcr2": measurement["pcr2"],
        "inputs": {
            "image/toolchain": fixed("input toolchain").hex(),
            "file/Cargo.lock": fixed("input lock").hex(),
            "binary/credential-enclave": fixed("input binary").hex(),
        },
    }
    stated.update(more or {})
    for name in [name for name, value in stated.items() if value is ...]:
        del stated[name]
    return (json.dumps(stated, indent=2) + "\n").encode()


def identity_of(release: str, commit: str, builder=None) -> dict[int, str]:
    """The values the certificate of the attestation of a release statement states, by the
    number of its extension: the certificate of the job of a build workflow, called by the
    release workflow, in a run the push of the tag of the release started at `commit`."""
    builder = builder or BUILDER
    ref = "refs/tags/" + release
    return {
        1: ISSUER,
        2: "push",
        3: commit,
        4: "release",
        5: "pickle-com/credential-enclave",
        6: ref,
        8: ISSUER,
        9: f"{REPOSITORY}/{builder['workflow']}@{builder['commit']}",
        10: builder["commit"],
        11: "github-hosted",
        12: REPOSITORY,
        13: commit,
        14: ref,
        15: REPOSITORY_ID,
        16: OWNER,
        17: OWNER_ID,
        18: f"{REPOSITORY}/{RELEASE_WORKFLOW}@{ref}",
        19: commit,
        20: "push",
        21: f"{REPOSITORY}/actions/runs/45452003045/attempts/1",
        22: "public",
    }


def pre_authentication(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def attestation_of(statement: bytes, name: str, **given) -> dict:
    """The attestation of a release statement as the job of a build workflow makes it: a
    Sigstore bundle with the certificate of the run, the envelope of the in-toto statement and
    the entry of the log. `name` names the case: the key and the serial number of its
    certificate follow from it. The options change one part:

      release, commit  what the certificate states of the run (those of the statement)
      identity      {number: text or None}: replaces or leaves out extensions of the certificate
      builder       the build workflow whose job signs (BUILDER)
      leaf          options of Authority.issue for the certificate of the run
      authority     the authority that issues the certificate (AUTHORITY)
      predicate, predicate_type, payload_type, in_toto, payload  the parts of the envelope
      signer        the key that signs the envelope (the key of the certificate)
      signed_type   the payload type in the signed bytes (the one of the envelope)
      curve         the curve of the key of the certificate (p256)
      log           the log that takes the entry (LOG)
      record        (record) -> None: changes the record before the log takes it
      body          the bytes of the record (its JSON)
      integrated_time, log_index, leaf_index, tree_size  what the log states for the entry
      entry         (entry) -> None: changes the entry after the log made it
      bundle        (bundle) -> None: changes the bundle at the end
    """
    try:
        stated = json.loads(statement)
    except ValueError:
        stated = None
    if not isinstance(stated, dict):
        stated = {}
    release = given.get("release", stated.get("release"))
    commit = given.get("commit", stated.get("git_commit"))
    if not isinstance(release, str):
        release = RELEASE
    if not isinstance(commit, str):
        commit = COMMIT
    log = given.get("log", LOG)
    key = Key("leaf " + name, given.get("curve", "p256"))
    texts = identity_of(release, commit, given.get("builder"))
    for number, value in given.get("identity", {}).items():
        if value is None:
            texts.pop(number, None)
        else:
            texts[number] = value
    leaf = given.get("authority", AUTHORITY).issue(
        key, texts, serial=name, **given.get("leaf", {})
    )
    in_toto = given.get("in_toto")
    if in_toto is None:
        in_toto = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "enclave.eif", "digest": {"sha256": sha256(release.encode()).hex()}}
            ],
            "predicateType": given.get("predicate_type", PREDICATE_TYPE),
            "predicate": given["predicate"] if "predicate" in given else stated,
        }
    payload = given["payload"] if "payload" in given else compact(in_toto).encode()
    payload_type = given.get("payload_type", PAYLOAD_TYPE)
    signature = given.get("signer", key).sign(
        pre_authentication(given.get("signed_type", payload_type), payload)
    )
    envelope = {
        "payload": b64(payload),
        "payloadType": payload_type,
        "signatures": [{"sig": b64(signature)}],
    }
    record = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": sha256(compact(envelope).encode()).hex()},
            "payloadHash": {"algorithm": "sha256", "value": sha256(payload).hex()},
            "signatures": [
                {"signature": b64(signature), "verifier": b64(pem("CERTIFICATE", leaf).encode())}
            ],
        },
    }
    if "record" in given:
        given["record"](record)
    body = given["body"] if "body" in given else compact(record).encode()
    body_text = b64(body)
    integrated_time = given.get("integrated_time", INTEGRATED_TIME)
    log_index = given.get("log_index", LOG_INDEX)
    included = log.include(body, given.get("leaf_index", 5), given.get("tree_size", 11))
    entry = {
        "logIndex": str(log_index),
        "logId": {"keyId": b64(log.id)},
        "kindVersion": {"kind": "dsse", "version": "0.0.1"},
        "integratedTime": str(integrated_time),
        "inclusionPromise": {
            "signedEntryTimestamp": log.promise(body_text, integrated_time, log_index)
        },
        "inclusionProof": {
            "logIndex": str(included["index"]),
            "rootHash": b64(included["root"]),
            "treeSize": str(included["size"]),
            "hashes": [b64(item) for item in included["path"]],
            "checkpoint": {"envelope": included["checkpoint"]},
        },
        "canonicalizedBody": body_text,
    }
    if "entry" in given:
        given["entry"](entry)
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": b64(leaf)},
            "tlogEntries": [entry],
            "timestampVerificationData": {},
        },
        "dsseEnvelope": envelope,
    }
    if "bundle" in given:
        given["bundle"](bundle)
    return bundle


def proofs_of(name: str, statement: bytes | None = None, **given) -> dict:
    """The release proofs of a statement (the one of the release of the cases), with the
    options of attestation_of."""
    statement = statement if statement is not None else statement_of()
    return {"statement": b64u(statement), "attestation": attestation_of(statement, name, **given)}


# ---- The trust of a case ----


def trust_of(authority: Authority, logs: list[Log], builders: list[dict], root: bytes | None = None) -> dict:
    return {
        "fulcio_root": b64u(root or authority.root),
        "fulcio_intermediate": b64u(authority.intermediate),
        "log_keys": [b64u(log.key.spki) for log in logs],
        "issuer": ISSUER,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "owner_id": OWNER_ID,
        "builders": builders,
    }


def pem_file(path: Path, label: str) -> bytes:
    text = path.read_text().strip()
    begin, end = f"-----BEGIN {label}-----", f"-----END {label}-----"
    assert text.startswith(begin) and text.endswith(end), path
    return base64.b64decode("".join(text[len(begin) : -len(end)].split()))


SAME_NAMES = Authority("authority of the same names")
EXPIRED = Authority("expired authority", not_after=1_794_000_000)
NO_AUTHORITY = Authority("authority without authority", intermediate_authority=False)

# The published release v2.3.0 was attested by a job of its release workflow, before the build
# workflow existed.
PUBLISHED_V230_BUILDER = {
    "workflow": ".github/workflows/release.yml",
    "commit": "29d450c2867b9c198c2f9680905a11120178d2b5",
}


# The published release candidate v2.4.0-rc.1 was attested by the job of the build workflow at
# the commit of that file a node and a secure program no longer list: the node program of
# that tag hands delegations on by a signature of the operator.
PUBLISHED_RC1_BUILDER = {
    "workflow": ".github/workflows/enclave-build.yml",
    "commit": "3f84e8368fcdf1f89e42ca629670bfe0989b6f13",
}


def trusts() -> dict:
    sigstore_root = pem_file(RELEASE_VALUES / "fulcio-root.pem", "CERTIFICATE")
    sigstore_intermediate = pem_file(RELEASE_VALUES / "fulcio-intermediate.pem", "CERTIFICATE")
    rekor = pem_file(RELEASE_VALUES / "rekor-key.pem", "PUBLIC KEY")
    return {
        "test": trust_of(AUTHORITY, [LOG], [BUILDER, SECOND_BUILDER]),
        "test-two-logs": trust_of(AUTHORITY, [OTHER_LOG, LOG], [BUILDER, SECOND_BUILDER]),
        "test-no-builder": trust_of(AUTHORITY, [LOG], []),
        "test-other-root": trust_of(AUTHORITY, [LOG], [BUILDER], root=SAME_NAMES.root),
        "test-expired": trust_of(EXPIRED, [LOG], [BUILDER]),
        "test-intermediate-without-authority": trust_of(NO_AUTHORITY, [LOG], [BUILDER]),
        "sigstore-release-workflow-v2.3.0": {
            "fulcio_root": b64u(sigstore_root),
            "fulcio_intermediate": b64u(sigstore_intermediate),
            "log_keys": [b64u(rekor)],
            "issuer": ISSUER,
            "repository": REPOSITORY,
            "repository_id": REPOSITORY_ID,
            "owner_id": OWNER_ID,
            "builders": [PUBLISHED_V230_BUILDER],
        },
        "sigstore-build-workflow-v2.4.0-rc.1": {
            "fulcio_root": b64u(sigstore_root),
            "fulcio_intermediate": b64u(sigstore_intermediate),
            "log_keys": [b64u(rekor)],
            "issuer": ISSUER,
            "repository": REPOSITORY,
            "repository_id": REPOSITORY_ID,
            "owner_id": OWNER_ID,
            "builders": [PUBLISHED_RC1_BUILDER],
        },
    }


# ---- The cases ----

CASES: list[dict] = []


def add(name, rule, proofs, *, trust="test", measurement=None, text=None):
    """A case: release proofs (a value, or with `text` the JSON text itself), the measurement
    they are verified for, the trust they are verified with, and the verdict. `rule` is None
    for proofs that hold, and names the rule that refuses the others: V1 to V7 of
    docs/protocol.md section 9, or `form` for a value that is no release proofs."""
    written = text if text is not None else compact(proofs)
    release = None
    if rule is None:
        stated = json.loads(base64.urlsafe_b64decode(proofs["statement"] + "=" * (-len(proofs["statement"]) % 4)))
        release = stated["release"]
    assert all(case["name"] != name for case in CASES), name
    CASES.append(
        {
            "name": name,
            "trust": trust,
            "measurement": measurement or MEASUREMENT,
            "release_proofs_text": written,
            "accepted": rule is None,
            "release": release,
            "rule": rule,
        }
    )


def edited(name, edit, statement=None, **given):
    proofs = proofs_of(name, statement, **given)
    edit(proofs)
    return proofs


def entry_of(bundle):
    return bundle["verificationMaterial"]["tlogEntries"][0]


def nested(levels: int):
    value = 1
    for _ in range(levels):
        value = [value]
    return value


def cases_that_hold():
    add("proofs that hold", None, proofs_of("hold"))
    add(
        "a statement with members no verifier reads",
        None,
        proofs_of("members", statement_of(more={"note": ["x", {"y": 1}], "program_min": 44})),
    )

    def more_members(proofs):
        proofs["note"] = "x"
        proofs["entry"] = {"log_id": "00", "body": "", "integrated_time": 0}
        proofs["deploy_signatures"] = [{"key_id": "prod", "signature": ""}]

    add("proofs with members no verifier reads", None, edited("proof members", more_members))
    add(
        "a bundle with members no verifier reads",
        None,
        proofs_of("bundle members", bundle=lambda bundle: bundle.update({"note": {"a": [1, 2, None, True]}})),
    )
    for release in ["v9.9.0-rc.1", "v10.20.30", "v2026.11_a-B", "vX"]:
        add(
            f"the proofs of the release {release}",
            None,
            proofs_of("release " + release, statement_of(release)),
        )
    add(
        "a statement whose members no verifier reads are not those of the predicate",
        None,
        proofs_of(
            "other inputs",
            statement_of(more={"inputs": {"image/toolchain": "00"}}),
            predicate=json.loads(statement_of()),
        ),
    )
    # The measurement and the release of the attestation document
    # protocol/tests/fixtures/nitro-attestation-document-operational.cbor: a test of the node
    # verifies that document as the document of a peer these proofs show.
    recorded = {
        "pcr0": "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47",
        "pcr1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        "pcr2": "a1952bc63a9e80a3a46eda48bb60236dfcb030d50bf81f02b5c50d20d42a905d1db7c82d3f1d4c4d5649b20697889d44",
    }
    add(
        "the proofs of the measurement of a recorded attestation document",
        None,
        proofs_of("recorded", statement_of("v0.0.0-diag.local", recorded)),
        measurement=recorded,
    )
    add(
        "a statement of 16,384 bytes",
        None,
        proofs_of("statement 16384", statement_of().ljust(16_384, b" ")),
    )
    add(
        "a log entry time at the first second of the validity of the certificate",
        None,
        proofs_of("first second", integrated_time=NOT_BEFORE),
    )
    add(
        "a log entry time at the last second of the validity of the certificate",
        None,
        proofs_of("last second", integrated_time=NOT_AFTER),
    )
    add(
        "a certificate the intermediate signed with SHA-256",
        None,
        proofs_of("sha256", leaf={"hash_name": "sha256"}),
    )
    build = f"{REPOSITORY}/{BUILDER['workflow']}"
    add(
        "the build workflow named by a branch whose head is the commit of the build workflow",
        None,
        proofs_of("branch", identity={9: build + "@refs/heads/main"}),
    )
    add(
        "the build workflow named by a tag at the commit of the build workflow",
        None,
        proofs_of("tag", identity={9: build + "@refs/tags/" + RELEASE}),
    )
    add("the second build workflow of the list", None, proofs_of("second", builder=SECOND_BUILDER))
    add(
        "a run another workflow file of the tag started",
        None,
        proofs_of("caller", identity={18: f"{REPOSITORY}/.github/workflows/other.yml@refs/tags/{RELEASE}"}),
    )
    add(
        "a certificate that does not state the workflow that started the run",
        None,
        proofs_of("no caller", identity={18: None, 19: None, 21: None}),
    )
    add("the last leaf of a tree", None, proofs_of("last leaf", leaf_index=10, tree_size=11))
    add("the only leaf of a tree", None, proofs_of("only leaf", leaf_index=0, tree_size=1))
    add(
        "the first leaf of a tree of 4,096 leaves",
        None,
        proofs_of("first of 4096", leaf_index=0, tree_size=4096),
    )

    def checkpoint_of(change):
        def edit(entry):
            proof = entry["inclusionProof"]
            proof["checkpoint"]["envelope"] = change(
                proof["checkpoint"]["envelope"],
                int(proof["treeSize"]),
                base64.b64decode(proof["rootHash"]),
            )

        return edit

    add(
        "a checkpoint with the line of a witness beside the line of the log",
        None,
        proofs_of(
            "witness",
            entry=checkpoint_of(
                lambda text, size, root: text + OTHER_LOG.checkpoint(size, root).split("\n\n")[1]
            ),
        ),
    )
    add(
        "a checkpoint with a line of another key under the name of the log",
        None,
        proofs_of(
            "other key line",
            entry=checkpoint_of(
                lambda text, size, root: text
                + LOG.checkpoint(size, root, signer=OTHER_LOG, key_id=OTHER_LOG.id).split("\n\n")[1]
            ),
        ),
    )
    add(
        "a checkpoint whose note has a line behind the root hash, signed by the log",
        None,
        proofs_of(
            "note line",
            entry=checkpoint_of(lambda text, size, root: LOG.checkpoint(size, root, more="1795000100\n")),
        ),
    )
    add(
        "an entry of the second log of the trust",
        None,
        proofs_of("second log"),
        trust="test-two-logs",
    )
    add(
        "an entry of the first log of the trust",
        None,
        proofs_of("first log", log=OTHER_LOG),
        trust="test-two-logs",
    )

    # The times and the indexes as JSON numbers, and as numbers that are written with a
    # fraction or an exponent and are integers: a count is a text of digits, and a JSON number
    # is none. The readers of a release proof do not read every text of a number as the same
    # double.
    def numbers(bundle):
        entry = entry_of(bundle)
        for holder, key in [
            (entry, "logIndex"),
            (entry, "integratedTime"),
            (entry["inclusionProof"], "logIndex"),
            (entry["inclusionProof"], "treeSize"),
        ]:
            holder[key] = int(holder[key])

    add("times and indexes that are JSON numbers", "V4", proofs_of("numbers", bundle=numbers))
    whole = proofs_of("whole numbers")
    written = compact(whole)
    for name, old, new in [
        ("a time written with a fraction that is zero", f'"integratedTime":"{INTEGRATED_TIME}"', f'"integratedTime":{INTEGRATED_TIME}.0'),
        ("a time written with an exponent", f'"integratedTime":"{INTEGRATED_TIME}"', '"integratedTime":1.7950001e9'),
        ("an index of the tree written with a fraction that is zero", '"inclusionProof":{"logIndex":"5"', '"inclusionProof":{"logIndex":5.0'),
    ]:
        assert written.count(old) == 1, old
        add(name, "V4", whole, text=written.replace(old, new))
    # An object that states a member twice states the last one.
    old = f'"payloadType":"{PAYLOAD_TYPE}"'
    assert written.count(old) == 1
    add(
        "a bundle that states a member twice, the value of the proofs last",
        None,
        whole,
        text=written.replace(old, '"payloadType":"application/vnd.other+json",' + old),
    )

    # The longest attestation: 65,536 bytes as JSON without white space.
    def padded(length):
        def pad(bundle):
            bundle["note"] = ""
            bundle["note"] = "x" * (length - len(compact(bundle).encode()))

        return pad

    longest = proofs_of("longest", bundle=padded(65_536))
    assert len(compact(longest["attestation"]).encode()) == 65_536
    add("an attestation of 65,536 bytes", None, longest)
    add(
        "proofs with 32 arrays and objects inside one another",
        None,
        edited("depth 32", lambda proofs: proofs.update({"note": nested(31)})),
    )
    add(
        "a certificate whose validity is written as two GeneralizedTime values",
        None,
        proofs_of("generalized time", leaf={"time": der_generalized_time}),
    )

    # The text of the proofs, written in other ways that are the same JSON value.
    plain = proofs_of("written")
    add(
        "proofs written with white space between their values",
        None,
        plain,
        text=json.dumps(plain, indent=2, ensure_ascii=False) + "\n",
    )
    add(
        "proofs written with every character outside ASCII escaped",
        None,
        plain,
        text=json.dumps(plain, separators=(",", ":"), ensure_ascii=True),
    )
    written = compact(plain)
    assert written.startswith('{"statement":"') and written.count('"attestation":') == 1
    add(
        "proofs whose keys are written with escapes",
        None,
        plain,
        text=written.replace('{"statement":"', '{"st\\u0061tement":"', 1).replace(
            '"attestation":', '"\\u0061ttestation":', 1
        ),
    )
    add(
        "proofs that state the statement twice, the statement of the proofs last",
        None,
        plain,
        text='{"statement":"e30",' + written[1:],
    )
    add(
        "proofs with a number too small for a double, which is zero",
        None,
        plain,
        text=written[:-1] + ',"note":1e-400}',
    )
    add(
        "proofs with a member named __proto__",
        None,
        plain,
        text=written[:-1] + ',"__proto__":{"statement":"e30","attestation":null}}',
    )

    # The longest attestation, counted as JSON without white space with every number as
    # ECMAScript writes it and every text as JSON writes it: a number written with a fraction
    # that is zero counts as its integer, a number from 1e21 on counts with its exponent and
    # the sign of it, and a character written as an escape counts as the character, with the
    # escape of a control character.
    def room(bundle, written_note: str, length: int) -> str:
        """The text of the bundle with `"note":[written_note,"xxx"]` at its end, where the
        padding makes the bundle `length` bytes long by that count."""
        bundle = dict(bundle)
        counted = {
            "[1.0,1e21,100000000000000000000,1.5e300,-0,0.000001,1e-7]": "[1,1e+21,100000000000000000000,1.5e+300,0,0.000001,1e-7]",
            '["\\u0041\\/\\u00e9\\u0001\\u001f\\n\\u2028\\ud83d\\ude00"]': '["A/\u00e9\\u0001\\u001f\\n\u2028\U0001f600"]',
        }[written_note]
        base = compact(bundle)
        fixed_bytes = len(base.encode()) + len(',"note":[,""]') + len(counted.encode())
        padding = "x" * (length - fixed_bytes)
        return base[:-1] + ',"note":[' + written_note + ',"' + padding + '"]}'

    for name, note in [
        ("numbers that ECMAScript writes in another form", "[1.0,1e21,100000000000000000000,1.5e300,-0,0.000001,1e-7]"),
        ("characters written as escapes", '["\\u0041\\/\\u00e9\\u0001\\u001f\\n\\u2028\\ud83d\\ude00"]'),
    ]:
        for length, rule in [(65_536, None), (65_537, "V2")]:
            whole = proofs_of(f"counted {name} {length}")
            attestation = room(whole["attestation"], note, length)
            add(
                f"an attestation of {length:,} bytes with {name}",
                rule,
                whole,
                text='{"statement":"' + whole["statement"] + '","attestation":' + attestation + "}",
            )


def cases_of_the_form():
    for name, value in [("null", None), ("an array", []), ("a text", "proofs"), ("a number", 7), ("true", True)]:
        add(f"proofs that are {name}", "form", value)
    add(
        "the proofs inside an array",
        "form",
        [proofs_of("in array")],
    )
    add(
        "proofs with 33 arrays and objects inside one another",
        "form",
        edited("depth 33", lambda proofs: proofs.update({"note": nested(32)})),
    )
    whole = proofs_of("form")
    written = compact(whole)
    add(
        "proofs with half of a surrogate pair in a text",
        "form",
        whole,
        text=written[:-1] + ',"note":"\\ud83d"}',
    )
    add(
        "proofs with a number no double holds",
        "form",
        whole,
        text=written[:-1] + ',"note":1e400}',
    )
    add(
        "proofs with an integer of four hundred digits",
        "form",
        whole,
        text=written[:-1] + ',"note":' + "9" * 400 + "}",
    )
    add(
        "proofs whose statement and attestation are members of a member named __proto__",
        "form",
        whole,
        text='{"__proto__":' + written + "}",
    )
    add("proofs that are no JSON", "form", whole, text=written[:-1])
    add("proofs with a text behind them", "form", whole, text=written + "x")


def cases_of_the_statement():
    def of_statement(name, statement, **given):
        return proofs_of(name, statement, **given)

    add("proofs without a statement", "form", edited("no statement", lambda proofs: proofs.pop("statement")))
    add("proofs whose statement is a number", "form", edited("statement number", lambda proofs: proofs.update({"statement": 7})))
    add(
        "proofs whose statement is the object of the statement",
        "form",
        edited("statement object", lambda proofs: proofs.update({"statement": json.loads(statement_of())})),
    )
    # A statement whose base64 has one padding character.
    odd = statement_of()
    while len(odd) % 3 != 2:
        odd += b" "
    add(
        "a statement in base64 with padding",
        "V1",
        edited("padding", lambda proofs: proofs.update({"statement": proofs["statement"] + "="}), odd),
    )
    # The bytes ??? and >>> give characters of the standard alphabet the URL-safe one lacks.
    marked = statement_of(more={"note": "???>>>"})
    assert "/" in b64(marked) and "+" in b64(marked)
    add(
        "a statement in the standard alphabet of base64",
        "V1",
        edited("standard", lambda proofs: proofs.update({"statement": b64(marked).rstrip("=")}), marked),
    )
    add(
        "a statement that is no base64",
        "V1",
        edited("no base64", lambda proofs: proofs.update({"statement": "*" + proofs["statement"]})),
    )
    # A last character that carries bits of no byte.
    tail = statement_of()
    while len(tail) % 3 != 1:
        tail += b" "
    text = b64u(tail)
    last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    spare = last[(last.index(text[-1]) | 1)]
    assert spare != text[-1]
    add(
        "a statement whose last character carries bits of no byte",
        "V1",
        edited("spare bits", lambda proofs: proofs.update({"statement": text[:-1] + spare}), tail),
    )
    add("a statement of 16,385 bytes", "V1", of_statement("statement 16385", statement_of().ljust(16_385, b" ")))
    # A text of base64url of more than twice 16,384 characters is no statement of any length.
    longest_text = proofs_of("statement text 32768", statement_of().ljust(24_576, b" "))
    assert len(longest_text["statement"]) == 32_768
    add("a statement of 24,576 bytes, whose text is 32,768 characters", "V1", longest_text)
    longer_text = proofs_of("statement text 32769", statement_of().ljust(24_577, b" "))
    assert len(longer_text["statement"]) == 32_770
    add("a statement of 24,577 bytes, whose text is 32,770 characters", "form", longer_text)
    add("a statement that is no JSON", "V1", of_statement("no json", b"release " + RELEASE.encode()))
    add("a statement that is a JSON array", "V1", of_statement("array", compact([json.loads(statement_of())]).encode()))
    add("a statement that is a JSON text", "V1", of_statement("json text", b'"release"'))
    add("an empty statement", "V1", of_statement("empty", b""))
    plain = statement_of()
    add(
        "a statement that is no UTF-8",
        "V1",
        of_statement("no utf8", plain[:4] + b"\xff" + plain[4:]),
    )
    add(
        "a statement with bytes that are no UTF-8 inside a text no verifier reads",
        "V1",
        of_statement("no utf8 inside", plain.replace(b'"inputs"', b'"note": "\xff",\n  "inputs"')),
    )
    add("a statement with a byte order mark", "V1", of_statement("bom", b"\xef\xbb\xbf" + plain))
    add("a statement with a text behind its object", "V1", of_statement("trailing", plain + b"x"))
    value = json.loads(plain)
    for field in ["release", "git_commit", "pcr0", "pcr1", "pcr2"]:
        twice = plain.decode().replace("{", "{\n  " + json.dumps(field) + ": " + json.dumps(value[field]) + ",", 1)
        add(f"a statement that states {field} twice", "V1", of_statement("twice " + field, twice.encode()))
        add(f"a statement without {field}", "V1", of_statement("without " + field, statement_of(more={field: ...})))
    add(
        "a statement that states pcr0 twice, once with an escaped key",
        "V1",
        of_statement("escaped", plain.decode().replace("{", '{\n  "pcr\\u0030": ' + json.dumps(MEASUREMENT["pcr0"]) + ",", 1).encode()),
    )
    add(
        "a statement that states release twice, the release of the proofs last",
        "V1",
        of_statement("twice last", plain.decode().replace("{", '{\n  "release": "v0.0.1",', 1).encode()),
    )
    add("a statement with a PCR in upper case", "V1", of_statement("upper", statement_of(more={"pcr1": MEASUREMENT["pcr1"].upper()})))
    add("a statement with a PCR of 95 characters", "V1", of_statement("95", statement_of(more={"pcr2": MEASUREMENT["pcr2"][1:]})))
    add("a statement with a PCR of 97 characters", "V1", of_statement("97", statement_of(more={"pcr2": MEASUREMENT["pcr2"] + "0"})))
    add("a statement whose pcr0 is a number", "V1", of_statement("pcr number", statement_of(more={"pcr0": 7})))
    add("a statement whose release is a number", "V1", of_statement("release number", statement_of(more={"release": 2})))
    add("a statement whose release is null", "V1", of_statement("release null", statement_of(more={"release": None})))
    for tag in ["dev", "9.9.0", "v", "V9.9.0", "v9.9.0 ", " v9.9.0", "v9.9.0/x", "v9.9.0+1", "v9.9.0\n", "v9.9.é"]:
        add(
            f"a statement whose release is {json.dumps(tag)}",
            "V1",
            of_statement("tag " + tag, statement_of(tag)),
        )
    for name, commit in [
        ("in upper case", COMMIT.upper()),
        ("of 39 characters", COMMIT[1:]),
        ("of 41 characters", COMMIT + "0"),
        ("a number", 7),
        ("null", None),
        ("the name of a branch", "main"),
    ]:
        add(
            f"a statement whose git_commit is {name}",
            "V1",
            of_statement("commit " + name, statement_of(more={"git_commit": commit})),
        )
    for field in ["pcr0", "pcr1", "pcr2"]:
        other = dict(MEASUREMENT, **{field: other_hex(MEASUREMENT[field])})
        add(
            f"the proofs of another measurement: one character of {field}",
            "V1",
            proofs_of("other " + field, statement_of(measurement=other)),
        )
    # A PCR whose value is all zero is the value of an enclave in debug mode.
    for name, debug in [
        ("pcr0", dict(MEASUREMENT, pcr0=ZERO)),
        ("pcr1", dict(MEASUREMENT, pcr1=ZERO)),
        ("pcr2", dict(MEASUREMENT, pcr2=ZERO)),
        ("every PCR", {"pcr0": ZERO, "pcr1": ZERO, "pcr2": ZERO}),
    ]:
        add(
            f"the proofs of a measurement whose {name} is all zero",
            "V1",
            proofs_of("zero " + name, statement_of(measurement=debug)),
            measurement=debug,
        )
    add(
        "a statement with 33 arrays and objects inside one another",
        "V1",
        of_statement("statement depth", statement_of(more={"note": nested(32)})),
    )
    add(
        "a statement with 32 arrays and objects inside one another",
        None,
        of_statement(
            "statement depth 32",
            statement_of(more={"note": nested(31)}),
            predicate=json.loads(statement_of()),
        ),
    )


def cases_of_the_bundle():
    add("proofs without an attestation", "form", edited("no attestation", lambda proofs: proofs.pop("attestation")))
    add("proofs whose attestation is an array", "form", edited("attestation array", lambda proofs: proofs.update({"attestation": [proofs["attestation"]]})))
    add(
        "proofs whose attestation is the text of the bundle",
        "form",
        edited("attestation text", lambda proofs: proofs.update({"attestation": compact(proofs["attestation"])})),
    )
    add("proofs whose attestation is null", "form", edited("attestation null", lambda proofs: proofs.update({"attestation": None})))

    def of_bundle(name, change, **given):
        return proofs_of(name, bundle=change, **given)

    add("an attestation without a certificate", "V2", of_bundle("no certificate", lambda bundle: bundle["verificationMaterial"].pop("certificate")))
    add(
        "an attestation whose certificate is no text",
        "V2",
        of_bundle("certificate number", lambda bundle: bundle["verificationMaterial"]["certificate"].update({"rawBytes": 7})),
    )
    add(
        "an attestation with a chain of certificates in the place of its certificate",
        "V2",
        of_bundle(
            "chain",
            lambda bundle: bundle["verificationMaterial"].update(
                {"x509CertificateChain": {"certificates": [bundle["verificationMaterial"].pop("certificate")]}}
            ),
        ),
    )
    add(
        "an attestation with two log entries",
        "V2",
        of_bundle("two entries", lambda bundle: bundle["verificationMaterial"]["tlogEntries"].append(entry_of(bundle))),
    )
    add("an attestation without a log entry", "V2", of_bundle("no entries", lambda bundle: bundle["verificationMaterial"].update({"tlogEntries": []})))
    add("an attestation whose log entries are an object", "V2", of_bundle("entries object", lambda bundle: bundle["verificationMaterial"].update({"tlogEntries": {"0": entry_of(bundle)}})))
    add("an attestation whose log entry is a text", "V2", of_bundle("entry text", lambda bundle: bundle["verificationMaterial"].update({"tlogEntries": ["entry"]})))
    add("an attestation without an envelope", "V2", of_bundle("no envelope", lambda bundle: bundle.pop("dsseEnvelope")))
    add("an envelope with two signatures", "V2", of_bundle("two signatures", lambda bundle: bundle["dsseEnvelope"]["signatures"].append(bundle["dsseEnvelope"]["signatures"][0])))
    add("an envelope without a signature", "V2", of_bundle("no signature", lambda bundle: bundle["dsseEnvelope"].update({"signatures": []})))
    add("an envelope whose signature is no text", "V2", of_bundle("signature number", lambda bundle: bundle["dsseEnvelope"]["signatures"][0].update({"sig": 7})))
    add("an envelope without a payload", "V2", of_bundle("no payload", lambda bundle: bundle["dsseEnvelope"].pop("payload")))
    add("an envelope without a payload type", "V2", of_bundle("no payload type", lambda bundle: bundle["dsseEnvelope"].pop("payloadType")))

    def padded(length):
        def pad(bundle):
            bundle["note"] = ""
            bundle["note"] = "x" * (length - len(compact(bundle).encode()))

        return pad

    longer = proofs_of("longer", bundle=padded(65_537))
    assert len(compact(longer["attestation"]).encode()) == 65_537
    add("an attestation of 65,537 bytes", "V2", longer)
    # Characters of two and of three bytes count by their bytes.
    def padded_with(character, length):
        def pad(bundle):
            bundle["note"] = ""
            room = length - len(compact(bundle).encode())
            width = len(character.encode())
            bundle["note"] = character * (room // width) + "x" * (room % width)

        return pad

    exact = proofs_of("longest of wide characters", bundle=padded_with("é", 65_536))
    assert len(compact(exact["attestation"]).encode()) == 65_536
    add("an attestation of 65,536 bytes with characters of two bytes", None, exact)
    over = proofs_of("longer of wide characters", bundle=padded_with("€", 65_537))
    assert len(compact(over["attestation"]).encode()) == 65_537
    add("an attestation of 65,537 bytes with characters of three bytes", "V2", over)

    add("an envelope of another payload type", "V2", proofs_of("payload type", payload_type="application/vnd.other+json"))
    add("a payload that is a JSON array", "V2", proofs_of("payload array", in_toto=["release"]))
    add("a payload that is no JSON", "V2", proofs_of("payload text", payload=b"release " + RELEASE.encode()))
    add(
        "a payload in base64url",
        "V2",
        of_bundle(
            "payload url",
            lambda bundle: bundle["dsseEnvelope"].update(
                {"payload": b64u(base64.b64decode(bundle["dsseEnvelope"]["payload"])) + "_"}
            ),
        ),
    )
    whole = proofs_of("member twice")
    written = compact(whole)
    old = f'"payloadType":"{PAYLOAD_TYPE}"'
    assert written.count(old) == 1
    add(
        "a bundle that states a member twice, another value last",
        "V2",
        whole,
        text=written.replace(old, old + ',"payloadType":"application/vnd.other+json"'),
    )


def spare_bits(text: str) -> str:
    """The same standard base64 with a last character that carries bits of no byte. The text
    ends with one or two padding characters."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = text.rstrip("=")
    assert body != text, "the text has no padding"
    changed = alphabet[alphabet.index(body[-1]) | 1]
    assert changed != body[-1]
    return body[:-1] + changed + text[len(body) :]


def padded_base64(data: bytes) -> bytes:
    """The bytes, with zero bytes behind them until their base64 has a padding character."""
    while len(data) % 3 == 0:
        data += b"\x00"
    return data


def cases_of_the_encodings():
    """A text of base64 whose last character carries bits of no byte is no base64, wherever it
    stands: each case is refused by the check that reads the value."""

    def envelope(bundle):
        item = bundle["dsseEnvelope"]["signatures"][0]
        item["sig"] = spare_bits(item["sig"])

    add("a signature whose last character carries bits of no byte", "V5", proofs_of("spare sig", bundle=envelope))

    def root(entry):
        entry["inclusionProof"]["rootHash"] = spare_bits(entry["inclusionProof"]["rootHash"])

    add("a root hash whose last character carries bits of no byte", "V4", proofs_of("spare root", entry=root))

    def path(entry):
        hashes = entry["inclusionProof"]["hashes"]
        hashes[0] = spare_bits(hashes[0])

    add("a hash of the audit path whose last character carries bits of no byte", "V4", proofs_of("spare hash", entry=path))

    def log(entry):
        entry["logId"]["keyId"] = spare_bits(entry["logId"]["keyId"])

    add("a log identifier whose last character carries bits of no byte", "V4", proofs_of("spare log id", entry=log))

    def promise(entry):
        item = entry["inclusionPromise"]
        item["signedEntryTimestamp"] = spare_bits(item["signedEntryTimestamp"])

    add("a signed entry timestamp whose last character carries bits of no byte", "V4", proofs_of("spare promise", entry=promise))

    def certificate(bundle):
        item = bundle["verificationMaterial"]["certificate"]
        assert item["rawBytes"].endswith("=")
        item["rawBytes"] = spare_bits(item["rawBytes"])

    # The serial number of a certificate decides the length of its DER: one of these has a
    # base64 with padding.
    for attempt in range(8):
        candidate = proofs_of(f"spare certificate {attempt}")
        if candidate["attestation"]["verificationMaterial"]["certificate"]["rawBytes"].endswith("="):
            add(
                "a certificate whose last character carries bits of no byte",
                "V3",
                proofs_of(f"spare certificate {attempt}", bundle=certificate),
            )
            break
    else:
        raise AssertionError("no certificate whose base64 has padding")

    def payload(bundle):
        item = bundle["dsseEnvelope"]
        assert item["payload"].endswith("=")
        item["payload"] = spare_bits(item["payload"])

    for attempt in range(8):
        more = {"note": "x" * attempt}
        statement = statement_of(more=more)
        candidate = proofs_of(f"spare payload {attempt}", statement)
        if candidate["attestation"]["dsseEnvelope"]["payload"].endswith("="):
            add(
                "a payload whose last character carries bits of no byte",
                "V2",
                proofs_of(f"spare payload {attempt}", statement, bundle=payload),
            )
            break
    else:
        raise AssertionError("no payload whose base64 has padding")

    def body(entry):
        assert entry["canonicalizedBody"].endswith("=")
        entry["canonicalizedBody"] = spare_bits(entry["canonicalizedBody"])

    for attempt in range(8):
        candidate = proofs_of(f"spare body {attempt}")
        if entry_of(candidate["attestation"])["canonicalizedBody"].endswith("="):
            add(
                "a body of the log entry whose last character carries bits of no byte",
                "V4",
                proofs_of(f"spare body {attempt}", entry=body),
            )
            break
    else:
        raise AssertionError("no body whose base64 has padding")

    # White space inside a text of base64, as a text of PEM or of MIME has it.
    def wrapped(bundle):
        item = bundle["verificationMaterial"]["certificate"]
        item["rawBytes"] = item["rawBytes"][:64] + "\n" + item["rawBytes"][64:]

    add("a certificate whose base64 has a line feed", "V3", proofs_of("wrapped certificate", bundle=wrapped))


def cases_of_the_certificate():
    def of_bundle(name, change, **given):
        return proofs_of(name, bundle=change, **given)

    def raw(change):
        def edit(bundle):
            certificate = bundle["verificationMaterial"]["certificate"]
            certificate["rawBytes"] = change(base64.b64decode(certificate["rawBytes"]))

        return edit

    add("a certificate that is no DER", "V3", of_bundle("no der", raw(lambda der: b64(b"certificate"))))
    add("a certificate with bytes behind it", "V3", of_bundle("bytes behind", raw(lambda der: b64(der + b"\x00"))))
    def url(der):
        assert b64u(der) != b64(der)
        return b64u(der)

    add("a certificate in base64url", "V3", of_bundle("certificate url", raw(url)))
    add("a certificate as the text of its PEM", "V3", of_bundle("certificate pem", raw(lambda der: pem("CERTIFICATE", der))))
    add(
        "a certificate that states the runner twice",
        "V3",
        proofs_of(
            "runner twice",
            leaf={"more": [der_extension(OID["fulcio"] + ".11", der_utf8("github-hosted"))]},
        ),
    )
    add("a log entry without a time", "V4", of_bundle("no time", lambda bundle: entry_of(bundle).pop("integratedTime")))
    whole = proofs_of("time forms")
    written = compact(whole)
    old = f'"integratedTime":"{INTEGRATED_TIME}"'
    assert written.count(old) == 1
    for name, new in [
        ("a text with a leading zero", f'"integratedTime":"0{INTEGRATED_TIME}"'),
        ("a text with a fraction", f'"integratedTime":"{INTEGRATED_TIME}.0"'),
        ("a text with a sign", f'"integratedTime":"+{INTEGRATED_TIME}"'),
        ("a text of seventeen digits", '"integratedTime":"10000000000000000"'),
        ("the text of 2^53", '"integratedTime":"9007199254740992"'),
        ("a number with a fraction", f'"integratedTime":{INTEGRATED_TIME}.5'),
        ("a negative number", f'"integratedTime":-{INTEGRATED_TIME}'),
        ("the number 2^53", '"integratedTime":9007199254740992'),
        ("null", '"integratedTime":null'),
        ("an array", f'"integratedTime":[{INTEGRATED_TIME}]'),
    ]:
        add(f"a log entry whose time is {name}", "V4", whole, text=written.replace(old, new))
    add(
        "a log entry time before the validity of the certificate",
        "V3",
        proofs_of("before", integrated_time=NOT_BEFORE - 1),
    )
    add(
        "a log entry time after the validity of the certificate",
        "V3",
        proofs_of("after", integrated_time=NOT_AFTER + 1),
    )
    add("a certificate of a certificate authority", "V3", proofs_of("authority", leaf={"authority": True}))
    add(
        "a certificate that another authority of the same names issued",
        "V3",
        proofs_of("same names", authority=SAME_NAMES),
    )
    add(
        "a certificate the root issued",
        "V3",
        proofs_of("root issued", leaf={"signer": AUTHORITY.root_key, "issuer": AUTHORITY.root_name}),
    )
    add(
        "a certificate the root signed under the name of the intermediate",
        "V3",
        proofs_of("root signed", leaf={"signer": AUTHORITY.root_key}),
    )
    add(
        "a certificate whose signature is not the one of its signed part",
        "V3",
        of_bundle("flipped", raw(lambda der: b64(der[:30] + bytes([der[30] ^ 1]) + der[31:]))),
    )
    add(
        "an intermediate that the root of the trust did not issue",
        "V3",
        proofs_of("other root"),
        trust="test-other-root",
    )
    add(
        "a root and an intermediate that ended before the time of the log entry",
        "V3",
        proofs_of("expired", authority=EXPIRED),
        trust="test-expired",
    )
    add(
        "an intermediate that is not the certificate of a certificate authority",
        "V3",
        proofs_of("no authority", authority=NO_AUTHORITY),
        trust="test-intermediate-without-authority",
    )


def cases_of_the_identity():
    identity = identity_of(RELEASE, COMMIT)
    build = f"{REPOSITORY}/{BUILDER['workflow']}"
    caller = f"{REPOSITORY}/{RELEASE_WORKFLOW}"
    others = {
        8: ["https://gitlab.com", ISSUER + "/"],
        # The workflow of the job that signed: another workflow file of the repository at
        # the commit of the build workflow, the build workflow of a repository of another
        # owner, the release workflow itself at the tag (a job that no workflow called), the
        # build workflow without a ref and with an empty one, and a file whose name begins
        # with its name.
        9: [
            f"{REPOSITORY}/.github/workflows/other.yml@{BUILDER['commit']}",
            f"https://github.com/someone/credential-enclave/{BUILDER['workflow']}@{BUILDER['commit']}",
            f"{caller}@refs/tags/{RELEASE}",
            build,
            build + "@",
            f"{build}.disabled@{BUILDER['commit']}",
        ],
        10: [other_hex(BUILDER["commit"]), BUILDER["commit"][1:], BUILDER["commit"].upper()],
        11: ["self-hosted", "github-hosted "],
        12: ["https://github.com/someone/credential-enclave", REPOSITORY + "/"],
        13: [other_hex(COMMIT), COMMIT[1:]],
        14: ["refs/heads/main", f"refs/tags/{RELEASE}-rc.1", f"refs/heads/tags/{RELEASE}", RELEASE],
        15: ["1400118249", "01400118248"],
        17: ["151645825"],
        20: ["workflow_dispatch", "release"],
        22: ["private", "internal"],
    }
    for number, values in others.items():
        for value in values:
            add(
                f"a certificate whose extension {number} is {json.dumps(value)} in the place of {json.dumps(identity[number])}",
                "V6",
                proofs_of(f"identity {number} {value}", identity={number: value}),
            )
        add(
            f"a certificate without the extension {number}",
            "V6",
            proofs_of(f"identity {number} none", identity={number: None}),
        )
    add(
        "a certificate whose extension 11 is a text that is no DER",
        "V6",
        proofs_of(
            "runner raw",
            identity={11: None},
            leaf={"more": [der_extension(OID["fulcio"] + ".11", b"github-hosted")]},
        ),
    )
    add(
        "a certificate whose extension 11 is the DER of another type of string",
        "V6",
        proofs_of(
            "runner printable",
            identity={11: None},
            leaf={"more": [der_extension(OID["fulcio"] + ".11", der_printable("github-hosted"))]},
        ),
    )
    add(
        "a certificate whose extension 11 holds bytes behind its string",
        "V6",
        proofs_of(
            "runner bytes behind",
            identity={11: None},
            leaf={"more": [der_extension(OID["fulcio"] + ".11", der_utf8("github-hosted") + b"\x00")]},
        ),
    )
    # The text before the last `@` of the extension 9 names the file: a ref that holds an
    # `@` leaves a part of itself in that text.
    add(
        "the build workflow named by a ref that holds an @",
        "V6",
        proofs_of("ref with at", identity={9: build + "@refs/heads/a@" + BUILDER["commit"]}),
    )
    add(
        "the build workflow called at another commit",
        "V6",
        proofs_of(
            "other commit",
            identity={9: f"{build}@{other_hex(BUILDER['commit'])}", 10: other_hex(BUILDER["commit"])},
        ),
    )
    add(
        "the file of one build workflow at the commit of the other",
        "V6",
        proofs_of(
            "mixed builders",
            identity={9: f"{build}@{SECOND_BUILDER['commit']}", 10: SECOND_BUILDER["commit"]},
        ),
    )
    add(
        "the attestation of a job of the release workflow itself, which no workflow called",
        "V6",
        proofs_of("release workflow", identity={9: f"{caller}@refs/tags/{RELEASE}", 10: COMMIT}),
    )
    add(
        "the attestation of a run in another repository, whose workflow called the build workflow",
        "V6",
        proofs_of(
            "other repository",
            identity={
                12: "https://github.com/another-owner/another-repository",
                15: "999999991",
                16: "https://github.com/another-owner",
                17: "999999992",
                18: f"https://github.com/another-owner/another-repository/{RELEASE_WORKFLOW}@refs/tags/{RELEASE}",
                21: "https://github.com/another-owner/another-repository/actions/runs/1/attempts/1",
            },
        ),
    )
    add(
        "the attestation of the run of another tag of the commit",
        "V6",
        proofs_of("other tag", release=RELEASE + "-rc.1", predicate=json.loads(statement_of())),
    )
    add(
        "the attestation of a run at another commit",
        "V6",
        proofs_of("other run commit", commit=other_hex(COMMIT), predicate=json.loads(statement_of())),
    )
    add(
        "proofs that hold for a trust that names no build workflow",
        "V6",
        proofs_of("no builder"),
        trust="test-no-builder",
    )


def cases_of_the_signature():
    add("an envelope another key signed", "V5", proofs_of("other signer", signer=OTHER_KEY))
    add("a certificate with a key on P-384", "V5", proofs_of("p384", curve="p384"))
    add(
        "a signature over another payload type",
        "V5",
        proofs_of("signed type", signed_type="application/vnd.other+json"),
    )

    # The checks of the entry of the log come after this one: the entry records the signature
    # the log took, and the signature of the envelope is refused before it is compared.
    def signature(change):
        def edit(bundle):
            item = bundle["dsseEnvelope"]["signatures"][0]
            item["sig"] = change(base64.b64decode(item["sig"]))

        return edit

    for name, change in [
        ("a signature with a byte behind it", lambda der: b64(der + b"\x00")),
        ("a signature in base64url", lambda der: b64u(der) + "-"),
        ("a signature of the two integers without the sequence", lambda der: b64(der[2:])),
    ]:
        add(f"an envelope with {name}", "V5", proofs_of(name, bundle=signature(change)))


def cases_of_the_log():
    def of_entry(name, change, **given):
        return proofs_of(name, entry=change, **given)

    def of_record(name, change, **given):
        return proofs_of(name, record=change, **given)

    add("a log entry of a log the trust does not have", "V4", proofs_of("other log", log=OTHER_LOG))
    add(
        "a log entry that names a log the trust does not have",
        "V4",
        of_entry("names other log", lambda entry: entry["logId"].update({"keyId": b64(OTHER_LOG.id)})),
    )
    add("a log entry without the identifier of its log", "V4", of_entry("no log id", lambda entry: entry.pop("logId")))
    add(
        "a log entry whose log identifier is in hexadecimal",
        "V4",
        of_entry("hex log id", lambda entry: entry["logId"].update({"keyId": LOG.id.hex()})),
    )
    add(
        "a log entry whose log identifier is the first 31 bytes of the identifier",
        "V4",
        of_entry("short log id", lambda entry: entry["logId"].update({"keyId": b64(LOG.id[:31])})),
    )
    add("a log entry of another kind", "V4", of_record("kind", lambda record: record.update({"kind": "intoto"})))
    add("a log entry of another version", "V4", of_record("version", lambda record: record.update({"apiVersion": "0.0.2"})))
    add("a log entry whose body is a JSON array", "V4", proofs_of("body array", body=b"[]"))
    add("a log entry whose body is no JSON", "V4", proofs_of("body text", body=b"record"))
    add("a log entry without a body", "V4", of_entry("no body", lambda entry: entry.pop("canonicalizedBody")))
    add(
        "a log entry of another payload",
        "V4",
        of_record("payload hash", lambda record: record["spec"]["payloadHash"].update({"value": sha256(b"another payload").hex()})),
    )
    add(
        "a log entry of the hash of the payload in upper case",
        "V4",
        of_record("upper hash", lambda record: record["spec"]["payloadHash"].update({"value": record["spec"]["payloadHash"]["value"].upper()})),
    )
    add(
        "a log entry of a hash of another algorithm",
        "V4",
        of_record("algorithm", lambda record: record["spec"]["payloadHash"].update({"algorithm": "sha512"})),
    )
    add(
        "a log entry of another signature",
        "V4",
        of_record("signature", lambda record: record["spec"]["signatures"][0].update({"signature": b64(OTHER_KEY.sign(b"x"))})),
    )
    add(
        "a log entry of two signatures",
        "V4",
        of_record("two", lambda record: record["spec"]["signatures"].append(record["spec"]["signatures"][0])),
    )
    add(
        "a log entry without a signature",
        "V4",
        of_record("none", lambda record: record["spec"].update({"signatures": []})),
    )
    other_leaf = AUTHORITY.issue(OTHER_KEY, identity_of(RELEASE, COMMIT), serial="another certificate")
    add(
        "a log entry of another certificate",
        "V4",
        of_record("certificate", lambda record: record["spec"]["signatures"][0].update({"verifier": b64(pem("CERTIFICATE", other_leaf).encode())})),
    )
    add(
        "a log entry whose certificate is the DER without its PEM",
        "V4",
        of_record(
            "der verifier",
            lambda record: record["spec"]["signatures"][0].update(
                {"verifier": b64(pem_bytes(base64.b64decode(record["spec"]["signatures"][0]["verifier"]).decode()))}
            ),
        ),
    )
    add(
        "another index than the log signed",
        "V4",
        of_entry("index", lambda entry: entry.update({"logIndex": str(int(entry["logIndex"]) + 1)})),
    )
    add(
        "another time than the log signed, inside the validity of the certificate",
        "V4",
        of_entry("time", lambda entry: entry.update({"integratedTime": str(int(entry["integratedTime"]) + 1)})),
    )
    add("a log entry without an index", "V4", of_entry("no index", lambda entry: entry.pop("logIndex")))
    add("a log entry without an inclusion promise", "V4", of_entry("no promise", lambda entry: entry.pop("inclusionPromise")))
    add(
        "a signed entry timestamp of another key",
        "V4",
        of_entry(
            "promise key",
            lambda entry: entry["inclusionPromise"].update(
                {"signedEntryTimestamp": OTHER_LOG.promise(entry["canonicalizedBody"], int(entry["integratedTime"]), int(entry["logIndex"]), LOG.id)}
            ),
        ),
    )
    add(
        "a signed entry timestamp with a byte behind the signature",
        "V4",
        of_entry(
            "promise byte",
            lambda entry: entry["inclusionPromise"].update(
                {"signedEntryTimestamp": b64(base64.b64decode(entry["inclusionPromise"]["signedEntryTimestamp"]) + b"\x00")}
            ),
        ),
    )
    add(
        "a signed entry timestamp over another body",
        "V4",
        of_entry(
            "promise body",
            lambda entry: entry["inclusionPromise"].update(
                {"signedEntryTimestamp": LOG.promise(b64(b'{"another":"body"}'), int(entry["integratedTime"]), int(entry["logIndex"]))}
            ),
        ),
    )

    def proof(change):
        return lambda entry: change(entry["inclusionProof"])

    add("a changed hash of the audit path", "V4", of_entry("hash", proof(lambda proof: proof["hashes"].__setitem__(0, b64(sha256(base64.b64decode(proof["hashes"][0])))))))
    add("an audit path without its last hash", "V4", of_entry("short", proof(lambda proof: proof["hashes"].pop())))
    add("an audit path with one hash more", "V4", of_entry("long", proof(lambda proof: proof["hashes"].append(b64(fixed("one hash more"))))))
    add("an audit path whose hash is in hexadecimal", "V4", of_entry("hex hash", proof(lambda proof: proof["hashes"].__setitem__(0, base64.b64decode(proof["hashes"][0]).hex()))))
    add("an audit path whose hash has 31 bytes", "V4", of_entry("hash 31", proof(lambda proof: proof["hashes"].__setitem__(0, b64(base64.b64decode(proof["hashes"][0])[:31])))))
    add("an audit path that is an object", "V4", of_entry("path object", proof(lambda proof: proof.update({"hashes": {"0": proof["hashes"][0]}}))))
    add("the index of another leaf", "V4", of_entry("leaf", proof(lambda proof: proof.update({"logIndex": "4"}))))
    add("an index that is not below the size of the tree", "V4", of_entry("beyond", proof(lambda proof: proof.update({"logIndex": "11"}))))
    add("an index written with a leading zero", "V4", of_entry("leading zero", proof(lambda proof: proof.update({"logIndex": "05"}))))
    add("the size of a larger tree", "V4", of_entry("size", proof(lambda proof: proof.update({"treeSize": "4096"}))))
    add("a tree without a size", "V4", of_entry("no size", proof(lambda proof: proof.pop("treeSize"))))
    add("a root hash of 31 bytes", "V4", of_entry("root 31", proof(lambda proof: proof.update({"rootHash": b64(base64.b64decode(proof["rootHash"])[:31])}))))
    add("another root hash than the audit path leads to", "V4", of_entry("root", proof(lambda proof: proof.update({"rootHash": b64(fixed("another root"))}))))
    add(
        "an audit path of 65 hashes",
        "V4",
        of_entry("65", proof(lambda proof: proof.update({"hashes": [proof["hashes"][0]] * 65}))),
    )
    add("a log entry without an inclusion proof", "V4", of_entry("no proof", lambda entry: entry.pop("inclusionProof")))
    # The index of the only leaf of a tree, written as the zero with a sign: no count.
    lone = proofs_of("signed zero", leaf_index=0, tree_size=1)
    written = compact(lone)
    old = '"inclusionProof":{"logIndex":"0"'
    assert written.count(old) == 1
    add("an index that is the zero with a sign", "V4", lone, text=written.replace(old, '"inclusionProof":{"logIndex":-0'))
    add("an index that is the number zero", "V4", lone, text=written.replace(old, '"inclusionProof":{"logIndex":0'))

    def checkpoint_of(change):
        def edit(entry):
            proof = entry["inclusionProof"]
            proof["checkpoint"]["envelope"] = change(
                proof["checkpoint"]["envelope"],
                int(proof["treeSize"]),
                base64.b64decode(proof["rootHash"]),
            )

        return edit

    add("a checkpoint another key signed", "V4", of_entry("checkpoint key", checkpoint_of(lambda text, size, root: LOG.checkpoint(size, root, signer=OTHER_LOG))))
    add("a checkpoint of a tree of another size", "V4", of_entry("checkpoint size", checkpoint_of(lambda text, size, root: LOG.checkpoint(size + 1, root))))
    add("a checkpoint of another root", "V4", of_entry("checkpoint root", checkpoint_of(lambda text, size, root: LOG.checkpoint(size, fixed("checkpoint root")))))
    add("a checkpoint without its signature lines", "V4", of_entry("checkpoint lines", checkpoint_of(lambda text, size, root: text[: text.index("\n\n") + 2])))
    add("a checkpoint without the empty line", "V4", of_entry("checkpoint empty line", checkpoint_of(lambda text, size, root: text.replace("\n\n", "\n"))))
    add(
        "a checkpoint with a changed note under the signature of the log",
        "V4",
        of_entry("checkpoint note", checkpoint_of(lambda text, size, root: text.replace("rekor.vectors.test -", "rekor.vectors.tesu -"))),
    )
    add(
        "a checkpoint with a second line of the log that is no signature of the log",
        "V4",
        of_entry(
            "checkpoint second",
            checkpoint_of(lambda text, size, root: text + LOG.checkpoint(size, fixed("second line")).split("\n\n")[1]),
        ),
    )
    add(
        "a checkpoint whose size has a leading zero, signed by the log",
        "V4",
        of_entry("checkpoint zero", checkpoint_of(lambda text, size, root: leading_zero_checkpoint(size, root))),
    )
    add("a checkpoint that is a number", "V4", of_entry("checkpoint number", proof(lambda proof: proof["checkpoint"].update({"envelope": 7}))))
    add("a log entry without a checkpoint", "V4", of_entry("no checkpoint", proof(lambda proof: proof.pop("checkpoint"))))


def leading_zero_checkpoint(size: int, root: bytes) -> str:
    note = f"{LOG.origin}\n0{size}\n{b64(root)}\n"
    signature = LOG.id[:4] + LOG.key.sign(note.encode())
    return f"{note}\n— {LOG.origin.split(' ')[0]} {b64(signature)}\n"


def pem_bytes(text: str) -> bytes:
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    text = text.strip()
    return base64.b64decode("".join(text[len(begin) : -len(end)].split()))


def cases_of_the_predicate():
    stated = json.loads(statement_of())
    add("a statement of another predicate type", "V7", proofs_of("type", predicate_type="https://slsa.dev/provenance/v1"))
    add(
        "an in-toto statement without a predicate type",
        "V7",
        proofs_of("no type", in_toto={"_type": "https://in-toto.io/Statement/v1", "subject": [], "predicate": stated}),
    )
    add("a predicate of another release", "V7", proofs_of("release", predicate=dict(stated, release=RELEASE + "-rc.1")))
    for field in ["pcr0", "pcr1", "pcr2"]:
        add(
            f"a predicate of another {field}",
            "V7",
            proofs_of("predicate " + field, predicate=dict(stated, **{field: other_hex(stated[field])})),
        )
        add(
            f"a predicate with {field} in upper case",
            "V7",
            proofs_of("predicate upper " + field, predicate=dict(stated, **{field: stated[field].upper()})),
        )
    add(
        "a predicate of another git_commit",
        "V7",
        proofs_of("commit", predicate=dict(stated, git_commit=other_hex(COMMIT))),
    )
    for field in ["release", "git_commit", "pcr0"]:
        without = dict(stated)
        del without[field]
        add(f"a predicate without {field}", "V7", proofs_of("predicate without " + field, predicate=without))
    add("a predicate that is an array", "V7", proofs_of("array", predicate=[stated]))
    add("a predicate that is the text of the statement", "V7", proofs_of("text", predicate=statement_of().decode()))
    add("an in-toto statement without a predicate", "V7", proofs_of("none", in_toto={"_type": "https://in-toto.io/Statement/v1", "subject": [], "predicateType": PREDICATE_TYPE}))


def published(release: str) -> tuple[bytes, dict]:
    directory = PUBLISHED / release
    statement = (directory / "measurements.json").read_bytes()
    bundle = json.loads((directory / "release-statement.sigstore.json").read_text())
    return statement, bundle


def cases_of_published_releases():
    """The proofs of two published releases, and such proofs with one value changed."""
    statement, bundle = published("v2.4.0-rc.1")
    stated = json.loads(statement)
    measurement = {name: stated[name] for name in ["pcr0", "pcr1", "pcr2"]}
    earlier_statement, earlier_bundle = published("v2.3.0")
    earlier = json.loads(earlier_statement)
    earlier_measurement = {name: earlier[name] for name in ["pcr0", "pcr1", "pcr2"]}

    def proofs(change=None, of_statement=None):
        value = {
            "statement": b64u(of_statement if of_statement is not None else statement),
            "attestation": copy.deepcopy(bundle),
        }
        if change:
            change(value["attestation"])
        return value

    # The cases of this release candidate are verified with the certificates of Sigstore, the
    # key of Rekor and the build workflow at the commit that attested it.
    def source(name, rule, value, **more):
        add(
            "release v2.4.0-rc.1: " + name,
            rule,
            value,
            trust="sigstore-build-workflow-v2.4.0-rc.1",
            measurement=more.pop("measurement", measurement),
            **more,
        )

    source("the published proofs, for a trust that names the build workflow at the commit that attested them", None, proofs())
    add(
        "release v2.4.0-rc.1: the published proofs, which the build workflow at an earlier commit attested",
        "V6",
        proofs(),
        trust="source",
        measurement=measurement,
    )
    add(
        "release v2.4.0-rc.1: the published proofs, for a trust that names another build workflow",
        "V6",
        proofs(),
        trust="sigstore-release-workflow-v2.3.0",
        measurement=measurement,
    )
    for field in ["pcr0", "pcr1", "pcr2"]:
        source(
            f"the measurement of another enclave: one character of {field}",
            "V1",
            proofs(),
            measurement=dict(measurement, **{field: other_hex(measurement[field])}),
        )
    changed = statement.replace(stated["pcr0"].encode(), other_hex(stated["pcr0"]).encode())
    source(
        "a statement of another pcr0, for the measurement it states",
        "V7",
        proofs(of_statement=changed),
        measurement=dict(measurement, pcr0=other_hex(measurement["pcr0"])),
    )
    source(
        "a statement of another release",
        "V6",
        proofs(of_statement=statement.replace(b'"v2.4.0-rc.1"', b'"v2.4.0-rc.2"')),
    )
    source(
        "a statement of another commit",
        "V6",
        proofs(of_statement=statement.replace(stated["git_commit"].encode(), other_hex(stated["git_commit"]).encode())),
    )
    source(
        "a statement whose inputs are not those of the predicate",
        None,
        proofs(of_statement=statement.replace(b'"image/toolchain"', b'"image/other"')),
    )
    source(
        "the statement of release v2.3.0 with the attestation of release v2.4.0-rc.1",
        "V6",
        proofs(of_statement=earlier_statement),
        measurement=earlier_measurement,
    )

    def entry(change):
        return lambda attestation: change(entry_of(attestation))

    source("the time of the log entry one second later", "V4", proofs(entry(lambda item: item.update({"integratedTime": str(int(item["integratedTime"]) + 1)}))))
    source("the time of the log entry an hour later", "V3", proofs(entry(lambda item: item.update({"integratedTime": str(int(item["integratedTime"]) + 3_600)}))))
    source("the index of the log entry one higher", "V4", proofs(entry(lambda item: item.update({"logIndex": str(int(item["logIndex"]) + 1)}))))
    source(
        "the certificate of release v2.3.0",
        "V3",
        proofs(lambda attestation: attestation["verificationMaterial"].update({"certificate": earlier_bundle["verificationMaterial"]["certificate"]})),
    )

    def payload(attestation):
        decoded = base64.b64decode(attestation["dsseEnvelope"]["payload"])
        digest = json.loads(decoded)["subject"][0]["digest"]["sha256"].encode()
        assert decoded.count(digest) == 1
        attestation["dsseEnvelope"]["payload"] = b64(decoded.replace(digest, other_hex(digest.decode()).encode()))

    source("a payload with another digest of the enclave image file", "V5", proofs(payload))

    def signature(attestation):
        item = attestation["dsseEnvelope"]["signatures"][0]
        der = bytearray(base64.b64decode(item["sig"]))
        der[-1] ^= 1
        item["sig"] = b64(bytes(der))

    source("a signature with one bit changed", "V5", proofs(signature))
    source("the envelope of release v2.3.0", "V5", proofs(lambda attestation: attestation.update({"dsseEnvelope": earlier_bundle["dsseEnvelope"]})))
    source(
        "the log entry of release v2.3.0",
        "V3",
        proofs(lambda attestation: attestation["verificationMaterial"].update({"tlogEntries": earlier_bundle["verificationMaterial"]["tlogEntries"]})),
    )
    source("the body of the log entry of release v2.3.0", "V4", proofs(entry(lambda item: item.update({"canonicalizedBody": entry_of(earlier_bundle)["canonicalizedBody"]}))))
    source("a log entry without its inclusion promise", "V4", proofs(entry(lambda item: item.pop("inclusionPromise"))))
    source("a log entry without its inclusion proof", "V4", proofs(entry(lambda item: item.pop("inclusionProof"))))
    source(
        "the first hash of the audit path changed",
        "V4",
        proofs(entry(lambda item: item["inclusionProof"]["hashes"].__setitem__(0, b64(sha256(base64.b64decode(item["inclusionProof"]["hashes"][0])))))),
    )
    source("the checkpoint of release v2.3.0", "V4", proofs(entry(lambda item: item["inclusionProof"].update({"checkpoint": entry_of(earlier_bundle)["inclusionProof"]["checkpoint"]}))))
    source("the size of the tree one higher", "V4", proofs(entry(lambda item: item["inclusionProof"].update({"treeSize": str(int(item["inclusionProof"]["treeSize"]) + 1)}))))
    source("two copies of the log entry", "V2", proofs(lambda attestation: attestation["verificationMaterial"]["tlogEntries"].append(entry_of(attestation))))

    def earlier_proofs():
        return {"statement": b64u(earlier_statement), "attestation": copy.deepcopy(earlier_bundle)}

    add(
        "release v2.3.0: the published statement and attestation, which a job of the release workflow made",
        "V6",
        earlier_proofs(),
        trust="source",
        measurement=earlier_measurement,
    )
    add(
        "release v2.3.0: the published statement and attestation, for a trust that names the release workflow of that tag",
        None,
        earlier_proofs(),
        trust="sigstore-release-workflow-v2.3.0",
        measurement=earlier_measurement,
    )


DESCRIPTION = (
    "Release proofs (docs/protocol.md section 9) with the verdict of each, for the two "
    "verifiers of this repository: the node (protocol/src/release_proofs.rs) and the secure "
    "program of the app (secure-program/secure-program.js). Both give `accepted` on every "
    "case. `release_proofs_text` is the JSON text of the proofs: a verifier parses it with "
    "its own reader of JSON, and a text that reader refuses is refused. `measurement` is "
    "the measurement the proofs are verified for, `trust` names what they are verified "
    "with, `release` is the release the statement names (for proofs that hold), and `rule` "
    "names the rule that refuses the others: V1 to V7 of section 9, or `form` for a value "
    "that is no release proofs (no JSON, no object with a text `statement` and an object "
    "`attestation`, or more than 32 arrays and objects inside one another). A trust of `trusts` holds the root certificate and the "
    "intermediate certificate of the certificate authority (`fulcio_root`, "
    "`fulcio_intermediate`: DER in base64url), the keys of the transparency logs "
    "(`log_keys`: the DER of each SubjectPublicKeyInfo in base64url), the issuer of the "
    "tokens, the repository with its identifier and the identifier of its owner, and the "
    "build workflows (`builders`: the path of each workflow file and its commit). The "
    "trust `source` has no values here: it is the constants of the verifier itself, the "
    "certificates of Sigstore, the key of Rekor and the build workflows of this "
    "repository. The file is written by protocol/vectors/release_proofs.py."
)


def generate() -> str:
    CASES.clear()
    cases_that_hold()
    cases_of_the_form()
    cases_of_the_statement()
    cases_of_the_bundle()
    cases_of_the_encodings()
    cases_of_the_certificate()
    cases_of_the_identity()
    cases_of_the_signature()
    cases_of_the_log()
    cases_of_the_predicate()
    cases_of_published_releases()
    document = {"v": 1, "description": DESCRIPTION, "trusts": trusts(), "cases": CASES}
    return json.dumps(document, indent=1) + "\n"


def main() -> int:
    generated = generate()
    arguments = sys.argv[1:]
    if arguments == []:
        OUTPUT.write_text(generated)
        print(f"wrote {OUTPUT}: {len(CASES)} cases")
        return 0
    if arguments == ["--check"]:
        if OUTPUT.read_text() == generated:
            print(f"{OUTPUT} is up to date")
            return 0
        print(f"{OUTPUT} differs from a fresh run", file=sys.stderr)
        return 1
    print("unknown arguments: expected none or --check", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
