//! A probe of the mail reads against an IMAP server of another implementation.
//!
//! The tests of the mail calls run against a stand-in of this repository, which answers in
//! the forms its author wrote. This probe runs the reads of a node against a server program
//! and compares what the node returns with what another client read from the same mailbox. It
//! is not part of `cargo test`: it needs the server.
//!
//! ```text
//! MAIL_PROBE_IMAP=127.0.0.1:10993 MAIL_PROBE_CERTIFICATE=certificate.der \
//! MAIL_PROBE_MANIFEST=manifest.json \
//!     cargo test -p credential-enclave mail_probe -- --ignored --nocapture
//! ```
//!
//! - `MAIL_PROBE_IMAP`: the address of an IMAP server over TLS. It presents a certificate for
//!   the name `imap.naver.com` and accepts the login `tester` with the password of the mail
//!   tests.
//! - `MAIL_PROBE_CERTIFICATE`: a file with that certificate in DER. The node of the probe
//!   trusts it for the mail host and nothing else.
//! - `MAIL_PROBE_MANIFEST`: what another client read from the mailbox, as JSON:
//!   `{"folders":[{"name","uid_validity","uid_next","messages":[{"uid","size",
//!   "header_sha256","body_sha256"}]}]}`. The two hashes are the SHA-256, in lower-case
//!   hexadecimal, of the bytes the server returns for `BODY[HEADER]` and for `BODY[]`.
//!
//! The probe lists the folders, pages through every folder with searches of 50 messages,
//! reads every message, and asks for a message of another generation, for a message that is
//! not there and for folders that do not exist. It prints the counts and the times as JSON.

use std::collections::BTreeSet;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::mail::{harness_at, request};
use crate::state::Limits;

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
#[ignore = "needs an IMAP server: see the head of this file"]
#[expect(
    clippy::print_stdout,
    reason = "the probe prints the counts and the times of its run"
)]
async fn a_mailbox_of_an_imap_server_is_read_as_another_client_reads_it() {
    let address = std::env::var("MAIL_PROBE_IMAP")
        .expect("MAIL_PROBE_IMAP")
        .parse()
        .expect("an address");
    let certificate = std::fs::read(std::env::var("MAIL_PROBE_CERTIFICATE").unwrap()).unwrap();
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MAIL_PROBE_MANIFEST").unwrap()).unwrap(),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate)).unwrap();
    let (harness, _app, record) = harness_at(roots, address, Limits::default()).await;
    let started = Instant::now();
    let mut calls = 0u64;

    let (status, meta, body) =
        request(&harness, &record, "read", json!({"action":"folders"}), b"").await;
    calls += 1;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    let listing: Value = serde_json::from_slice(&body).unwrap();
    let listed: BTreeSet<&str> = listing["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|folder| folder["name"].as_str().unwrap())
        .collect();

    let (mut messages_read, mut bytes_read, mut pages) = (0u64, 0u64, 0u64);
    let mut longest_read_ms = 0u128;
    for folder in manifest["folders"].as_array().unwrap() {
        let name = folder["name"].as_str().unwrap();
        assert!(listed.contains(name), "{name} is not among {listed:?}");
        let validity = folder["uid_validity"].as_u64().unwrap();
        let expected = folder["messages"].as_array().unwrap();
        // The pages of the folder, the latest messages first.
        let mut found = Vec::new();
        let mut before: Option<u64> = None;
        loop {
            let mut params = json!({"action":"search","mailbox":name,"limit":50});
            if let Some(before) = before {
                params["before_uid"] = json!(before);
                params["uid_validity"] = json!(validity);
            }
            let (status, meta, body) = request(&harness, &record, "read", params, b"").await;
            calls += 1;
            pages += 1;
            assert_eq!(
                (status, meta["status"].as_u64()),
                (200, Some(200)),
                "{name}: {meta}"
            );
            let page: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(page["uid_validity"].as_u64(), Some(validity), "{name}");
            found.extend(page["messages"].as_array().unwrap().iter().cloned());
            match page["next_uid"].as_u64() {
                Some(next) => before = Some(next),
                None => break,
            }
        }
        let mut uids: Vec<u64> = found
            .iter()
            .map(|row| row["uid"].as_u64().unwrap())
            .collect();
        assert!(uids.windows(2).all(|pair| pair[0] > pair[1]), "{name}");
        uids.reverse();
        let expected_uids: Vec<u64> = expected
            .iter()
            .map(|row| row["uid"].as_u64().unwrap())
            .collect();
        assert_eq!(uids, expected_uids, "{name}");
        for row in &found {
            let uid = row["uid"].as_u64().unwrap();
            let reference = expected
                .iter()
                .find(|other| other["uid"].as_u64() == Some(uid))
                .unwrap();
            assert_eq!(row["size"], reference["size"], "{name} {uid}");
            let header = STANDARD
                .decode(row["headers_b64"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                hex(&header),
                reference["header_sha256"].as_str().unwrap(),
                "{name} {uid}"
            );
        }
        for reference in expected {
            let uid = reference["uid"].as_u64().unwrap();
            let read_started = Instant::now();
            let (status, meta, body) = request(
                &harness,
                &record,
                "read",
                json!({"action":"read","mailbox":name,"uid":uid,"uid_validity":validity}),
                b"",
            )
            .await;
            longest_read_ms = longest_read_ms.max(read_started.elapsed().as_millis());
            calls += 1;
            assert_eq!(
                (status, meta["status"].as_u64()),
                (200, Some(200)),
                "{name} {uid}: {meta}"
            );
            assert_eq!(
                hex(&body),
                reference["body_sha256"].as_str().unwrap(),
                "{name} {uid}"
            );
            messages_read += 1;
            bytes_read += body.len() as u64;
        }
        if let Some(reference) = expected.first() {
            // Another generation of the folder, and a message that is not in it.
            let uid = reference["uid"].as_u64().unwrap();
            let (_, meta, _) = request(
                &harness,
                &record,
                "read",
                json!({"action":"read","mailbox":name,"uid":uid,"uid_validity":validity + 1}),
                b"",
            )
            .await;
            assert_eq!(meta["status"], 409, "{name}");
            let (_, meta, _) = request(
                &harness,
                &record,
                "read",
                json!({"action":"read","mailbox":name,"uid":4_000_000_000u64,"uid_validity":validity}),
                b"",
            )
            .await;
            assert_eq!(meta["status"], 404, "{name}");
            calls += 2;
        }
    }

    // A search whose words go to the server as literals.
    let (status, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"search","subject":"회의","since":"2026-01-01","limit":50}),
        b"",
    )
    .await;
    calls += 1;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    let page: Value = serde_json::from_slice(&body).unwrap();
    let found_by_subject = page["messages"].as_array().unwrap().len();

    // Folders that do not exist. The server names the folder in its refusal, and one of the
    // names ends in the form of a literal declaration: the refusal is one line all the same.
    let mut refusal_ms = Vec::new();
    for missing in ["No Such Folder", "missing{100000}"] {
        let refused = Instant::now();
        let (status, meta, _) = request(
            &harness,
            &record,
            "read",
            json!({"action":"search","mailbox":missing}),
            b"",
        )
        .await;
        calls += 1;
        assert_eq!(
            (status, meta["code"].as_str()),
            (502, Some("provider_unreachable")),
            "{missing}"
        );
        refusal_ms.push(refused.elapsed().as_millis());
    }

    let health = harness.health().await;
    let connections = harness
        .platform
        .connections()
        .iter()
        .filter(|(host, _)| host == "imap.naver.com")
        .count();
    println!(
        "{}",
        json!({
            "probe": "mail reads against an IMAP server",
            "server": address.to_string(),
            "calls": calls,
            "folders_listed": listed.len(),
            "folders_read": manifest["folders"].as_array().unwrap().len(),
            "search_pages": pages,
            "messages_read": messages_read,
            "message_bytes_read": bytes_read,
            "messages_found_by_subject": found_by_subject,
            "refusal_of_a_missing_folder_ms": refusal_ms,
            "longest_read_ms": longest_read_ms,
            "elapsed_ms": started.elapsed().as_millis(),
            "imap_connections": connections,
            "egress": health["egress"],
            "idle_connections": health["state"]["idle_connections"],
        })
    );
}
