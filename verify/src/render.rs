//! The report of the tool: a head, one block per node and the summary line.

use std::fmt::Write;

use crate::arguments::{hex, Measurements};
use crate::evaluate::{NodeReport, Outcome};

/// The exit status when every node passed.
pub const EXIT_PASSED: u8 = 0;
/// The exit status when at least one node failed.
pub const EXIT_FAILED: u8 = 1;
/// The exit status when there is no result: the arguments, a file, the network, the HTTP
/// status or the response.
pub const EXIT_NO_RESULT: u8 = 2;

/// Everything the report shows.
pub struct Report<'a> {
    /// What was asked: the address of the attestation route, or the path of the stored
    /// document.
    pub source: &'a str,
    /// The nonce that was sent, or the nonce given with the stored document.
    pub nonce: &'a [u8],
    pub expected: Option<&'a Measurements>,
    pub nodes: &'a [NodeReport],
}

impl Report<'_> {
    /// `EXIT_PASSED` when every node passed, `EXIT_FAILED` when at least one failed.
    pub fn exit_status(&self) -> u8 {
        if self.nodes.iter().all(NodeReport::passed) {
            EXIT_PASSED
        } else {
            EXIT_FAILED
        }
    }

    /// The text of the report. Its last line is the summary.
    pub fn render(&self) -> String {
        let mut out = String::new();
        line(&mut out, 0, "source", self.source);
        line(&mut out, 0, "nonce", &hex(self.nonce));
        match self.expected {
            Some(expected) => {
                let origin = match &expected.release {
                    Some(release) => format!("release {} of {}", shown(release), expected.origin),
                    None => expected.origin.clone(),
                };
                line(&mut out, 0, "expected", &origin);
                for (index, pcr) in expected.pcrs.iter().enumerate() {
                    line(&mut out, 2, &format!("pcr{index}"), &hex(pcr));
                }
            }
            None => line(
                &mut out,
                0,
                "expected",
                "nothing: no measurement is compared",
            ),
        }

        for (index, node) in self.nodes.iter().enumerate() {
            let _ = writeln!(out, "\nnode {} of {}", index + 1, self.nodes.len());
            render_node(&mut out, node, self.expected.is_some());
        }

        let count = self.nodes.len();
        let passed = self.nodes.iter().filter(|node| node.passed()).count();
        let _ = write!(
            out,
            "\nsummary: {count} {}: {passed} passed, {} failed.",
            if count == 1 { "node" } else { "nodes" },
            count - passed
        );
        if self.expected.is_none() {
            out.push_str(" No measurement was compared: no expected values were given.");
        }
        out.push('\n');
        out
    }
}

/// The block of one node. `compared` says whether there were expected measurements.
fn render_node(out: &mut String, node: &NodeReport, compared: bool) {
    if let Some(claimed) = &node.claimed {
        out.push_str("  response (not verified, the checks compare the node with the document)\n");
        line(out, 4, "node", &shown(&claimed.node));
        if let Some(release) = &claimed.release {
            line(out, 4, "release", &shown(release));
        }
        line(out, 4, "platform", &shown(&claimed.platform));
    }
    match &node.stated {
        Some(stated) => {
            out.push_str("  document\n");
            line(out, 4, "time", &utc(stated.time_ms));
            if let Some(module_id) = &stated.module_id {
                line(out, 4, "module_id", &shown(module_id));
            }
            for (index, pcr) in stated.pcrs.iter().flatten().enumerate() {
                line(out, 4, &format!("pcr{index}"), &hex(pcr));
            }
            if let Some(node) = &stated.node {
                line(out, 4, "node", &shown(node));
            }
            if let Some(release) = &stated.release {
                line(out, 4, "release", &shown(release));
            }
            // What the binding says about the log store of the node: the bucket the node
            // writes every log entry to before it acts, or that it has none.
            if stated.node.is_some() {
                let named = match &stated.log_store {
                    Some(log_store) => format!(
                        "{} in {}",
                        shown(log_store.bucket()),
                        shown(log_store.region())
                    ),
                    None => "none".to_string(),
                };
                line(out, 4, "log_store", &named);
            }
        }
        None => out.push_str("  document: nothing it states is known\n"),
    }
    out.push_str("  checks\n");
    for check in &node.checks {
        let (mark, text) = match &check.outcome {
            Outcome::Pass(text) => ("pass", text),
            Outcome::Fail(text) => ("FAIL", text),
            Outcome::NotRun(text) => ("skip", text),
        };
        let _ = writeln!(out, "    {mark}  {}: {text}", check.name);
    }
    let result = match (node.passed(), compared) {
        (true, true) => "pass",
        (true, false) => "pass (no measurement was compared)",
        (false, _) => "FAIL",
    };
    let _ = writeln!(out, "  result: {result}");
}

/// Appends `{indent}{label}{padding}{value}` and a line end, the values in one column.
fn line(out: &mut String, indent: usize, label: &str, value: &str) {
    let width = 14usize.saturating_sub(indent);
    let _ = writeln!(out, "{:indent$}{label:<width$}{value}", "");
}

/// A text from outside the tool (the response, a document, a file) as the report prints it:
/// printable ASCII, every other character escaped, and at most 128 characters. A text can
/// therefore not add a line to the report or move the cursor of a terminal.
fn shown(text: &str) -> String {
    const LIMIT: usize = 128;
    let mut escaped: String = text
        .chars()
        .take(LIMIT)
        .flat_map(char::escape_default)
        .collect();
    if text.chars().nth(LIMIT).is_some() {
        escaped.push_str("...");
    }
    escaped
}

/// The UTC date and time of a Unix time in milliseconds, as `YYYY-MM-DDThh:mm:ssZ`.
pub fn utc(time_ms: u64) -> String {
    let seconds = time_ms / 1000;
    let (days, second_of_day) = (seconds / 86_400, seconds % 86_400);
    // The date of a day count since 1970-01-01 in the Gregorian calendar, by the algorithm
    // `civil_from_days` of Howard Hinnant ("chrono-Compatible Low-Level Date Algorithms"),
    // for day counts that are not negative. A year starts on March 1 in it, so a leap day is
    // the last day of a year, and 146097 days are 400 years.
    let shifted = days + 719_468;
    let (era, day_of_era) = (shifted / 146_097, shifted % 146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3600,
        second_of_day % 3600 / 60,
        second_of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::{evaluate_document, evaluate_entry};
    use credential_enclave_protocol::encoding::b64u;
    use serde_json::json;

    const RELEASE_DOCUMENT: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-alpha-prerelease.cbor");
    const RELEASE_NONCE: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-alpha-prerelease.cbor.nonce");
    const RELEASE_MEASUREMENTS: &[u8] =
        include_bytes!("../tests/fixtures/measurements-prerelease.json");
    const OTHER_BUILD_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document-operational.cbor");

    fn release_measurements() -> Measurements {
        Measurements::of_file("out/measurements.json", RELEASE_MEASUREMENTS).unwrap()
    }

    fn entry(document: &[u8], node: &str, release: &str) -> serde_json::Value {
        json!({
            "v": 1, "platform": "nitro", "document": b64u(document), "node": node,
            "release": release,
        })
    }

    #[test]
    fn the_report_of_a_node_that_passes() {
        let expected = release_measurements();
        let nodes = [evaluate_entry(
            &entry(
                RELEASE_DOCUMENT,
                "Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE",
                "v1.0.0",
            ),
            RELEASE_NONCE,
            Some(&expected),
            false,
        )];
        let report = Report {
            source: "https://api.example.com/api/credential-enclave/attestation",
            nonce: RELEASE_NONCE,
            expected: Some(&expected),
            nodes: &nodes,
        };
        assert_eq!(report.exit_status(), EXIT_PASSED);
        assert_eq!(
            report.render(),
            "\
source        https://api.example.com/api/credential-enclave/attestation
nonce         488818963c99ac32f3c43f92a73f1ee1978e32ed1a597020cb0efaf2957978de
expected      release v1.0.0 of out/measurements.json
  pcr0        d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7
  pcr1        4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493
  pcr2        a20b4116edfa4777b9a128025b2c77fd3bfa41e2aedf7710ed6e6b03eebf1110f99e486772ffb0e6a7b8c37070d814f8

node 1 of 1
  response (not verified, the checks compare the node with the document)
    node      Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE
    release   v1.0.0
    platform  nitro
  document
    time      2026-10-01T04:26:30Z
    module_id i-00e27c4213a488340-enc01a0f5b621ecd411
    pcr0      d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7
    pcr1      4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493
    pcr2      a20b4116edfa4777b9a128025b2c77fd3bfa41e2aedf7710ed6e6b03eebf1110f99e486772ffb0e6a7b8c37070d814f8
    node      Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE
    release   v1.0.0
    log_store none
  checks
    pass  response entry: version 1 with a platform, a document and a node
    pass  document form: a COSE_Sign1 structure with the ES384 header around an attestation payload
    pass  certificate chain: leads to the AWS Nitro Enclaves Root-G1 at the time of the document
    pass  signature: verifies under the key of the certificate of the document
    pass  nonce: the document carries the nonce that was asked for
    pass  production mode: none of PCR0, PCR1 and PCR2 is all zero
    pass  pcr0: equals the expected value
    pass  pcr1: equals the expected value
    pass  pcr2: equals the expected value
    pass  binding: a signing key, a sealing key and a release
    pass  node key: the signing key of the binding is the node of the response
  result: pass

summary: 1 node: 1 passed, 0 failed.
"
        );
    }

    #[test]
    fn the_report_of_nodes_that_fail() {
        // Two nodes: the release, and a node whose document is that of another build and was
        // made for another request.
        let expected = release_measurements();
        let nodes = [
            evaluate_document(RELEASE_DOCUMENT, RELEASE_NONCE, Some(&expected)),
            evaluate_document(OTHER_BUILD_DOCUMENT, RELEASE_NONCE, Some(&expected)),
            evaluate_document(b"no document", RELEASE_NONCE, Some(&expected)),
        ];
        let report = Report {
            source: "stored.cbor",
            nonce: RELEASE_NONCE,
            expected: Some(&expected),
            nodes: &nodes,
        };
        assert_eq!(report.exit_status(), EXIT_FAILED);
        let text = report.render();
        assert!(text.ends_with("\nsummary: 3 nodes: 1 passed, 2 failed.\n"));
        let blocks: Vec<&str> = text.split("\nnode ").collect();
        assert_eq!(blocks.len(), 4);
        assert!(blocks[1].starts_with("1 of 3\n  document\n"));
        assert!(blocks[1].contains("\n  result: pass\n"));
        assert!(blocks[2].starts_with("2 of 3\n"));
        assert!(blocks[2].contains("\n    release   v0.0.0-diag.local\n"));
        assert!(blocks[2].contains(
            "\n    FAIL  nonce: the nonce of the document is not the nonce that was asked for\n"
        ));
        assert!(blocks[2].contains(
            "\n    FAIL  pcr0: is not the expected value d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7\n"
        ));
        assert!(blocks[2].contains("\n    pass  pcr1: equals the expected value\n"));
        assert!(blocks[2].contains("\n  result: FAIL\n"));
        assert!(blocks[3].starts_with(
            "3 of 3\n  document: nothing it states is known\n  checks\n    FAIL  document form: the document does not have the expected form\n    skip  certificate chain: not evaluated: an earlier check failed\n"
        ));
        assert!(blocks[3].contains("\n  result: FAIL\n"));
    }

    #[test]
    fn the_report_says_that_nothing_was_compared() {
        let nodes = [evaluate_document(RELEASE_DOCUMENT, RELEASE_NONCE, None)];
        let report = Report {
            source: "stored.cbor",
            nonce: RELEASE_NONCE,
            expected: None,
            nodes: &nodes,
        };
        assert_eq!(report.exit_status(), EXIT_PASSED);
        let text = report.render();
        assert!(text.contains("\nexpected      nothing: no measurement is compared\n"));
        assert!(text.contains("\n    skip  pcr0: not compared: no expected value was given\n"));
        // The measurements the tool saw are printed.
        assert!(text.contains(
            "\n    pcr0      d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7\n"
        ));
        assert!(text.ends_with(
            "\n  result: pass (no measurement was compared)\n\nsummary: 1 node: 1 passed, 0 failed. No measurement was compared: no expected values were given.\n"
        ));
    }

    #[test]
    fn the_report_names_the_log_store_of_a_binding() {
        let binding = json!({
            "v": 1, "sign": "Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE",
            "seal": "cEbNoWZTb6WqyPag8n54ID4bUEtXYamfPmsVlxReUBo", "release": "v1.0.0",
            "log": {"bucket": "character-credential-log-prod-1", "region": "us-west-2"},
        });
        let document = json!({
            "v": 1, "platform": "local", "binding": b64u(binding.to_string().as_bytes()),
            "nonce": b64u(RELEASE_NONCE), "time_ms": 1_790_828_465_207u64,
        });
        let entry = json!({
            "v": 1, "platform": "local", "document": b64u(document.to_string().as_bytes()),
            "node": "Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE", "release": "v1.0.0",
        });
        let nodes = [evaluate_entry(&entry, RELEASE_NONCE, None, true)];
        let report = Report {
            source: "https://api.example.com/api/credential-enclave/attestation",
            nonce: RELEASE_NONCE,
            expected: None,
            nodes: &nodes,
        };
        assert!(report.render().contains(
            "\n    release   v1.0.0\n    log_store character-credential-log-prod-1 in us-west-2\n"
        ));
    }

    #[test]
    fn a_text_of_the_response_cannot_add_a_line_to_the_report() {
        let forged = "v1.0.0\n  result: pass\n\u{1b}[2Jsummary: 1 node: 1 passed, 0 failed.";
        let nodes = [evaluate_entry(
            &entry(b"no document", forged, forged),
            RELEASE_NONCE,
            None,
            false,
        )];
        let report = Report {
            source: "https://api.example.com/api/credential-enclave/attestation",
            nonce: RELEASE_NONCE,
            expected: None,
            nodes: &nodes,
        };
        assert_eq!(report.exit_status(), EXIT_FAILED);
        let text = report.render();
        assert!(text.contains(
            "\n    release   v1.0.0\\n  result: pass\\n\\u{1b}[2Jsummary: 1 node: 1 passed, 0 failed.\n"
        ));
        assert_eq!(text.matches("\n  result: ").count(), 1);
        assert!(text.contains("\n  result: FAIL\n"));
        assert_eq!(text.matches("\nsummary: ").count(), 1);
        assert!(!text.contains('\u{1b}'));

        assert_eq!(shown("plain text 1.0_-"), "plain text 1.0_-");
        assert_eq!(shown("é\t\\"), "\\u{e9}\\t\\\\");
        assert_eq!(shown(&"a".repeat(128)), "a".repeat(128));
        assert_eq!(shown(&"a".repeat(129)), format!("{}...", "a".repeat(128)));
    }

    #[test]
    fn times_in_utc() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(999), "1970-01-01T00:00:00Z");
        assert_eq!(utc(86_399_000), "1970-01-01T23:59:59Z");
        // A leap day, the day after it, and the last second of a leap year.
        assert_eq!(utc(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(utc(951_868_800_000), "2000-03-01T00:00:00Z");
        assert_eq!(utc(1_735_689_599_000), "2024-12-31T23:59:59Z");
        // 2100 is not a leap year.
        assert_eq!(utc(4_107_542_400_000), "2100-03-01T00:00:00Z");
        // The times of the documents of the fixtures.
        assert_eq!(utc(1_790_828_790_930), "2026-10-01T04:26:30Z");
        assert_eq!(utc(1_790_827_255_513), "2026-10-01T04:00:55Z");
        assert_eq!(utc(1_695_049_410_860), "2023-09-18T15:03:30Z");
    }
}
