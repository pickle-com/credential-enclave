//! Real in-node TLS, protocol parsing, credential exclusion and SMTP ambiguity.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::http::Method;
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::body::Bytes;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::quiet_provider_and_log_store;
use crate::frame::{self, META_LIMIT_BYTES};
use crate::mail::{self, LiteralScan};
use crate::state::Limits;
use crate::testing::{App, Harness};

const PASSWORD: &str = "naver-secret-marker-2e7c06830e6f";
const MESSAGE: &[u8] = b"From: tester@naver.com\r\nTo: friend@example.com\r\nSubject: a test\r\nMessage-ID: <one@pickle.com>\r\n\r\nhello\r\n";

struct MailServer {
    address: std::net::SocketAddr,
    roots: RootCertStore,
    passwords: Arc<Mutex<Vec<String>>>,
    submissions: Arc<Mutex<Vec<Vec<u8>>>>,
    search_literals: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MailServer {
    async fn start(drop_after_data: bool, reflect_password: bool) -> Self {
        Self::with_replies(drop_after_data, reflect_password, None, None).await
    }

    async fn with_replies(
        drop_after_data: bool,
        reflect_password: bool,
        imap_auth_reply: Option<&'static str>,
        smtp_recipient_reply: Option<&'static str>,
    ) -> Self {
        Self::with_login_delay(
            drop_after_data,
            reflect_password,
            imap_auth_reply,
            smtp_recipient_reply,
            std::time::Duration::ZERO,
            None,
            false,
        )
        .await
    }

    /// `oversized_list`: the LIST reply declares a literal far above any input bound and
    /// sends nothing after it.
    async fn with_login_delay(
        drop_after_data: bool,
        reflect_password: bool,
        imap_auth_reply: Option<&'static str>,
        smtp_recipient_reply: Option<&'static str>,
        login_delay: std::time::Duration,
        login_gate: Option<Arc<tokio::sync::Semaphore>>,
        oversized_list: bool,
    ) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert =
            rcgen::CertificateParams::new(vec!["imap.naver.com".into(), "smtp.naver.com".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let passwords = Arc::new(Mutex::new(Vec::new()));
        let submissions = Arc::new(Mutex::new(Vec::new()));
        let search_literals = Arc::new(Mutex::new(Vec::new()));
        let literals = search_literals.clone();
        let captured = passwords.clone();
        let delivered = submissions.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let captured = captured.clone();
                let delivered = delivered.clone();
                let literals = literals.clone();
                let login_gate = login_gate.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let smtp = tls.get_ref().1.server_name() == Some("smtp.naver.com");
                    let mut io = BufReader::new(tls);
                    let greeting: &[u8] = if smtp {
                        b"220 mail ready\r\n"
                    } else {
                        b"* OK mail ready\r\n"
                    };
                    if io.get_mut().write_all(greeting).await.is_err() {
                        return;
                    }
                    let mut auth = 0;
                    loop {
                        let mut line = String::new();
                        if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let reply: Vec<u8> = if smtp {
                            if auth > 0 {
                                let decoded = STANDARD.decode(line.trim()).unwrap();
                                auth += 1;
                                if auth == 2 {
                                    b"334 UGFzc3dvcmQ6\r\n".to_vec()
                                } else {
                                    captured
                                        .lock()
                                        .unwrap()
                                        .push(String::from_utf8(decoded).unwrap());
                                    auth = 0;
                                    b"235 authenticated\r\n".to_vec()
                                }
                            } else if line.starts_with("EHLO") {
                                b"250-mail\r\n250-SIZE 67108864\r\n250 AUTH LOGIN\r\n".to_vec()
                            } else if line.starts_with("AUTH LOGIN") {
                                auth = 1;
                                b"334 VXNlcm5hbWU6\r\n".to_vec()
                            } else if line.starts_with("RCPT TO:<refused@") {
                                smtp_recipient_reply
                                    .unwrap_or("250 ok\r\n")
                                    .as_bytes()
                                    .to_vec()
                            } else if line.starts_with("DATA") {
                                io.get_mut().write_all(b"354 send data\r\n").await.unwrap();
                                let mut body = Vec::new();
                                loop {
                                    let mut data = String::new();
                                    if io.read_line(&mut data).await.unwrap_or(0) == 0 {
                                        return;
                                    }
                                    if data == ".\r\n" {
                                        break;
                                    }
                                    body.extend_from_slice(
                                        data.strip_prefix('.').unwrap_or(&data).as_bytes(),
                                    );
                                }
                                delivered.lock().unwrap().push(body);
                                if drop_after_data {
                                    return;
                                }
                                b"250 accepted\r\n".to_vec()
                            } else {
                                b"250 ok\r\n".to_vec()
                            }
                        } else {
                            let (tag, command) = line.trim_end().split_once(' ').unwrap();
                            let mut reply = Vec::new();
                            if command.starts_with("LOGIN ") {
                                assert!(command.contains(PASSWORD));
                                captured.lock().unwrap().push(PASSWORD.to_string());
                                if let Some(gate) = &login_gate {
                                    gate.acquire().await.unwrap().forget();
                                }
                                tokio::time::sleep(login_delay).await;
                                if let Some(refusal) = imap_auth_reply {
                                    if io
                                        .get_mut()
                                        .write_all(format!("{tag} {refusal}\r\n").as_bytes())
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                    continue;
                                }
                            } else if command.starts_with("LIST ") {
                                if oversized_list {
                                    let _ = io
                                        .get_mut()
                                        .write_all(b"* LIST () \"/\" {600000000}\r\n")
                                        .await;
                                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                                    return;
                                }
                                reply.extend_from_slice(b"* LIST () \"/\" \"INBOX\"\r\n");
                            } else if command.starts_with("EXAMINE ") {
                                reply.extend_from_slice(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 42] valid\r\n* OK [UIDNEXT 8] next\r\n");
                            } else if command.starts_with("UID SEARCH") {
                                assert!(command.is_ascii());
                                let mut tail = command.to_string();
                                while tail.ends_with('}') {
                                    let count: usize = tail
                                        .rsplit_once('{')
                                        .unwrap()
                                        .1
                                        .trim_end_matches('}')
                                        .parse()
                                        .unwrap();
                                    io.get_mut().write_all(b"+ send literal\r\n").await.unwrap();
                                    let mut literal = vec![0; count];
                                    io.read_exact(&mut literal).await.unwrap();
                                    literals.lock().unwrap().push(literal);
                                    tail.clear();
                                    io.read_line(&mut tail).await.unwrap();
                                    tail = tail.trim_end().to_string();
                                }
                                reply.extend_from_slice(b"* SEARCH 7\r\n");
                            } else if command.starts_with("UID FETCH") {
                                let mut body = MESSAGE.to_vec();
                                if reflect_password {
                                    body.extend_from_slice(PASSWORD.as_bytes());
                                }
                                if command.contains("BODY.PEEK[]") {
                                    reply.extend_from_slice(
                                        format!("* 1 FETCH (UID 7 BODY[] {{{}}}\r\n", body.len())
                                            .as_bytes(),
                                    );
                                    reply.extend_from_slice(&body);
                                    reply.extend_from_slice(b")\r\n");
                                } else if command.contains("BODY.PEEK[HEADER]") {
                                    let header =
                                        b"Subject: a test\r\nMessage-ID: <one@pickle.com>\r\n\r\n";
                                    reply.extend_from_slice(format!("* 1 FETCH (UID 7 RFC822.SIZE {} BODY[HEADER] {{{}}}\r\n", body.len(), header.len()).as_bytes());
                                    reply.extend_from_slice(header);
                                    reply.extend_from_slice(b")\r\n");
                                } else {
                                    reply.extend_from_slice(
                                        format!("* 1 FETCH (UID 7 RFC822.SIZE {})\r\n", body.len())
                                            .as_bytes(),
                                    );
                                }
                            }
                            reply.extend_from_slice(format!("{tag} OK completed\r\n").as_bytes());
                            reply
                        };
                        if io.get_mut().write_all(&reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            address,
            roots,
            passwords,
            submissions,
            search_literals,
        }
    }

    async fn harness(&self) -> (Harness, App, Value) {
        self.harness_with_limits(Limits::default()).await
    }

    async fn harness_with_limits(&self, limits: Limits) -> (Harness, App, Value) {
        let provider = quiet_provider_and_log_store().await;
        let harness = Harness::with_mail_roots(&provider, self.roots.clone(), limits);
        harness.platform.route("imap.naver.com", self.address);
        harness.platform.route("smtp.naver.com", self.address);
        harness.use_log_store().await;
        let app = App::new("mail-user", 33);
        app.grant(&harness).await;
        let record = app.record(
            "app_password",
            "naver_mail",
            &json!({"username":"tester@naver.com","password":PASSWORD}),
        );
        (harness, app, record)
    }
}

async fn request(
    harness: &Harness,
    record: &Value,
    operation: &str,
    params: Value,
    body: &[u8],
) -> (u16, Value, Vec<u8>) {
    let meta =
        json!({"user_id":"mail-user","record":record,"context":"cli:naver-mail","request":params});
    let metadata = serde_json::to_vec(&meta).unwrap();
    let mut wire = (metadata.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(&metadata);
    wire.extend_from_slice(body);
    let response = harness
        .call(Method::POST, &format!("/v1/mail/{operation}"), wire)
        .await;
    assert!(!String::from_utf8_lossy(&response.body).contains(PASSWORD));
    assert!(!String::from_utf8_lossy(&response.body).contains(&STANDARD.encode(PASSWORD)));
    if response.status != 200 {
        return (
            response.status,
            serde_json::from_slice(&response.body).unwrap(),
            Vec::new(),
        );
    }
    let (meta, bytes) = frame::decode(&Bytes::from(response.body)).unwrap();
    (200, meta, bytes.to_vec())
}

pub async fn canary_routes() -> (BTreeSet<(String, String)>, BTreeSet<(String, String)>) {
    let server = MailServer::start(false, false).await;
    let (harness, app, record) = server.harness().await;
    let mut success = BTreeSet::new();
    let mut failure = BTreeSet::new();
    for (operation, params, payload) in [
        ("verify", json!({}), &b""[..]),
        ("read", json!({"action":"folders"}), &b""[..]),
        (
            "submit",
            json!({"recipients":["friend@example.com"]}),
            MESSAGE,
        ),
    ] {
        let (status, meta, _) =
            request(&harness, &record, operation, params.clone(), payload).await;
        assert_eq!(
            (status, meta["status"].as_u64()),
            (200, Some(200)),
            "{meta}"
        );
        success.insert(("POST".into(), format!("/v1/mail/{operation}")));
        let wrong_kind = app.record("vault_password", "vault", &json!({"value":PASSWORD}));
        let (status, _, _) = request(&harness, &wrong_kind, operation, params, payload).await;
        assert_eq!(status, 403);
        failure.insert(("POST".into(), format!("/v1/mail/{operation}")));
    }
    assert_eq!(
        server.submissions.lock().unwrap().as_slice(),
        &[MESSAGE.to_vec()]
    );
    assert!(server
        .passwords
        .lock()
        .unwrap()
        .iter()
        .all(|s| s == PASSWORD));
    assert!(harness
        .platform
        .connections()
        .iter()
        .all(|(host, port)| host == crate::testing::LOG_HOST
            || matches!(
                (host.as_str(), *port),
                ("imap.naver.com", 993) | ("smtp.naver.com", 465)
            )));
    (success, failure)
}

#[tokio::test]
async fn mail_calls_use_tls_and_return_no_password() {
    canary_routes().await;
}

#[tokio::test]
async fn reads_check_mailbox_generation_and_withhold_reflected_credentials() {
    let server = MailServer::start(false, true).await;
    let (harness, _, record) = server.harness().await;
    let (status, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"read","uid":7,"uid_validity":99}),
        b"",
    )
    .await;
    assert_eq!((status, meta["status"].as_u64()), (200, Some(409)));
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["code"],
        "mailbox_changed"
    );
    let (status, meta, _) = request(
        &harness,
        &record,
        "read",
        json!({"action":"read","uid":7,"uid_validity":42}),
        b"",
    )
    .await;
    assert_eq!(status, 502);
    assert_eq!(meta["code"], "response_withheld");
}

#[tokio::test]
async fn lost_smtp_reply_has_one_delivery_and_is_never_retried() {
    let server = MailServer::start(true, false).await;
    let (harness, _, record) = server.harness().await;
    let (status, meta, _) = request(
        &harness,
        &record,
        "submit",
        json!({"recipients":["friend@example.com"]}),
        MESSAGE,
    )
    .await;
    assert_eq!(status, 502);
    assert_eq!(meta["code"], "provider_unreachable");
    assert_eq!(server.submissions.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn search_and_read_preserve_mailbox_identity_and_mime() {
    let server = MailServer::start(false, false).await;
    let (harness, _, record) = server.harness().await;
    let (_, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"search","from":"friend@example.com","subject":"회의","since":"2026-10-01","limit":1}),
        b"",
    )
    .await;
    assert_eq!(meta["status"], 200);
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["uid_validity"], 42);
    assert_eq!(
        server.search_literals.lock().unwrap().as_slice(),
        &[b"friend@example.com".to_vec(), "회의".as_bytes().to_vec()]
    );
    assert_eq!(page["messages"][0]["uid"], 7);
    let (_, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"read","uid":7,"uid_validity":42}),
        b"",
    )
    .await;
    assert_eq!(meta["status"], 200);
    assert_eq!(body, MESSAGE);
}

#[tokio::test]
async fn partial_recipient_refusal_never_sends_data() {
    let server = MailServer::with_replies(false, false, None, Some("550 refused\r\n")).await;
    let (harness, _, record) = server.harness().await;
    let (_, meta, body) = request(
        &harness,
        &record,
        "submit",
        json!({"recipients":["friend@example.com","refused@example.com"]}),
        MESSAGE,
    )
    .await;
    assert_eq!(meta["status"], 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"status":"rejected","smtp_code":550})
    );
    assert!(server.submissions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn authentication_refusal_is_distinct_from_temporary_mail_failure() {
    for (reply, expected) in [
        ("NO [AUTHENTICATIONFAILED] Login failed", 401),
        ("NO [UNAVAILABLE] Try later", 502),
    ] {
        let server = MailServer::with_replies(false, false, Some(reply), None).await;
        let (harness, _, record) = server.harness().await;
        let (status, meta, _) = request(&harness, &record, "verify", json!({}), b"").await;
        assert_eq!(
            if status == 200 {
                meta["status"].as_u64().unwrap()
            } else {
                status as u64
            },
            expected,
            "{meta}"
        );
        assert!(server.submissions.lock().unwrap().is_empty());
    }
}

/// Mail beyond the memory budget is refused while admitted mail remains blocked at the
/// TLS provider. A small HTTP call must finish before those mail calls are released.
#[tokio::test]
async fn excess_mail_does_not_queue_ahead_of_google() {
    mixed_admission_scenario().await;
}

#[tokio::test]
#[ignore = "bounded mixed mail/HTTP admission experiment"]
#[expect(
    clippy::print_stdout,
    reason = "The opt-in probe emits only fixture timings"
)]
async fn mixed_mail_and_google_admission_probe() {
    println!("{}", mixed_admission_scenario().await);
}

async fn mixed_admission_scenario() -> Value {
    use std::time::{Duration, Instant};
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let server = MailServer::with_login_delay(
        false,
        false,
        None,
        None,
        Duration::ZERO,
        Some(gate.clone()),
        false,
    )
    .await;
    // A budget that two folder listings fill: the third mail call is refused while the small
    // HTTP calls still fit.
    let listing = mail::LISTING_INPUT_BYTES * 6 + 2 * META_LIMIT_BYTES;
    let (harness, app, record) = server
        .harness_with_limits(Limits {
            body_budget_bytes: 2 * listing + 1024 * 1024,
            ..Limits::default()
        })
        .await;
    let harness = Arc::new(harness);
    let google = app.record(
        "oauth",
        "google_workspace",
        &json!({"token":{"access_token":"mixed-probe-token"},"obtained_ms":1}),
    );
    let google_meta = |field: &str| {
        json!({
            "user_id":app.user_id,"record":google,"method":"GET",
            "url":format!("https://gmail.googleapis.com/gmail/v1/users/me/profile?fields={field}"),
            "headers":[],"context":"cli:gog","timeout_ms":5000,
        })
    };
    let start = Instant::now();
    assert_eq!(
        harness
            .forward(google_meta("emailAddress"), b"")
            .await
            .unwrap()
            .status,
        200
    );
    let control_ms = start.elapsed().as_millis();
    let spawn_mail = || {
        let harness = harness.clone();
        let record = record.clone();
        tokio::spawn(async move {
            request(&harness, &record, "read", json!({"action":"folders"}), b"").await
        })
    };
    let first = spawn_mail();
    let second = spawn_mail();
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.passwords.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("both admitted mail calls reached the blocked provider");
    for (operation, params, body) in [
        ("verify", json!({}), &b""[..]),
        ("read", json!({"action":"folders"}), &b""[..]),
        (
            "submit",
            json!({"recipients":["friend@example.com"]}),
            MESSAGE,
        ),
    ] {
        let (status, meta, _) = tokio::time::timeout(
            Duration::from_secs(5),
            request(&harness, &record, operation, params, body),
        )
        .await
        .expect("excess mail must be refused without waiting for a provider");
        assert_eq!(status, 503);
        assert_eq!(meta["code"], "capacity_unavailable");
    }
    assert_eq!(server.passwords.lock().unwrap().len(), 2);
    assert!(server.submissions.lock().unwrap().is_empty());
    let start = Instant::now();
    let forwarded = tokio::time::timeout(
        Duration::from_secs(5),
        harness.forward(google_meta("messagesTotal"), b""),
    )
    .await
    .expect("Google must complete while mail remains blocked")
    .unwrap();
    let concurrent_ms = start.elapsed().as_millis();
    assert_eq!(forwarded.status, 200);
    assert!(!first.is_finished() && !second.is_finished());
    gate.add_permits(2);
    for handle in [first, second] {
        let (status, meta, _) = handle.await.unwrap();
        assert_eq!((status, meta["status"].as_u64()), (200, Some(200)));
    }
    let start = Instant::now();
    assert_eq!(
        harness
            .forward(google_meta("threadsTotal"), b"")
            .await
            .unwrap()
            .status,
        200
    );
    json!({
        "experiment":"mixed_mail_google_admission",
        "provider":"local TLS stand-ins", "mail_logins_held":2,
        "excess_mail_operations_refused":3,
        "google_control_ms":control_ms, "google_concurrent_ms":concurrent_ms,
        "google_recovered_ms":start.elapsed().as_millis(),
        "imap_logins_observed":server.passwords.lock().unwrap().len(),
        "real_credentials":false, "real_email_sent":false,
    })
}

#[test]
fn literal_scan_refuses_a_declaration_above_the_bound() {
    let accepted =
        b"* LIST () \"/\" {5}\r\nhello\r\n* 1 FETCH (BODY[] {9}\r\n{99999}\r\n)\r\nA1 OK done\r\n";
    for chunk in [1usize, 3, 7, accepted.len()] {
        let mut scan = LiteralScan::Text;
        for piece in accepted.chunks(chunk) {
            scan.feed(piece, 9).unwrap();
        }
        assert_eq!(scan, LiteralScan::Text, "chunks of {chunk}");
    }
    let mut scan = LiteralScan::Text;
    assert_eq!(scan.feed(accepted, 8), Err(9));
    let mut scan = LiteralScan::Text;
    scan.feed(b"* OK {12}x is text\r\n* OK {}\r\n{{3}\r\nabc", 3)
        .unwrap();
    assert_eq!(scan, LiteralScan::Text);
    let mut scan = LiteralScan::Text;
    assert_eq!(
        scan.feed(b"* 1 FETCH (BODY[] {99999999999999999999999}\r\n", 64),
        Err(u64::MAX)
    );
}

#[tokio::test]
async fn oversized_literal_declaration_is_refused_before_it_is_read() {
    let server = MailServer::with_login_delay(
        false,
        false,
        None,
        None,
        std::time::Duration::ZERO,
        None,
        true,
    )
    .await;
    let (harness, _app, record) = server.harness().await;
    let started = std::time::Instant::now();
    let (status, meta, _) =
        request(&harness, &record, "read", json!({"action":"folders"}), b"").await;
    assert_eq!(
        (status, meta["code"].as_str()),
        (502, Some("provider_unreachable"))
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(
        harness.node.body_budget.available_permits(),
        harness.node.limits.body_budget_bytes
    );
}

#[tokio::test]
async fn mail_reservations_follow_the_operation() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let server = MailServer::with_login_delay(
        false,
        false,
        None,
        None,
        std::time::Duration::ZERO,
        Some(gate.clone()),
        false,
    )
    .await;
    let (harness, _app, record) = server.harness().await;
    let harness = Arc::new(harness);
    let budget = harness.node.limits.body_budget_bytes;
    let frames = 2 * META_LIMIT_BYTES;
    for (params, expected) in [
        (
            json!({"action":"folders"}),
            mail::LISTING_INPUT_BYTES * 6 + frames,
        ),
        (
            json!({"action":"read","uid_validity":42,"uid":7}),
            mail::message_input_bytes(&harness.node.limits)
                + harness.node.limits.body_bytes
                + frames,
        ),
    ] {
        let seen = server.passwords.lock().unwrap().len();
        let call = {
            let harness = harness.clone();
            let record = record.clone();
            tokio::spawn(async move { request(&harness, &record, "read", params, b"").await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while server.passwords.lock().unwrap().len() == seen {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the call reached the blocked login");
        assert_eq!(
            budget - harness.node.body_budget.available_permits(),
            expected
        );
        gate.add_permits(1);
        let (status, _, _) = call.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(harness.node.body_budget.available_permits(), budget);
    }
}
