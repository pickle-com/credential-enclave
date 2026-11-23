//! A stand-in for imap.naver.com whose answers a test writes, and two probes that print what
//! the mail reads of a node cost: the share of the body budget of reads that run at the same
//! time, and the connections and the logins of reads that follow each other.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::mail::{harness_at, request};
use crate::state::Limits;
use crate::testing::{App, Harness};

/// The message of the mailbox of [`mailbox`].
pub(super) const MESSAGE: &[u8] = b"From: friend@example.com\r\nTo: tester@naver.com\r\nSubject: a test\r\nMessage-ID: <one@pickle.com>\r\n\r\nhello\r\n";

/// One command a client sent: the number of its connection (the first is 0), its number on
/// that connection (the first is 0, the `LOGIN`), and its text without its tag, with the
/// octets of its literals in the places of their declarations.
pub(super) struct Command<'a> {
    pub connection: usize,
    pub number: usize,
    pub text: &'a str,
}

/// One thing the stand-in does in answer to a command.
pub(super) enum Act {
    /// Sends bytes.
    Send(Vec<u8>),
    /// Waits for one permit of the gate, and takes it.
    Wait(Arc<Semaphore>),
    /// Waits for this long.
    Pause(Duration),
    /// Ends the connection: nothing follows, the completion of the command included.
    Close,
}

/// The answer to a command: what the stand-in does, and then the completion of the command
/// (`OK done`, `NO [NONEXISTENT] no such mailbox`). An empty completion sends none.
pub(super) struct Answer {
    pub acts: Vec<Act>,
    pub completion: String,
}

impl Answer {
    /// `text` and the completion `OK done`.
    pub(super) fn ok(text: impl Into<Vec<u8>>) -> Answer {
        Answer {
            acts: vec![Act::Send(text.into())],
            completion: "OK done".to_string(),
        }
    }

    /// The acts and the completion `OK done`.
    pub(super) fn after(acts: Vec<Act>) -> Answer {
        Answer {
            acts,
            completion: "OK done".to_string(),
        }
    }

    /// The completion alone.
    pub(super) fn completion(completion: &str) -> Answer {
        Answer {
            acts: Vec::new(),
            completion: completion.to_string(),
        }
    }
}

/// A `FETCH` response of the message with this UID whose last item is `item` with the
/// literal `octets`.
pub(super) fn fetch_literal(uid: u32, items: &str, item: &str, octets: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "* 1 FETCH (UID {uid} {items}{item} {{{}}}\r\n",
        octets.len()
    )
    .into_bytes();
    response.extend_from_slice(octets);
    response.extend_from_slice(b")\r\n");
    response
}

/// The answers of a mailbox with the folder `INBOX` of the generation 42 and the one message
/// [`MESSAGE`], whose UID is 7.
pub(super) fn mailbox(command: &Command<'_>) -> Answer {
    let text = command.text;
    let header_end = MESSAGE
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    if text.starts_with("LOGIN ") {
        Answer::ok("")
    } else if text.starts_with("LIST ") {
        Answer::ok("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n")
    } else if text.starts_with("EXAMINE ") {
        Answer::ok("* 1 EXISTS\r\n* OK [UIDVALIDITY 42] valid\r\n* OK [UIDNEXT 8] next\r\n")
    } else if text.starts_with("UID SEARCH ") {
        Answer::ok("* SEARCH 7\r\n")
    } else if text.ends_with(" (UID RFC822.SIZE)") {
        Answer::ok(format!(
            "* 1 FETCH (UID 7 RFC822.SIZE {})\r\n",
            MESSAGE.len()
        ))
    } else if text.ends_with(" (UID BODY.PEEK[])") {
        Answer::ok(fetch_literal(7, "", "BODY[]", MESSAGE))
    } else if text.ends_with(" (UID RFC822.SIZE BODY.PEEK[HEADER])") {
        Answer::ok(fetch_literal(
            7,
            &format!("RFC822.SIZE {} ", MESSAGE.len()),
            "BODY[HEADER]",
            &MESSAGE[..header_end],
        ))
    } else {
        Answer::completion("BAD unknown command")
    }
}

/// A stand-in for imap.naver.com: IMAP over TLS, with a certificate for that name.
pub(super) struct ImapServer {
    pub address: SocketAddr,
    pub roots: RootCertStore,
    /// The TLS connections the stand-in accepted.
    pub connections: Arc<AtomicUsize>,
    /// The `LOGIN` commands it received.
    pub logins: Arc<AtomicUsize>,
    /// The connections that ended: the client closed them, or an act of the stand-in did.
    pub ended: Arc<AtomicUsize>,
    /// The commands that wait at a gate at this moment.
    pub waiting: Arc<AtomicUsize>,
    /// Every command it received, in the order it received them.
    pub commands: Arc<Mutex<Vec<(usize, String)>>>,
}

impl ImapServer {
    /// A stand-in that answers every command with what `script` gives for it, after the
    /// greeting `* OK ready`.
    pub(super) async fn start(
        script: impl Fn(&Command<'_>) -> Answer + Send + Sync + 'static,
    ) -> ImapServer {
        ImapServer::greeting("* OK ready\r\n", script).await
    }

    /// A stand-in whose first bytes on a connection are `greeting`.
    pub(super) async fn greeting(
        greeting: &'static str,
        script: impl Fn(&Command<'_>) -> Answer + Send + Sync + 'static,
    ) -> ImapServer {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["imap.naver.com".into()])
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
        let server = ImapServer {
            address: listener.local_addr().unwrap(),
            roots,
            connections: Arc::default(),
            logins: Arc::default(),
            ended: Arc::default(),
            waiting: Arc::default(),
            commands: Arc::default(),
        };
        let script = Arc::new(script);
        let (connections, logins, ended, waiting, commands) = (
            server.connections.clone(),
            server.logins.clone(),
            server.ended.clone(),
            server.waiting.clone(),
            server.commands.clone(),
        );
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let script = script.clone();
                let (connections, logins, ended, waiting, commands) = (
                    connections.clone(),
                    logins.clone(),
                    ended.clone(),
                    waiting.clone(),
                    commands.clone(),
                );
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let connection = connections.fetch_add(1, Ordering::SeqCst);
                    let mut io = BufReader::new(tls);
                    let served = async {
                        io.get_mut().write_all(greeting.as_bytes()).await.ok()?;
                        let mut number = 0;
                        loop {
                            let mut line = Vec::new();
                            if io.read_until(b'\n', &mut line).await.ok()? == 0 {
                                return None;
                            }
                            let line = String::from_utf8_lossy(&line).trim_end().to_string();
                            let (tag, first) = line.split_once(' ')?;
                            let mut text = first.to_string();
                            // A line that ends in a declaration: the octets of the literal
                            // follow the continuation request, and then the rest of the line.
                            while text.ends_with('}') {
                                let (front, declared) = text.rsplit_once('{')?;
                                let count: usize = declared.trim_end_matches('}').parse().ok()?;
                                let front = front.to_string();
                                io.get_mut().write_all(b"+ send it\r\n").await.ok()?;
                                let mut literal = vec![0; count];
                                io.read_exact(&mut literal).await.ok()?;
                                let mut rest = Vec::new();
                                io.read_until(b'\n', &mut rest).await.ok()?;
                                text = format!(
                                    "{front}{}{}",
                                    String::from_utf8_lossy(&literal),
                                    String::from_utf8_lossy(&rest).trim_end()
                                );
                            }
                            commands.lock().unwrap().push((connection, text.clone()));
                            if text.starts_with("LOGIN ") {
                                logins.fetch_add(1, Ordering::SeqCst);
                            }
                            let answer = script(&Command {
                                connection,
                                number,
                                text: &text,
                            });
                            number += 1;
                            for act in answer.acts {
                                match act {
                                    Act::Send(bytes) => {
                                        io.get_mut().write_all(&bytes).await.ok()?
                                    }
                                    Act::Wait(gate) => {
                                        waiting.fetch_add(1, Ordering::SeqCst);
                                        let permit = gate.acquire().await;
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        permit.ok()?.forget();
                                    }
                                    Act::Pause(pause) => tokio::time::sleep(pause).await,
                                    Act::Close => return None,
                                }
                            }
                            if !answer.completion.is_empty() {
                                let completion = format!("{tag} {}\r\n", answer.completion);
                                io.get_mut().write_all(completion.as_bytes()).await.ok()?;
                            }
                        }
                    };
                    let _: Option<()> = served.await;
                    ended.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        server
    }

    /// A node whose IMAP host is this stand-in, the account `mail-user` with a grant, and a
    /// record of the mailbox `tester@naver.com`.
    pub(super) async fn harness(&self, limits: Limits) -> (Harness, App, Value) {
        harness_at(self.roots.clone(), self.address, limits).await
    }

    /// The commands the stand-in received, without the numbers of their connections.
    pub(super) fn texts(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|(_, text)| text.clone())
            .collect()
    }
}

/// Waits until `reached` is true, for 10 seconds at the longest.
pub(super) async fn until(what: &str, reached: impl Fn() -> bool) {
    let waited = tokio::time::timeout(Duration::from_secs(10), async {
        while !reached() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "{what}");
}

/// What folder listings that run at the same time hold of the body budget of a node. The
/// probe starts `MAIL_PROBE_CALLS` listings (100 when the variable is not set) against a
/// stand-in that sends 3,000 bytes of folders and then holds every call in front of the
/// completion of its `LIST`, and prints how many of the calls the node admitted, how many it
/// refused, and how much of the body budget the admitted ones hold while they wait.
#[tokio::test]
#[ignore = "prints what concurrent folder listings hold of the body budget"]
#[expect(clippy::print_stdout, reason = "the probe prints its counts")]
async fn the_share_of_concurrent_folder_listings_probe() {
    let calls: usize = std::env::var("MAIL_PROBE_CALLS")
        .ok()
        .and_then(|calls| calls.parse().ok())
        .unwrap_or(100);
    let gate = Arc::new(Semaphore::new(0));
    let mut listing = Vec::new();
    for folder in 0..75 {
        listing.extend_from_slice(
            format!("* LIST (\\HasNoChildren) \"/\" \"Folder number {folder:04}\"\r\n").as_bytes(),
        );
    }
    let listing_bytes = listing.len();
    let server = {
        let gate = gate.clone();
        ImapServer::start(move |command| match command.text.starts_with("LIST ") {
            true => Answer::after(vec![Act::Send(listing.clone()), Act::Wait(gate.clone())]),
            false => mailbox(command),
        })
        .await
    };
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let harness = Arc::new(harness);
    let budget = harness.node.limits.body_budget_bytes;
    let finished = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..calls {
        let harness = harness.clone();
        let record = record.clone();
        let finished = finished.clone();
        handles.push(tokio::spawn(async move {
            let answer = request(&harness, &record, "read", json!({"action":"folders"}), b"").await;
            finished.fetch_add(1, Ordering::SeqCst);
            answer
        }));
    }
    until("every call waits at the gate or has ended", || {
        server.waiting.load(Ordering::SeqCst) + finished.load(Ordering::SeqCst) == calls
    })
    .await;
    // The node takes the bytes the stand-in sent in front of the gate.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let admitted = server.waiting.load(Ordering::SeqCst);
    let held = budget - harness.node.body_budget.available_permits();
    gate.add_permits(calls);
    let (mut answered, mut refused) = (0, 0);
    for handle in handles {
        let (status, meta, _) = handle.await.unwrap();
        match (status, meta["code"].as_str()) {
            (200, _) => answered += 1,
            (503, Some("capacity_unavailable")) => refused += 1,
            other => panic!("{other:?}"),
        }
    }
    println!(
        "{}",
        json!({
            "probe": "the share of concurrent folder listings",
            "calls": calls,
            "listing_bytes": listing_bytes,
            "admitted": admitted,
            "answered": answered,
            "refused_with_capacity_unavailable": refused,
            "body_budget_bytes": budget,
            "held_while_the_admitted_calls_wait_bytes": held,
            "held_per_admitted_call_bytes": held / admitted.max(1),
            "imap_logins": server.logins.load(Ordering::SeqCst),
        })
    );
}

/// What reads of one mailbox that follow each other cost. The probe makes `MAIL_PROBE_CALLS`
/// reads (20 when the variable is not set: a folder listing, a search, and reads of a
/// message) against a stand-in that takes 50 milliseconds for a login, and prints the
/// connections the stand-in accepted, the logins it received and the time of the reads.
#[tokio::test]
#[ignore = "prints the connections and the logins of reads that follow each other"]
#[expect(clippy::print_stdout, reason = "the probe prints its counts")]
async fn the_connections_of_consecutive_reads_probe() {
    let calls: usize = std::env::var("MAIL_PROBE_CALLS")
        .ok()
        .and_then(|calls| calls.parse().ok())
        .unwrap_or(20);
    let server = ImapServer::start(|command| match command.text.starts_with("LOGIN ") {
        true => Answer::after(vec![Act::Pause(Duration::from_millis(50))]),
        false => mailbox(command),
    })
    .await;
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let started = Instant::now();
    let mut times = Vec::new();
    for call in 0..calls {
        let params = match call {
            0 => json!({"action":"folders"}),
            1 => json!({"action":"search"}),
            _ => json!({"action":"read","uid":7,"uid_validity":42}),
        };
        let call_started = Instant::now();
        let (status, meta, _) = request(&harness, &record, "read", params, b"").await;
        assert_eq!(
            (status, meta["status"].as_u64()),
            (200, Some(200)),
            "{meta}"
        );
        times.push(call_started.elapsed().as_millis() as u64);
    }
    let elapsed = started.elapsed().as_millis();
    times.sort_unstable();
    println!(
        "{}",
        json!({
            "probe": "the connections of consecutive reads",
            "calls": calls,
            "imap_connections": server.connections.load(Ordering::SeqCst),
            "imap_logins": server.logins.load(Ordering::SeqCst),
            "elapsed_ms": elapsed,
            "median_call_ms": times[times.len() / 2],
            "first_call_ms": times.first(),
            "last_call_ms": times.last(),
        })
    );
}
