//! The connections of the mail reads: what a read holds of the body budget of the node while
//! it reads, and the responses of a server that a read reads.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use super::mail::{frame_of, request};
use super::mail_stand_in::{fetch_literal, mailbox, until, Act, Answer, ImapServer, MESSAGE};
use crate::mail;
use crate::state::Limits;

/// A message of `bytes` bytes.
fn message_of(bytes: usize) -> Vec<u8> {
    let mut message = b"Subject: a long one\r\n\r\n".to_vec();
    while message.len() < bytes {
        message.extend_from_slice(b"0123456789 a line of the body of the message 0123456789\r\n");
    }
    message.truncate(bytes);
    message
}

/// The share of a read is its request frame, its fixed share, and what it holds of the input
/// it took so far: six bytes per byte of a folder listing or of a search, two per byte of a
/// raw message, in steps of 64 KiB. It is given back when the call ends.
#[tokio::test]
async fn the_share_of_a_read_follows_the_input_it_took() {
    let gate = Arc::new(Semaphore::new(0));
    // 1,000 folders: 43,000 bytes of input.
    let mut listing = Vec::new();
    for folder in 0..1_000 {
        listing.extend_from_slice(
            format!("* LIST (\\HasNoChildren) \"/\" \"Folder {folder:04}\"\r\n").as_bytes(),
        );
    }
    let long = message_of(300_000);
    let server = {
        let (gate, listing, long) = (gate.clone(), listing.clone(), long.clone());
        ImapServer::start(move |command| {
            let text = command.text;
            if text.starts_with("LIST ") {
                Answer::after(vec![Act::Send(listing.clone()), Act::Wait(gate.clone())])
            } else if text.ends_with(" (UID RFC822.SIZE)") {
                Answer::ok(format!("* 1 FETCH (UID 7 RFC822.SIZE {})\r\n", long.len()))
            } else if text.ends_with(" (UID BODY.PEEK[])") {
                // The declaration of the literal and half of its octets, then the gate.
                let response = fetch_literal(7, "", "BODY[]", &long);
                let (front, back) = response.split_at(response.len() / 2);
                Answer::after(vec![
                    Act::Send(front.to_vec()),
                    Act::Wait(gate.clone()),
                    Act::Send(back.to_vec()),
                ])
            } else {
                mailbox(command)
            }
        })
        .await
    };
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let harness = Arc::new(harness);
    let budget = harness.node.limits.body_budget_bytes;
    let held = || budget - harness.node.body_budget.available_permits();
    let step = mail::SHARE_STEP_BYTES;

    // Eight folder listings at once, each in front of the completion of its `LIST`.
    let params = json!({"action":"folders"});
    let fixed = frame_of(&record, &params, b"").len() + mail::CALL_BYTES;
    let mut calls = Vec::new();
    for _ in 0..8 {
        let (harness, record, params) = (harness.clone(), record.clone(), params.clone());
        calls.push(tokio::spawn(async move {
            request(&harness, &record, "read", params, b"").await
        }));
    }
    until("the listings wait at the gate", || {
        server.waiting.load(Ordering::SeqCst) == 8
    })
    .await;
    // Each call took the greeting, the completion of its login and the folders: 6 bytes of
    // its share per byte, in whole steps.
    let input = "* OK ready\r\n".len() + "a1 OK done\r\n".len() + listing.len();
    let expected = fixed + (6 * input).div_ceil(step) * step;
    until("the listings took the folders", || held() == 8 * expected).await;
    assert_eq!(expected, fixed + 4 * step);
    gate.add_permits(8);
    for call in calls {
        let (status, meta, body) = call.await.unwrap();
        assert_eq!((status, meta["status"].as_u64()), (200, Some(200)));
        let listed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["folders"].as_array().unwrap().len(), 1_000);
        assert_eq!(listed["folders"][999]["name"], "Folder 0999");
    }
    until("the shares of the listings are given back", || held() == 0).await;

    // One raw message read, in the middle of the octets of its message: the share covers
    // the whole of the literal from its declaration on, two bytes per byte.
    let params = json!({"action":"read","uid":7,"uid_validity":42});
    let fixed = frame_of(&record, &params, b"").len() + mail::CALL_BYTES;
    let call = {
        let (harness, record) = (harness.clone(), record.clone());
        tokio::spawn(async move { request(&harness, &record, "read", params, b"").await })
    };
    until("the read waits inside its message", || {
        server.waiting.load(Ordering::SeqCst) == 1
    })
    .await;
    until("the read took the first half", || {
        held() >= fixed + 2 * long.len()
    })
    .await;
    assert!(
        held() <= fixed + 2 * (long.len() + 1_024) + step,
        "{}",
        held()
    );
    gate.add_permits(1);
    let (status, meta, body) = call.await.unwrap();
    assert_eq!((status, meta["status"].as_u64()), (200, Some(200)));
    assert_eq!(body, long);
    until("the share of the read is given back", || held() == 0).await;
}

/// A read whose input the body budget has no room for ends where the room ends, with
/// `capacity_unavailable`: its entry is on the chain, nothing of what it read leaves, and
/// its share is given back. A verification and a submission take their whole share before
/// their entry, so they are refused without one.
#[tokio::test]
async fn a_read_ends_where_the_body_budget_has_no_room_for_its_input() {
    let long = message_of(400_000);
    let server = {
        let long = long.clone();
        ImapServer::start(move |command| {
            let text = command.text;
            if text.starts_with("EXAMINE \"Large\"") {
                Answer::ok("* 1 EXISTS\r\n* OK [UIDVALIDITY 9] valid\r\n")
            } else if text.starts_with("UID FETCH 400 ") && text.ends_with(" (UID RFC822.SIZE)") {
                Answer::ok(format!(
                    "* 1 FETCH (UID 400 RFC822.SIZE {})\r\n",
                    long.len()
                ))
            } else if text.starts_with("UID FETCH 400 ") {
                Answer::ok(fetch_literal(400, "", "BODY[]", &long))
            } else {
                mailbox(command)
            }
        })
        .await
    };
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let budget = harness.node.limits.body_budget_bytes;
    // The node has 512 KiB of its body budget left: the rest is held here.
    let free = 512 * 1024;
    let rest = harness
        .node
        .body_budget
        .clone()
        .try_acquire_many_owned((budget - free) as u32)
        .unwrap();
    let held = || budget - rest.num_permits() - harness.node.body_budget.available_permits();

    // A message of 400,000 bytes takes 800,000 bytes of share: the input ends at the
    // declaration of its literal.
    let before = harness.last_seq("mail-user");
    let (status, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"read","mailbox":"Large","uid":400,"uid_validity":9}),
        b"",
    )
    .await;
    assert_eq!(
        (status, meta["code"].as_str()),
        (503, Some("capacity_unavailable"))
    );
    assert_eq!(
        meta["message"],
        "the node has no room for the mail the call reads; the call changed nothing"
    );
    assert!(body.is_empty());
    assert_eq!(harness.last_seq("mail-user"), before + 1);
    assert_eq!(held(), 0);
    until("the connection of the read ended", || {
        server.ended.load(Ordering::SeqCst) == 1
    })
    .await;

    // The message of the other folder fits, and the node reads it.
    let (status, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"read","uid":7,"uid_validity":42}),
        b"",
    )
    .await;
    assert_eq!((status, meta["status"].as_u64()), (200, Some(200)));
    assert_eq!(body, MESSAGE);
    assert_eq!(held(), 0);

    // A verification holds 192 KiB and its frame from its start on, and a submission 128 KiB
    // and its frame. With less than that left, each is refused before it has an entry and
    // before a connection is opened.
    let _more = harness
        .node
        .body_budget
        .clone()
        .try_acquire_many_owned((free - 100 * 1024) as u32)
        .unwrap();
    let (entries, connections) = (
        harness.last_seq("mail-user"),
        server.connections.load(Ordering::SeqCst),
    );
    for (operation, params, payload) in [
        ("verify", json!({}), &b""[..]),
        (
            "submit",
            json!({"recipients":["friend@example.com"]}),
            &b"From: tester@naver.com\r\n\r\nhello\r\n"[..],
        ),
    ] {
        let (status, meta, _) = request(&harness, &record, operation, params, payload).await;
        assert_eq!(
            (status, meta["code"].as_str(), meta["message"].as_str()),
            (
                503,
                Some("capacity_unavailable"),
                Some("the call was not admitted; no provider request was sent")
            ),
            "{operation}"
        );
    }
    assert_eq!(harness.last_seq("mail-user"), entries);
    assert_eq!(server.connections.load(Ordering::SeqCst), connections);
}

/// The three responses that ended the parser of imap-proto 0.17.0, and with it a node, are
/// read inside the calls that meet them: a character outside ASCII directly behind the
/// response code of a tagged and of an untagged status response, and `INTERNALDATE NIL`.
#[tokio::test]
async fn the_responses_that_ended_the_former_parser_are_read_by_a_call() {
    let server = ImapServer::start(|command| {
        let text = command.text;
        if text.starts_with("LOGIN ") {
            Answer {
                acts: vec![Act::Send("* OK [ALERT]한 x\r\n".as_bytes().to_vec())],
                completion: "OK [READ-WRITE]é done".to_string(),
            }
        } else if text.ends_with(" (UID RFC822.SIZE)") {
            Answer::ok(format!(
                "* 1 FETCH (INTERNALDATE NIL UID 7 RFC822.SIZE {})\r\n",
                MESSAGE.len()
            ))
        } else if text.ends_with(" (UID BODY.PEEK[])") {
            Answer::ok(fetch_literal(7, "INTERNALDATE NIL ", "BODY[]", MESSAGE))
        } else if text.ends_with(" (UID RFC822.SIZE BODY.PEEK[HEADER])") {
            Answer::ok(fetch_literal(
                7,
                "INTERNALDATE NIL RFC822.SIZE 105 ",
                "BODY[HEADER]",
                b"Subject: a test\r\n\r\n",
            ))
        } else {
            mailbox(command)
        }
    })
    .await;
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let (status, meta, body) =
        request(&harness, &record, "read", json!({"action":"search"}), b"").await;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        page,
        json!({"uid_validity":42,"messages":[{"uid":7,"size":105,
            "headers_b64":STANDARD.encode("Subject: a test\r\n\r\n")}],"next_uid":null})
    );
    let (status, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"read","uid":7,"uid_validity":42}),
        b"",
    )
    .await;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    assert_eq!(body, MESSAGE);
}

/// What a server sends beside the answers a read asks for does not fail the read: a warning
/// while a mailbox opens, responses about other messages, the items of one message in two
/// responses, and a status line that ends in the form of a literal declaration.
#[tokio::test]
async fn a_read_reads_past_what_it_did_not_ask_for() {
    let server = ImapServer::start(|command| {
        let text = command.text;
        if text.starts_with("EXAMINE \"missing{100000}\"") {
            Answer::completion("NO [NONEXISTENT] Mailbox doesn't exist: missing{100000}")
        } else if text.starts_with("EXAMINE ") {
            Answer::ok(
                "* FLAGS (\\Answered \\Seen)\r\n* 2 EXISTS\r\n* 0 RECENT\r\n\
                 * NO [ALERT] The mailbox is close to its quota {12}\r\n\
                 * OK [UIDVALIDITY 0] UIDs valid\r\n* OK [UIDNEXT 8] Predicted next UID\r\n\
                 * OK [HIGHESTMODSEQ 90]\r\n",
            )
        } else if text.starts_with("UID SEARCH ") {
            Answer::ok("* 9 EXISTS\r\n* SEARCH 7 5 \r\n* SEARCH 5\r\n")
        } else if text.ends_with(" (UID RFC822.SIZE BODY.PEEK[HEADER])") {
            let mut responses = b"* 4 FETCH (FLAGS (\\Seen))\r\n\
                * 3 FETCH (UID 99 FLAGS (\\Seen) RFC822.SIZE 1)\r\n\
                * 1 FETCH (UID 7 RFC822.SIZE 105)\r\n"
                .to_vec();
            responses.extend(fetch_literal(
                7,
                "FLAGS () ",
                "BODY[HEADER]",
                b"A: 1\r\n\r\n",
            ));
            responses.extend_from_slice(b"* 2 FETCH (BODY[HEADER] \"B: \\\"2\\\"\" UID 5)\r\n");
            Answer::ok(responses)
        } else {
            mailbox(command)
        }
    })
    .await;
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let (status, meta, body) =
        request(&harness, &record, "read", json!({"action":"search"}), b"").await;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        page,
        json!({"uid_validity":0,"messages":[
            {"uid":7,"size":105,"headers_b64":STANDARD.encode("A: 1\r\n\r\n")},
            {"uid":5,"size":null,"headers_b64":STANDARD.encode("B: \"2\"")},
        ],"next_uid":null})
    );
    // A folder that is not there: the refusal names it and is one line.
    let (status, meta, _) = request(
        &harness,
        &record,
        "read",
        json!({"action":"search","mailbox":"missing{100000}"}),
        b"",
    )
    .await;
    assert_eq!(
        (status, meta["code"].as_str()),
        (502, Some("provider_unreachable"))
    );
}

/// A folder listing hands on the names a read can put into a command, as the server means
/// them: a quoted name without its escapes, a name in a literal, a name in UTF-8.
#[tokio::test]
async fn a_folder_listing_names_the_folders_a_read_can_examine() {
    let server = ImapServer::start(|command| {
        let text = command.text;
        if text.starts_with("LIST ") {
            let mut listing = b"* LIST (\\HasNoChildren) \"/\" inbox\r\n\
                * LIST (\\HasNoChildren \\Sent) \"/\" \"Sent Messages\"\r\n\
                * LIST (\\HasNoChildren) \"/\" \"quote\\\"and\\\\backslash\"\r\n\
                * LIST (\\HasNoChildren) \"/\" \"braces{12}\"\r\n\
                * LIST (\\Noselect \\HasChildren) \"/\" Projects/2026\r\n\
                * LIST () NIL {8}\r\nlite)ral\r\n"
                .to_vec();
            listing.extend_from_slice("* LIST () \"/\" \"받은 편지\"\r\n".as_bytes());
            // Names a node cannot put into a command are left out.
            listing.extend_from_slice(b"* LIST () \"/\" \"\xff\xfe\"\r\n");
            listing.extend_from_slice(b"* LIST () \"/\" \"bell\x07\"\r\n");
            listing.extend_from_slice(b"* LIST () \"/\" \"\"\r\n");
            Answer::ok(listing)
        } else if text == "EXAMINE \"quote\\\"and\\\\backslash\"" {
            Answer::ok("* OK [UIDVALIDITY 3] valid\r\n")
        } else {
            mailbox(command)
        }
    })
    .await;
    let (harness, _app, record) = server.harness(Limits::default()).await;
    let (status, meta, body) =
        request(&harness, &record, "read", json!({"action":"folders"}), b"").await;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"folders":[
            {"name":"INBOX"},{"name":"Sent Messages"},{"name":"quote\"and\\backslash"},
            {"name":"braces{12}"},{"name":"Projects/2026"},{"name":"lite)ral"},
            {"name":"받은 편지"},
        ]})
    );
    // The name the listing gave opens the folder.
    let (status, meta, body) = request(
        &harness,
        &record,
        "read",
        json!({"action":"search","mailbox":"quote\"and\\backslash"}),
        b"",
    )
    .await;
    assert_eq!(
        (status, meta["status"].as_u64()),
        (200, Some(200)),
        "{meta}"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["uid_validity"],
        3
    );
    assert!(server
        .texts()
        .contains(&"EXAMINE \"quote\\\"and\\\\backslash\"".to_string()));
}
