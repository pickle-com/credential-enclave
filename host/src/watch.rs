//! The watch of the enclave (enclave.md section 9): whether the enclave the host program
//! started is still running.
//!
//! The node keeps its state in memory. When the enclave ends on its own (the node program
//! aborted, the enclave ran out of memory, the hypervisor ended it), that state is gone, and
//! the one recovery is a new enclave that takes the delegations from the living nodes. The
//! host program learns of the end from `nitro-cli describe-enclaves`, which it runs every
//! [`POLL_INTERVAL`]: the JSON list of the running enclaves holds an object whose `State` is
//! `RUNNING` while the enclave runs, and holds none after it ended. [`GONE_POLLS`] consecutive
//! answers without a running enclave confirm the end: the host program then makes the
//! shutdown collection call (the backend records the node as closed), ends what is left of
//! the enclave and exits with a status that is not 0, and the container runtime starts the
//! host program again with a new enclave. One answer without a running enclave does not
//! confirm the end, and an answer that does not come (`nitro-cli` failed or took longer than
//! [`DESCRIBE_TIMEOUT`]) changes nothing: a host program that exited on a reading failure
//! would end a living node and lose its delegations. One run of `describe-enclaves` is in
//! progress at a time: a run that passed its time limit is waited for at the next poll, and
//! no second one starts beside it (a `nitro-cli` that hangs costs one thread and one child
//! process, not one per poll). Before the answer that would confirm the end counts, the host
//! program makes one `health` call to the node: a node that answers is alive whatever the
//! list said, the answer is taken as a running enclave, and the count starts over. A node
//! that does not answer is judged by the list alone, so `/livez` does not depend on the
//! responsiveness of the node.
//!
//! `GET /livez` of the status surface (`health.rs`) answers from the same observations: 200
//! until the end is confirmed, 503 after. It makes no call to the node, so the responsiveness
//! of the node (`GET /healthz`) and the life of the enclave are two signals.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::health::node_health;
use crate::log;
use crate::relay::NodeConnector;

/// Time between two runs of `describe-enclaves`.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Longest run of `describe-enclaves` that counts as an answer.
pub const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Consecutive answers without a running enclave that confirm its end.
pub const GONE_POLLS: u32 = 3;

/// No answer of `describe-enclaves` came yet.
const LAST_NONE: u8 = 0;
/// The last answer listed a running enclave.
const LAST_RUNNING: u8 = 1;
/// The last answer listed no running enclave.
const LAST_GONE: u8 = 2;

/// The observations of the enclave: the last answer of `describe-enclaves`, the consecutive
/// answers without a running enclave, and whether the end is confirmed.
pub struct EnclaveWatch {
    last: AtomicU8,
    gone_polls: AtomicU32,
    ended: AtomicBool,
    /// Woken once when the end is confirmed.
    notify: Notify,
}

impl EnclaveWatch {
    pub fn new() -> Arc<EnclaveWatch> {
        Arc::new(EnclaveWatch {
            last: AtomicU8::new(LAST_NONE),
            gone_polls: AtomicU32::new(0),
            ended: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    /// What the last answer of `describe-enclaves` said: `Some(true)` a running enclave,
    /// `Some(false)` none, `None` no answer came yet.
    pub fn running(&self) -> Option<bool> {
        match self.last.load(Ordering::SeqCst) {
            LAST_RUNNING => Some(true),
            LAST_GONE => Some(false),
            _ => None,
        }
    }

    /// True once [`GONE_POLLS`] consecutive answers listed no running enclave.
    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    /// True while one more answer without a running enclave would confirm the end.
    pub fn one_answer_from_the_end(&self) -> bool {
        !self.ended() && self.gone_polls.load(Ordering::SeqCst) + 1 >= GONE_POLLS
    }

    /// Records one run of `describe-enclaves`: `Some(true)` an answer with a running enclave,
    /// `Some(false)` an answer without one, `None` no answer (the run failed or took too
    /// long). Returns true when this observation confirmed the end of the enclave.
    pub fn observe(&self, running: Option<bool>) -> bool {
        match running {
            None => false,
            Some(true) => {
                self.last.store(LAST_RUNNING, Ordering::SeqCst);
                self.gone_polls.store(0, Ordering::SeqCst);
                false
            }
            Some(false) => {
                self.last.store(LAST_GONE, Ordering::SeqCst);
                let polls = self.gone_polls.fetch_add(1, Ordering::SeqCst) + 1;
                if polls < GONE_POLLS || self.ended.swap(true, Ordering::SeqCst) {
                    return false;
                }
                self.notify.notify_one();
                true
            }
        }
    }

    /// Resolves when the end of the enclave is confirmed.
    pub async fn wait_ended(&self) {
        if self.ended() {
            return;
        }
        self.notify.notified().await;
    }
}

/// Reads the answer of `describe-enclaves`, the JSON list of the running enclaves on one
/// line: `Some(true)` when an element has the `State` `RUNNING`, `Some(false)` when none has,
/// `None` when the text is not a JSON list.
pub fn running_enclave(line: &str) -> Option<bool> {
    let enclaves = serde_json::from_str::<Value>(line).ok()?;
    let enclaves = enclaves.as_array()?;
    Some(enclaves.iter().any(|enclave| {
        enclave
            .get("State")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "RUNNING")
    }))
}

/// Runs `describe` every [`POLL_INTERVAL`] in a blocking task, waits for its answer for
/// [`DESCRIBE_TIMEOUT`] (a run that takes longer is waited for at the next poll, and no second
/// run starts beside it), and records what it says until the end of the enclave is confirmed.
/// Before the answer that would confirm the end counts, one `health` call to `node` decides:
/// a node that answers is a running enclave. One line is logged when an answer first lists no
/// running enclave, one when the node answered all the same, one when the end is confirmed,
/// and one when a running enclave is listed again before that.
pub async fn keep_watching(
    watch: Arc<EnclaveWatch>,
    describe: impl Fn() -> Result<String, String> + Send + Sync + 'static,
    node: Arc<dyn NodeConnector>,
) {
    let describe = Arc::new(describe);
    let mut running: Option<JoinHandle<Result<String, String>>> = None;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let mut run = match running.take() {
            Some(run) => run,
            None => {
                let describe = describe.clone();
                tokio::task::spawn_blocking(move || describe())
            }
        };
        let answer = tokio::time::timeout(DESCRIBE_TIMEOUT, &mut run).await;
        let mut observation = match answer {
            Ok(Ok(Ok(line))) => running_enclave(&line),
            Ok(_) => None,
            Err(_) => {
                // The run goes on: it is waited for at the next poll.
                running = Some(run);
                None
            }
        };
        if observation == Some(false)
            && watch.one_answer_from_the_end()
            && node_health(node.as_ref()).await.is_some()
        {
            log("enclave: describe-enclaves lists no running enclave but the node answers its health call: not ended");
            observation = Some(true);
        }
        let before = watch.running();
        if watch.observe(observation) {
            log(&format!(
                "enclave: ended on its own, no running enclave in {GONE_POLLS} consecutive \
                 describe-enclaves"
            ));
            return;
        }
        match (before, observation) {
            (Some(true) | None, Some(false)) => {
                log("enclave: describe-enclaves lists no running enclave")
            }
            (Some(false), Some(true)) => {
                log("enclave: describe-enclaves lists a running enclave again")
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::testing::{health_body, Behavior, FakeNode};

    #[test]
    fn the_answer_of_describe_enclaves_says_whether_an_enclave_runs() {
        assert_eq!(
            running_enclave(
                r#"[ { "EnclaveID": "i-0-enc1", "State": "RUNNING", "MemoryMiB": 4096 } ]"#
            ),
            Some(true)
        );
        assert_eq!(
            running_enclave(r#"[{"EnclaveID":"i-0-enc1","State":"TERMINATING"}]"#),
            Some(false)
        );
        assert_eq!(running_enclave("[]"), Some(false));
        assert_eq!(running_enclave(""), None);
        assert_eq!(running_enclave("not json"), None);
        assert_eq!(running_enclave(r#"{"State":"RUNNING"}"#), None);
    }

    #[test]
    fn three_answers_without_a_running_enclave_confirm_the_end_and_one_does_not() {
        let watch = EnclaveWatch::new();
        assert_eq!(watch.running(), None);
        assert!(!watch.observe(Some(true)));
        assert_eq!(watch.running(), Some(true));
        // Two answers without a running enclave, then one with: the count starts over.
        assert!(!watch.observe(Some(false)));
        assert!(!watch.observe(Some(false)));
        assert_eq!(watch.running(), Some(false));
        assert!(!watch.observe(Some(true)));
        assert!(!watch.ended());
        // A failed run changes nothing.
        assert!(!watch.observe(Some(false)));
        assert!(!watch.observe(None));
        assert_eq!(watch.running(), Some(false));
        assert!(!watch.observe(Some(false)));
        assert!(!watch.ended());
        // The third consecutive answer confirms the end, once.
        assert!(watch.observe(Some(false)));
        assert!(watch.ended());
        assert!(!watch.observe(Some(false)));
        assert!(watch.ended());
    }

    #[test]
    fn one_answer_from_the_end_is_the_second_consecutive_answer_without_a_running_enclave() {
        let watch = EnclaveWatch::new();
        assert!(!watch.one_answer_from_the_end());
        watch.observe(Some(false));
        assert!(!watch.one_answer_from_the_end());
        watch.observe(Some(false));
        assert!(watch.one_answer_from_the_end());
        watch.observe(Some(true));
        assert!(!watch.one_answer_from_the_end());
        watch.observe(Some(false));
        watch.observe(Some(false));
        assert!(watch.one_answer_from_the_end());
        watch.observe(Some(false));
        assert!(watch.ended());
        assert!(!watch.one_answer_from_the_end());
    }

    #[tokio::test(start_paused = true)]
    async fn the_watch_confirms_the_end_after_three_polls_and_a_failed_run_does_not_count() {
        let watch = EnclaveWatch::new();
        let answers = Arc::new(Mutex::new(vec![
            Ok(r#"[{"State":"RUNNING"}]"#.to_string()),
            Ok("[]".to_string()),
            Err("nitro-cli describe-enclaves ended with exit status: 1".to_string()),
            Ok("[]".to_string()),
            Ok("[]".to_string()),
            Ok(r#"[{"State":"RUNNING"}]"#.to_string()),
        ]));
        let answers_of_the_watch = answers.clone();
        // The node is gone with the enclave: its health call does not answer.
        let watching = tokio::spawn(keep_watching(
            watch.clone(),
            move || {
                let mut answers = answers_of_the_watch.lock().unwrap();
                if answers.is_empty() {
                    Ok("[]".to_string())
                } else {
                    answers.remove(0)
                }
            },
            FakeNode::new(Behavior::Unreachable),
        ));
        let started = tokio::time::Instant::now();
        watch.wait_ended().await;
        // Five polls: running, none, a failed run, none, none.
        let waited = started.elapsed();
        assert!(
            waited >= 5 * POLL_INTERVAL && waited < 6 * POLL_INTERVAL,
            "{waited:?}"
        );
        watching.await.unwrap();
        // The answer after the confirmation was never asked for.
        assert_eq!(answers.lock().unwrap().len(), 1);
        // A wait after the confirmation resolves at once.
        watch.wait_ended().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_answers_its_health_call_keeps_the_end_from_being_confirmed() {
        let watch = EnclaveWatch::new();
        // Every answer lists no running enclave, but the node answers: the third answer of
        // every run of three is taken as a running enclave, and the end is never confirmed.
        let node = FakeNode::answering(|_| (200, health_body(true, 1, 1_790_000_000_000)));
        let watching = tokio::spawn(keep_watching(
            watch.clone(),
            || Ok("[]".to_string()),
            node.clone(),
        ));
        // Nine polls, and a second past the ninth so that its health call is counted.
        assert!(tokio::time::timeout(
            9 * POLL_INTERVAL + Duration::from_secs(1),
            watch.wait_ended()
        )
        .await
        .is_err());
        assert!(!watch.ended());
        assert_eq!(watch.running(), Some(true));
        // One health call per three polls.
        assert_eq!(node.calls().len(), 3);
        watching.abort();
    }
}
