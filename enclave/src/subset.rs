//! The delegation subset (protocol.md 10.1, enclave.md 5.13 and 5.15): which accounts a node
//! holds when the operator runs `pods` nodes and gives every account to `copies` of them.
//!
//! The nodes are numbered by their ordinal, 0 to `pods - 1`. The nodes of an account are the
//! first `copies` ordinals in the order of `SHA-256(user_id || "\n" || ordinal)`, the ordinal
//! written as decimal digits. The order depends on the account and the ordinal alone: a node
//! that restarts keeps its ordinal and its accounts, and when `pods` changes only the accounts
//! whose first `copies` ordinals gain a new one move. The backend computes the same function to
//! list the nodes of an account; a node computes it to select the accounts of a transfer page
//! (`peer/export`), to keep its own share of a transfer (`peer/import`) and to drop the grants
//! outside its share (`grants/prune`). A node does not know its own ordinal: the caller names it.
//!
//! No function here takes a secret: the inputs are the `user_id` of an account and three
//! integers of the request.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Most nodes a subset names (`pods`).
pub const PODS_MAX: u32 = 1024;

/// The hash that orders the ordinals of an account.
fn rank(user_id: &str, ordinal: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(ordinal.to_string().as_bytes());
    hasher.finalize().into()
}

/// The ordinals that hold the delegation of `user_id` among `pods` nodes, `copies` of them: the
/// first `min(copies, pods)` ordinals of `0..pods` in the ascending order of their rank, the
/// ordinal itself deciding between two equal ranks.
pub fn assign(user_id: &str, pods: u32, copies: u32) -> BTreeSet<u32> {
    let mut ranked: Vec<([u8; 32], u32)> = (0..pods)
        .map(|ordinal| (rank(user_id, ordinal), ordinal))
        .collect();
    ranked.sort_unstable();
    ranked
        .into_iter()
        .take(copies.min(pods) as usize)
        .map(|(_, ordinal)| ordinal)
        .collect()
}

/// The `subset` object of a request: the nodes the operator runs (`pods`), the ordinal of the
/// node the request is about (`pod`) and the nodes per account (`copies`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subset {
    pub pods: u32,
    pub pod: u32,
    pub copies: u32,
}

impl Subset {
    /// Reads a `subset` object: three integer keys with `pods` 1 to [`PODS_MAX`], `pod` below
    /// `pods` and `copies` at least 1. `None` for any other value.
    pub fn from_value(value: &Value) -> Option<Subset> {
        let integer = |key: &str| -> Option<u32> {
            value
                .as_object()?
                .get(key)?
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
        };
        let (pods, pod, copies) = (integer("pods")?, integer("pod")?, integer("copies")?);
        let valid = (1..=PODS_MAX).contains(&pods) && pod < pods && copies >= 1;
        valid.then_some(Subset { pods, pod, copies })
    }

    /// True when the node of ordinal `pod` is one of the nodes of `user_id`:
    /// `assign(user_id, pods, copies)` contains `pod`.
    pub fn contains(&self, user_id: &str) -> bool {
        assign(user_id, self.pods, self.copies).contains(&self.pod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The vectors of protocol.md 10.1: the backend asserts the same sets.
    #[test]
    fn the_assignment_vectors_of_the_protocol_hold() {
        let set = |ordinals: &[u32]| ordinals.iter().copied().collect::<BTreeSet<u32>>();
        assert_eq!(assign("user-1", 3, 2), set(&[0, 1]));
        assert_eq!(
            assign("00000000-0000-4000-8000-000000000007", 12, 2),
            set(&[2, 6])
        );
        assert_eq!(assign("alice", 5, 3), set(&[0, 2, 3]));
        assert_eq!(assign("bob", 4, 1), set(&[1]));
        assert_eq!(assign("사용자 1", 6, 2), set(&[0, 4]));
        // `copies` at or above `pods` names every ordinal.
        assert_eq!(assign("carol", 2, 5), set(&[0, 1]));
        assert_eq!(assign("carol", 2, 2), set(&[0, 1]));
        // The rank of ordinal 7 of the second vector: the hash of the bytes of the account,
        // a line feed and the decimal digits of the ordinal.
        let mut hasher = Sha256::new();
        hasher.update(b"00000000-0000-4000-8000-000000000007\n7");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(rank("00000000-0000-4000-8000-000000000007", 7), expected);
    }

    #[test]
    fn contains_agrees_with_the_assignment_and_every_account_has_its_copies() {
        for pods in 1..=12u32 {
            for copies in 1..=4u32 {
                for index in 0..40u32 {
                    let user_id = format!("user-{index}");
                    let assigned = assign(&user_id, pods, copies);
                    assert_eq!(
                        assigned.len() as u32,
                        copies.min(pods),
                        "{user_id} {pods} {copies}"
                    );
                    for pod in 0..pods {
                        let subset = Subset { pods, pod, copies };
                        assert_eq!(
                            subset.contains(&user_id),
                            assigned.contains(&pod),
                            "{user_id} {pods} {pod} {copies}"
                        );
                    }
                }
            }
        }
        // A change of `pods` moves only the accounts whose first ordinals gain the new one:
        // an ordinal that held an account under 3 nodes holds it under 4 nodes unless the
        // fourth node ranks before it.
        for index in 0..200u32 {
            let user_id = format!("account-{index}");
            let three = assign(&user_id, 3, 2);
            let four = assign(&user_id, 4, 2);
            let kept: BTreeSet<u32> = three.intersection(&four).copied().collect();
            assert!(!kept.is_empty(), "{user_id}: {three:?} {four:?}");
            assert!(
                four.contains(&3) || kept == three,
                "{user_id}: {three:?} {four:?}"
            );
        }
    }

    #[test]
    fn a_subset_is_read_from_three_integers_within_their_bounds() {
        assert_eq!(
            Subset::from_value(&json!({"pods": 3, "pod": 2, "copies": 2})),
            Some(Subset {
                pods: 3,
                pod: 2,
                copies: 2,
            })
        );
        assert_eq!(
            Subset::from_value(&json!({"pods": 1024, "pod": 0, "copies": 1, "other": "x"})),
            Some(Subset {
                pods: 1024,
                pod: 0,
                copies: 1,
            })
        );
        for value in [
            json!({"pods": 0, "pod": 0, "copies": 1}),
            json!({"pods": 1025, "pod": 0, "copies": 1}),
            json!({"pods": 3, "pod": 3, "copies": 1}),
            json!({"pods": 3, "pod": 0, "copies": 0}),
            json!({"pods": 3, "pod": 0}),
            json!({"pods": "3", "pod": 0, "copies": 1}),
            json!({"pods": 3.5, "pod": 0, "copies": 1}),
            json!({"pods": -3, "pod": 0, "copies": 1}),
            json!({"pods": 3, "pod": 0, "copies": 4294967296u64}),
            json!([3, 0, 1]),
            json!("3/0/1"),
            json!(null),
        ] {
            assert_eq!(Subset::from_value(&value), None, "{value}");
        }
    }
}
