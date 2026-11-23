//! The delegation subset (protocol.md 10.4): which nodes of a pool hold the delegation of an
//! account.
//!
//! The operator runs its nodes in pools. The nodes of a pool are numbered by their ordinal, 0
//! to `pods - 1`, and every account has its delegation on `copies` of them. An account ranks
//! the ordinals by `SHA-256(user_id || "\n" || ordinal)`, the ordinal written as decimal
//! digits.
//!
//! Without `groups` the nodes of an account are the first `copies` ordinals of that order: the
//! assignment of the releases before v2.4.0.
//!
//! With `groups`, the name of a group for every ordinal (the place that node runs in: its
//! availability zone), an account also ranks the groups, by
//! `SHA-256(user_id || "\n" || "zone" || "\n" || group)`. Its nodes are one ordinal of each of
//! `copies` groups: the groups at the positions `skip` to `skip + copies - 1` of that order,
//! and of each of them the ordinal that ranks first. The order of the groups depends on the
//! account and the names alone, so two pools whose nodes run in the same groups agree on it:
//! a pool that takes the groups 0 and 1 of an account and a pool that takes its group 2 (`skip`
//! 2) hold the delegation of that account in three different groups.
//!
//! The assignment depends on the account, the ordinals and the group of each ordinal alone: a
//! node that restarts keeps its ordinal and its accounts. The backend of the operator computes
//! the same function to list the nodes of an account. A node computes it to select the
//! accounts of a transfer page (`peer/export`), to keep its own share of a transfer
//! (`peer/import`) and to drop the grants outside its share (`grants/prune`). A node does not
//! know its own ordinal: the caller names it.
//!
//! No function here takes a secret: the inputs are the `user_id` of an account and the values
//! of the `subset` object of a request.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Most nodes a pool names (`pods`).
pub const PODS_MAX: u32 = 1024;

/// Longest name of a group, in bytes.
pub const GROUP_NAME_BYTES: usize = 63;

/// The hash that orders the ordinals of an account:
/// `SHA-256(UTF-8(user_id) || "\n" || the ordinal as decimal digits)`.
pub fn rank(user_id: &str, ordinal: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(ordinal.to_string().as_bytes());
    hasher.finalize().into()
}

/// The hash that orders the groups of an account:
/// `SHA-256(UTF-8(user_id) || "\n" || "zone" || "\n" || the bytes of the name)`.
///
/// A `user_id` holds no line feed (protocol.md section 1) and a group name none either, so
/// the input of this hash has two line feeds and the input of [`rank`] one: no ordinal and no
/// group of any account share an input.
pub fn group_rank(user_id: &str, group: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(b"\nzone\n");
    hasher.update(group.as_bytes());
    hasher.finalize().into()
}

/// True for the name of a group: 1 to 63 bytes, each an ASCII letter, a digit, `-`, `_` or
/// `.`. Two names are the same group when their bytes are equal.
pub fn is_group_name(text: &str) -> bool {
    (1..=GROUP_NAME_BYTES).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The groups of the nodes of a pool, and the groups an account passes over.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Groups {
    /// The distinct names, in the order of their first ordinal.
    names: Vec<String>,
    /// The ordinals of every group, ascending, in the order of `names`.
    members: Vec<Vec<u32>>,
    /// The group of every ordinal: its index in `names`.
    of: Vec<usize>,
    /// The groups at the front of the order of an account that this pool does not take.
    skip: u32,
}

/// How the delegations of the accounts are placed on the nodes of one pool: the values of a
/// `subset` object without its `pod`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pods: u32,
    copies: u32,
    groups: Option<Groups>,
}

impl Placement {
    /// A placement of `pods` nodes (1 to [`PODS_MAX`]) with `copies` nodes per account (at
    /// least 1).
    ///
    /// Without `groups`, `skip` is not read: it counts groups, and there are none. With
    /// `groups`, there is exactly one group name ([`is_group_name`]) per ordinal, and the
    /// names are at least `skip + copies` different ones: every account then has one node in
    /// each of `copies` groups. `None` for any other value.
    pub fn new(pods: u32, copies: u32, groups: Option<&[&str]>, skip: u32) -> Option<Placement> {
        if !(1..=PODS_MAX).contains(&pods) || copies < 1 {
            return None;
        }
        let Some(listed) = groups else {
            return Some(Placement {
                pods,
                copies,
                groups: None,
            });
        };
        if u32::try_from(listed.len()) != Ok(pods) {
            return None;
        }
        let mut names: Vec<String> = Vec::new();
        let mut members: Vec<Vec<u32>> = Vec::new();
        let mut of = Vec::with_capacity(listed.len());
        for (ordinal, name) in (0..pods).zip(listed) {
            if !is_group_name(name) {
                return None;
            }
            let index = match names.iter().position(|known| known == name) {
                Some(index) => index,
                None => {
                    names.push((*name).to_string());
                    members.push(Vec::new());
                    names.len().saturating_sub(1)
                }
            };
            members.get_mut(index)?.push(ordinal);
            of.push(index);
        }
        let taken = u64::from(skip).saturating_add(u64::from(copies));
        if taken > u64::try_from(names.len()).ok()? {
            return None;
        }
        Some(Placement {
            pods,
            copies,
            groups: Some(Groups {
                names,
                members,
                of,
                skip,
            }),
        })
    }

    /// The nodes of the pool.
    pub fn pods(&self) -> u32 {
        self.pods
    }

    /// The groups of the pool in the order `user_id` takes them: ascending by
    /// ([`group_rank`], the bytes of the name). Empty for a placement without groups.
    pub fn group_order(&self, user_id: &str) -> Vec<&str> {
        let Some(groups) = &self.groups else {
            return Vec::new();
        };
        let mut ranked: Vec<([u8; 32], &str)> = groups
            .names
            .iter()
            .map(|name| (group_rank(user_id, name), name.as_str()))
            .collect();
        ranked.sort_unstable();
        ranked.into_iter().map(|(_, name)| name).collect()
    }

    /// The ordinals of `group` in the order `user_id` takes them: ascending by ([`rank`], the
    /// ordinal). With `None`, every ordinal of the pool in that order. Empty for a group the
    /// placement does not name.
    pub fn ranked(&self, user_id: &str, group: Option<&str>) -> Vec<u32> {
        let ordinals: Vec<u32> = match (group, &self.groups) {
            (None, _) => (0..self.pods).collect(),
            (Some(group), Some(groups)) => groups
                .names
                .iter()
                .position(|name| name == group)
                .and_then(|index| groups.members.get(index))
                .cloned()
                .unwrap_or_default(),
            (Some(_), None) => Vec::new(),
        };
        let mut ranked: Vec<([u8; 32], u32)> = ordinals
            .into_iter()
            .map(|ordinal| (rank(user_id, ordinal), ordinal))
            .collect();
        ranked.sort_unstable();
        ranked.into_iter().map(|(_, ordinal)| ordinal).collect()
    }

    /// The ordinals that hold the delegation of `user_id`, in the order the account takes
    /// them.
    ///
    /// Without groups: the first `min(copies, pods)` ordinals of the pool in the order of
    /// their rank. With groups: for each of the `copies` groups from the position `skip` of
    /// [`Placement::group_order`] on, in that order, the ordinal of the group that ranks
    /// first.
    pub fn assign(&self, user_id: &str) -> Vec<u32> {
        let copies = usize::try_from(self.copies).unwrap_or(usize::MAX);
        let Some(groups) = &self.groups else {
            let mut ranked = self.ranked(user_id, None);
            ranked.truncate(copies);
            return ranked;
        };
        let skip = usize::try_from(groups.skip).unwrap_or(usize::MAX);
        self.group_order(user_id)
            .into_iter()
            .skip(skip)
            .take(copies)
            .filter_map(|group| self.ranked(user_id, Some(group)).first().copied())
            .collect()
    }

    /// True when the node of ordinal `pod` holds the delegation of `user_id`:
    /// [`Placement::assign`] contains `pod`. The answer is computed from the ranks `pod` is
    /// compared with alone, without the whole assignment.
    pub fn holds(&self, user_id: &str, pod: u32) -> bool {
        if pod >= self.pods {
            return false;
        }
        let own = (rank(user_id, pod), pod);
        let Some(groups) = &self.groups else {
            // The ordinals that rank before `pod` are fewer than the copies.
            let before = (0..self.pods)
                .filter(|other| (rank(user_id, *other), *other) < own)
                .count();
            return u64::try_from(before).is_ok_and(|before| before < u64::from(self.copies));
        };
        let group = usize::try_from(pod)
            .ok()
            .and_then(|ordinal| groups.of.get(ordinal));
        let Some((name, members)) =
            group.and_then(|index| groups.names.get(*index).zip(groups.members.get(*index)))
        else {
            return false;
        };
        // The position of the group of `pod` in the order of the account is one this pool
        // takes, and `pod` ranks first among the ordinals of that group.
        let own_group = (group_rank(user_id, name), name.as_str());
        let position = groups
            .names
            .iter()
            .filter(|other| (group_rank(user_id, other), other.as_str()) < own_group)
            .count();
        let Ok(position) = u64::try_from(position) else {
            return false;
        };
        let first = u64::from(groups.skip);
        position >= first
            && position < first.saturating_add(u64::from(self.copies))
            && members
                .iter()
                .all(|other| (rank(user_id, *other), *other) >= own)
    }
}

/// The nodes of `user_id` among `pods` nodes of a pool with `copies` nodes per account, the
/// groups `groups` and `skip` groups passed over: [`Placement::assign`] of the placement these
/// values make, `None` when they make none ([`Placement::new`]).
pub fn assign(
    user_id: &str,
    pods: u32,
    copies: u32,
    groups: Option<&[&str]>,
    skip: u32,
) -> Option<Vec<u32>> {
    Placement::new(pods, copies, groups, skip).map(|placement| placement.assign(user_id))
}

/// The `subset` object of a request: the placement of a pool and the ordinal of the node of
/// that pool the request is about (`pod`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subset {
    placement: Placement,
    pod: u32,
}

impl Subset {
    /// Reads a `subset` object.
    ///
    /// `pods` (1 to [`PODS_MAX`]), `pod` (below `pods`) and `copies` (at least 1) are
    /// integers. `groups` is optional: an array of exactly `pods` group names
    /// ([`is_group_name`]), absent or null for a pool without groups. `skip` is optional: an
    /// integer, absent or null for 0, and with `groups` the names are at least
    /// `skip + copies` different ones. Without `groups` the value of `skip` changes nothing.
    /// Other keys are not read. `None` for any other value.
    pub fn from_value(value: &Value) -> Option<Subset> {
        let object = value.as_object()?;
        let integer = |key: &str| -> Option<u32> {
            object
                .get(key)?
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
        };
        let (pods, pod, copies) = (integer("pods")?, integer("pod")?, integer("copies")?);
        let skip = match object.get("skip") {
            None | Some(Value::Null) => 0,
            Some(_) => integer("skip")?,
        };
        let groups: Option<Vec<&str>> = match object.get("groups") {
            None | Some(Value::Null) => None,
            Some(groups) => Some(
                groups
                    .as_array()?
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<&str>>>()?,
            ),
        };
        let placement = Placement::new(pods, copies, groups.as_deref(), skip)?;
        (pod < pods).then_some(Subset { placement, pod })
    }

    /// The placement of the pool.
    pub fn placement(&self) -> &Placement {
        &self.placement
    }

    /// The ordinal of the node the request is about.
    pub fn pod(&self) -> u32 {
        self.pod
    }

    /// True when the node of ordinal `pod` is one of the nodes of `user_id`.
    pub fn contains(&self, user_id: &str) -> bool {
        self.placement.holds(user_id, self.pod)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use serde_json::json;

    /// The assignment of release v2.3.0, as its source computes it
    /// (`enclave/src/subset.rs` of the tag): the first `min(copies, pods)` ordinals in the
    /// ascending order of (rank, ordinal). Written apart from [`Placement`].
    fn assign_v2_3_0(user_id: &str, pods: u32, copies: u32) -> BTreeSet<u32> {
        let mut ranked: Vec<([u8; 32], u32)> = (0..pods)
            .map(|ordinal| {
                let mut hasher = Sha256::new();
                hasher.update(user_id.as_bytes());
                hasher.update(b"\n");
                hasher.update(ordinal.to_string().as_bytes());
                let rank: [u8; 32] = hasher.finalize().into();
                (rank, ordinal)
            })
            .collect();
        ranked.sort_unstable();
        ranked
            .into_iter()
            .take(copies.min(pods) as usize)
            .map(|(_, ordinal)| ordinal)
            .collect()
    }

    fn set(ordinals: &[u32]) -> BTreeSet<u32> {
        ordinals.iter().copied().collect()
    }

    fn as_set(ordinals: Vec<u32>) -> BTreeSet<u32> {
        let count = ordinals.len();
        let set: BTreeSet<u32> = ordinals.into_iter().collect();
        assert_eq!(set.len(), count, "an assignment names an ordinal once");
        set
    }

    fn users(count: u32) -> impl Iterator<Item = String> {
        (0..count).map(|index| format!("account-{index}"))
    }

    /// The group of every ordinal of `0..pods` when the ordinals go round `names`.
    fn round_robin<'a>(pods: u32, names: &[&'a str]) -> Vec<&'a str> {
        (0..pods as usize)
            .map(|ordinal| names[ordinal % names.len()])
            .collect()
    }

    const THREE: [&str; 3] = ["us-west-2a", "us-west-2b", "us-west-2c"];

    /// The vectors of protocol.md 10.4 without `groups`: the assignment of release v2.3.0.
    #[test]
    fn the_assignment_vectors_without_groups_hold() {
        let assigned = |user_id: &str, pods: u32, copies: u32| {
            as_set(assign(user_id, pods, copies, None, 0).unwrap())
        };
        assert_eq!(assigned("user-1", 3, 2), set(&[0, 1]));
        assert_eq!(
            assigned("00000000-0000-4000-8000-000000000007", 12, 2),
            set(&[2, 6])
        );
        assert_eq!(assigned("alice", 5, 3), set(&[0, 2, 3]));
        assert_eq!(assigned("bob", 4, 1), set(&[1]));
        assert_eq!(assigned("사용자 1", 6, 2), set(&[0, 4]));
        // `copies` at or above `pods` names every ordinal.
        assert_eq!(assigned("carol", 2, 5), set(&[0, 1]));
        assert_eq!(assigned("carol", 2, 2), set(&[0, 1]));
        // The rank of ordinal 7 of the second vector: the hash of the bytes of the account,
        // a line feed and the decimal digits of the ordinal.
        let mut hasher = Sha256::new();
        hasher.update(b"00000000-0000-4000-8000-000000000007\n7");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(rank("00000000-0000-4000-8000-000000000007", 7), expected);
        // The order of the assignment is the order of the ranks.
        assert_eq!(assign("bob", 4, 4, None, 0).unwrap(), [1, 0, 3, 2]);
        assert_eq!(assign("bob", 4, 2, None, 0).unwrap(), [1, 0]);
    }

    #[test]
    fn without_groups_the_assignment_is_that_of_release_v2_3_0() {
        for pods in 1..=16u32 {
            for copies in 1..=5u32 {
                for user_id in users(40) {
                    let expected = assign_v2_3_0(&user_id, pods, copies);
                    // `skip` counts groups: without groups its value changes nothing.
                    for skip in [0, 2] {
                        let placement = Placement::new(pods, copies, None, skip).unwrap();
                        assert_eq!(
                            as_set(placement.assign(&user_id)),
                            expected,
                            "{user_id} {pods} {copies} {skip}"
                        );
                        for pod in 0..pods {
                            assert_eq!(
                                placement.holds(&user_id, pod),
                                expected.contains(&pod),
                                "{user_id} {pods} {pod} {copies}"
                            );
                        }
                        assert!(!placement.holds(&user_id, pods));
                    }
                    assert_eq!(expected.len() as u32, copies.min(pods));
                }
            }
        }
        // The largest pool, and the `subset` object a backend of release v2.3.0 sends.
        for user_id in users(5) {
            let expected = assign_v2_3_0(&user_id, PODS_MAX, 2);
            for pod in expected.iter().copied().chain([0, 511, 1023]) {
                let subset =
                    Subset::from_value(&json!({"pods": PODS_MAX, "pod": pod, "copies": 2}))
                        .unwrap();
                assert_eq!(subset.contains(&user_id), expected.contains(&pod));
            }
        }
    }

    #[test]
    fn the_hash_of_a_group_is_that_of_the_account_the_word_zone_and_the_name() {
        let mut hasher = Sha256::new();
        hasher.update("사용자 1\nzone\nus-west-2a".as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(group_rank("사용자 1", "us-west-2a"), expected);
        // The order of the groups of an account is the order of those hashes, and it does not
        // depend on which ordinal runs in which group.
        let first = Placement::new(6, 2, Some(&round_robin(6, &THREE)), 0).unwrap();
        let second = Placement::new(
            4,
            1,
            Some(&["us-west-2c", "us-west-2c", "us-west-2b", "us-west-2a"]),
            2,
        )
        .unwrap();
        for user_id in users(50) {
            let mut expected: Vec<&str> = THREE.to_vec();
            expected.sort_by_key(|name| group_rank(&user_id, name));
            assert_eq!(first.group_order(&user_id), expected);
            assert_eq!(second.group_order(&user_id), expected);
        }
        assert!(Placement::new(3, 2, None, 0)
            .unwrap()
            .group_order("user-1")
            .is_empty());
    }

    #[test]
    fn with_groups_the_nodes_of_an_account_are_the_first_ordinal_of_each_of_its_groups() {
        for (pods, names) in [
            (3u32, &THREE[..]),
            (6, &THREE[..]),
            (15, &THREE[..]),
            (16, &THREE[..]),
            (9, &["a", "b", "c", "d"][..]),
            (7, &["x", "y"][..]),
            (5, &["one"][..]),
        ] {
            let groups = round_robin(pods, names);
            let count = names.len() as u32;
            for copies in 1..=count {
                for skip in 0..=(count - copies) {
                    let placement = Placement::new(pods, copies, Some(&groups), skip).unwrap();
                    for user_id in users(80) {
                        let assigned = placement.assign(&user_id);
                        assert_eq!(assigned.len() as u32, copies);
                        // The groups of the account, in its order, from `skip` on: one
                        // ordinal of each, the one that ranks first in it.
                        let order = placement.group_order(&user_id);
                        let taken = &order[skip as usize..(skip + copies) as usize];
                        for (ordinal, group) in assigned.iter().zip(taken) {
                            assert_eq!(groups[*ordinal as usize], *group);
                            let ranked = placement.ranked(&user_id, Some(group));
                            assert_eq!(ranked.first(), Some(ordinal));
                            let mut expected: Vec<u32> = (0..pods)
                                .filter(|ordinal| groups[*ordinal as usize] == *group)
                                .collect();
                            expected.sort_by_key(|ordinal| rank(&user_id, *ordinal));
                            assert_eq!(ranked, expected);
                        }
                        // `holds` answers what the assignment says, for every ordinal.
                        for pod in 0..pods {
                            assert_eq!(
                                placement.holds(&user_id, pod),
                                assigned.contains(&pod),
                                "{user_id} {pods} {pod} {copies} {skip}"
                            );
                        }
                        assert!(!placement.holds(&user_id, pods));
                    }
                }
            }
        }
    }

    #[test]
    fn two_pools_that_share_their_groups_place_an_account_in_three_groups() {
        // A pool of the delegation role takes the first two groups of an account, and a pool
        // of the reserve role the third one. The two pools have their own ordinals, and the
        // nodes of each are spread over the three groups in another way.
        let calls = [
            "us-west-2a",
            "us-west-2b",
            "us-west-2c",
            "us-west-2b",
            "us-west-2a",
            "us-west-2c",
            "us-west-2a",
        ];
        let reserve = ["us-west-2c", "us-west-2a", "us-west-2b", "us-west-2c"];
        let call_pool = Placement::new(7, 2, Some(&calls), 0).unwrap();
        let reserve_pool = Placement::new(4, 1, Some(&reserve), 2).unwrap();
        let mut per_group: BTreeMap<&str, usize> = BTreeMap::new();
        for user_id in users(600) {
            let of_calls = call_pool.assign(&user_id);
            let of_reserve = reserve_pool.assign(&user_id);
            assert_eq!((of_calls.len(), of_reserve.len()), (2, 1));
            let groups: BTreeSet<&str> = of_calls
                .iter()
                .map(|ordinal| calls[*ordinal as usize])
                .chain(of_reserve.iter().map(|ordinal| reserve[*ordinal as usize]))
                .collect();
            assert_eq!(groups.len(), 3, "{user_id}: {of_calls:?} {of_reserve:?}");
            *per_group
                .entry(reserve[of_reserve[0] as usize])
                .or_default() += 1;
        }
        // Every group is the third one of about a third of the accounts.
        assert_eq!(per_group.len(), 3);
        assert!(per_group.values().all(|count| (150..=250).contains(count)));
    }

    #[test]
    fn the_loss_of_one_group_takes_one_node_of_an_account_at_the_most() {
        let groups = round_robin(15, &THREE);
        let placement = Placement::new(15, 3, Some(&groups), 0).unwrap();
        for user_id in users(300) {
            let assigned = placement.assign(&user_id);
            for lost in THREE {
                let left = assigned
                    .iter()
                    .filter(|ordinal| groups[**ordinal as usize] != lost)
                    .count();
                assert_eq!(left, 2, "{user_id} {lost}");
            }
        }
    }

    #[test]
    fn a_node_more_or_less_in_a_group_moves_the_accounts_that_rank_it_first_there() {
        // A sixteenth node in the group of the ordinals 0, 3, 6, 9 and 12: an account
        // changes a node only when the new ordinal ranks first in that group for it, and
        // the node it leaves is of the same group.
        let before = round_robin(15, &THREE);
        let mut after = before.clone();
        after.push(THREE[0]);
        let old = Placement::new(15, 2, Some(&before), 0).unwrap();
        let new = Placement::new(16, 2, Some(&after), 0).unwrap();
        let mut moved = 0;
        for user_id in users(600) {
            let (was, is) = (old.assign(&user_id), new.assign(&user_id));
            if was == is {
                continue;
            }
            moved += 1;
            let left: Vec<u32> = was.iter().copied().filter(|o| !is.contains(o)).collect();
            let gained: Vec<u32> = is.iter().copied().filter(|o| !was.contains(o)).collect();
            assert_eq!(gained, [15], "{user_id}");
            assert_eq!(left.len(), 1, "{user_id}");
            assert_eq!(before[left[0] as usize], THREE[0], "{user_id}");
        }
        // Two of the three groups of an account are taken, and the new node ranks first
        // among the six of its group for one account in six: about 600 x 2/3 x 1/6.
        assert!((35..=100).contains(&moved), "{moved}");
    }

    #[test]
    fn a_subset_is_read_from_its_integers_its_groups_and_its_skip() {
        let read = |value: Value| Subset::from_value(&value);
        let subset = read(json!({"pods": 3, "pod": 2, "copies": 2})).unwrap();
        assert_eq!((subset.pod(), subset.placement().pods()), (2, 3));
        assert_eq!(subset.placement(), &Placement::new(3, 2, None, 0).unwrap());
        // Keys the object does not define are not read, and a null is an absent key.
        assert_eq!(
            read(
                json!({"pods": 3, "pod": 2, "copies": 2, "other": "x", "groups": null, "skip": null})
            ),
            Some(subset.clone())
        );
        assert!(read(json!({"pods": 1024, "pod": 0, "copies": 1})).is_some());
        // Without groups a skip changes nothing.
        let skipped = read(json!({"pods": 3, "pod": 2, "copies": 2, "skip": 2})).unwrap();
        for user_id in users(40) {
            assert_eq!(skipped.contains(&user_id), subset.contains(&user_id));
        }

        let grouped = read(json!({
            "pods": 6, "pod": 4, "copies": 2, "skip": 1,
            "groups": ["us-west-2a", "us-west-2b", "us-west-2c", "us-west-2a", "us-west-2b", "us-west-2c"],
        }))
        .unwrap();
        assert_eq!(
            grouped.placement(),
            &Placement::new(6, 2, Some(&round_robin(6, &THREE)), 1).unwrap()
        );
        for user_id in users(40) {
            assert_eq!(
                grouped.contains(&user_id),
                grouped.placement().assign(&user_id).contains(&4)
            );
        }
        // As many groups as `skip + copies`, and names of every character a name takes.
        for value in [
            json!({"pods": 3, "pod": 0, "copies": 3, "groups": ["a", "b", "c"]}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 2, "groups": ["a", "b", "c"]}),
            json!({"pods": 3, "pod": 0, "copies": 2, "skip": 1, "groups": ["a", "b", "c"]}),
            json!({"pods": 2, "pod": 1, "copies": 1, "groups": ["Zone_1.a-b", "z".repeat(63)]}),
            json!({"pods": 2, "pod": 1, "copies": 1, "groups": ["same", "same"]}),
        ] {
            assert!(read(value.clone()).is_some(), "{value}");
        }

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
            // A skip that is not an integer of 32 bits, with groups and without.
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": "2"}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": -1}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 1.5}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 4294967296u64}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 4294967296u64, "groups": ["a", "b", "c"]}),
            // Groups that are not one name per ordinal.
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": ["a", "b"]}),
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": ["a", "b", "c", "a"]}),
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": []}),
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": "abc"}),
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": {"0": "a", "1": "b", "2": "c"}}),
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": [0, 1, 2]}),
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": ["a", null, "c"]}),
            // A name that is not a group name.
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["", "b"]}),
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["a b", "b"]}),
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["a\nzone\nb", "b"]}),
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["us/west", "b"]}),
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["영역", "b"]}),
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["z".repeat(64), "b"]}),
            // Fewer groups than `skip + copies`: an account would have fewer nodes than its
            // copies, or two of them in one group.
            json!({"pods": 3, "pod": 0, "copies": 4, "groups": ["a", "b", "c"]}),
            json!({"pods": 3, "pod": 0, "copies": 2, "skip": 2, "groups": ["a", "b", "c"]}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 3, "groups": ["a", "b", "c"]}),
            json!({"pods": 3, "pod": 0, "copies": 2, "groups": ["a", "a", "a"]}),
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 4294967295u32, "groups": ["a", "b", "c"]}),
            json!({"pods": 3, "pod": 0, "copies": 4294967295u32, "skip": 4294967295u32, "groups": ["a", "b", "c"]}),
        ] {
            assert_eq!(read(value.clone()), None, "{value}");
        }
    }

    #[test]
    fn a_group_name_is_letters_digits_and_three_marks() {
        for name in ["a", "us-west-2a", "usw2-az1", "Zone_1.a", &"z".repeat(63)] {
            assert!(is_group_name(name), "{name}");
        }
        for name in ["", " ", "a b", "a\n", "a/b", "a:b", "é", &"z".repeat(64)] {
            assert!(!is_group_name(name), "{name:?}");
        }
    }
}
