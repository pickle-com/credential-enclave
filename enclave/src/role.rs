//! The role of a node (protocol.md 4.1, enclave.md section 4), and what a node of the forward
//! role keeps of the uses it sent (protocol.md 10.5).
//!
//! One node program runs in two roles. A node of the delegation role holds the delegations of
//! accounts and connects to the addresses of its provider definitions and to its log store. A
//! node of the forward role holds no delegation and opens no record: it sends the one request
//! of a secret use that a node of the delegation role sealed to it (`vault/send`).

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU8, Ordering};

use credential_enclave_protocol::keys::Role;
use credential_enclave_protocol::limits;

/// The role of a node. A node starts without a role and takes one once: the forward role from
/// the operator configuration that names it, the delegation role from an operator
/// configuration without a role or from the first call of the delegation role that reaches it.
/// A role that was taken does not change, so a node that ever held a user key never has the
/// forward role, and a node of the forward role never takes a user key.
#[derive(Debug, Default)]
pub struct RoleCell(AtomicU8);

impl RoleCell {
    const NONE: u8 = 0;
    const DELEGATION: u8 = 1;
    const FORWARD: u8 = 2;

    fn code(role: Role) -> u8 {
        match role {
            Role::Delegation => RoleCell::DELEGATION,
            Role::Forward => RoleCell::FORWARD,
        }
    }

    /// The role of the node, `None` while it has not taken one.
    pub fn get(&self) -> Option<Role> {
        match self.0.load(Ordering::SeqCst) {
            RoleCell::DELEGATION => Some(Role::Delegation),
            RoleCell::FORWARD => Some(Role::Forward),
            _ => None,
        }
    }

    /// Takes `role` when the node has none. True when the node has `role` afterwards, false
    /// when it has the other one.
    pub fn take(&self, role: Role) -> bool {
        let wanted = RoleCell::code(role);
        match self
            .0
            .compare_exchange(RoleCell::NONE, wanted, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(held) => held == wanted,
        }
    }
}

/// The numbers of the secret uses a node of the forward role sent (protocol.md 10.5), each
/// with the node time at which it was marked.
///
/// An envelope carries a number and an end. A number is marked at a node time at which the
/// end of its envelope has not passed and lies at most twice the life of an envelope ahead,
/// and it is kept for twice that life from its mark: until the end of its envelope has
/// passed. The end is judged by the clock reading the number is marked with, inside the one
/// lock of this store, and node time does not decrease. So a call that comes to mark a
/// number after the store dropped it finds the end of the envelope passed, however long the
/// call took to come there: no envelope sends two requests.
///
/// The store never drops a number before that time: when it is full, a further use is
/// refused and no number is forgotten, because a forgotten number is an envelope that can be
/// sent again.
#[derive(Default)]
pub struct UsedNonces {
    marked: HashSet<[u8; 16]>,
    /// The numbers in the order of their marks, each with the node time of its mark.
    order: VecDeque<([u8; 16], u64)>,
}

/// Why a number was not marked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceRefusal {
    /// The end of the envelope has passed, or lies further ahead than an envelope made by a
    /// node whose clock is near the clock of this one can end.
    OutOfTime,
    /// The number is marked: its envelope was used before.
    Used,
    /// The store holds as many numbers as it keeps.
    Full,
}

impl UsedNonces {
    /// How long a number is kept from its mark: twice the life of an envelope.
    pub const KEPT_MS: u64 = 2 * limits::SECRET_USE_MS;
    /// The numbers the store keeps at the same time.
    pub const CAPACITY: usize = 1_048_576;

    /// Marks the number of an envelope that ends at `not_after_ms`, at the node time
    /// `now_ms`. The caller reads `now_ms` while it holds the lock of this store. The numbers
    /// whose time has passed leave first.
    pub fn mark(
        &mut self,
        nonce: [u8; 16],
        not_after_ms: u64,
        now_ms: u64,
    ) -> Result<(), NonceRefusal> {
        let ahead_ms = not_after_ms.saturating_sub(now_ms);
        if ahead_ms == 0 || ahead_ms > UsedNonces::KEPT_MS {
            return Err(NonceRefusal::OutOfTime);
        }
        while let Some((oldest, marked_ms)) = self.order.front().copied() {
            if now_ms < marked_ms.saturating_add(UsedNonces::KEPT_MS) {
                break;
            }
            self.marked.remove(&oldest);
            self.order.pop_front();
        }
        if self.marked.contains(&nonce) {
            return Err(NonceRefusal::Used);
        }
        if self.marked.len() >= UsedNonces::CAPACITY {
            return Err(NonceRefusal::Full);
        }
        self.marked.insert(nonce);
        self.order.push_back((nonce, now_ms));
        Ok(())
    }

    /// The numbers the store keeps at this moment.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.marked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_takes_one_role_and_keeps_it() {
        let role = RoleCell::default();
        assert_eq!(role.get(), None);
        assert!(role.take(Role::Forward));
        assert_eq!(role.get(), Some(Role::Forward));
        // The same role again is the role the node has. The other one is not taken.
        assert!(role.take(Role::Forward));
        assert!(!role.take(Role::Delegation));
        assert_eq!(role.get(), Some(Role::Forward));

        let role = RoleCell::default();
        assert!(role.take(Role::Delegation));
        assert!(!role.take(Role::Forward));
        assert!(role.take(Role::Delegation));
        assert_eq!(role.get(), Some(Role::Delegation));
    }

    #[test]
    fn a_number_that_was_marked_is_not_marked_again_at_any_later_time() {
        // An envelope whose end lies as far ahead as a node takes, marked at the time 1,000.
        let (marked_ms, not_after_ms) = (1_000, 1_000 + UsedNonces::KEPT_MS);
        let number = [7u8; 16];
        let mut used = UsedNonces::default();
        assert_eq!(used.mark(number, not_after_ms, marked_ms), Ok(()));
        // While the number is kept it is a used number. From the end of the envelope on the
        // envelope is out of its time, also after the store dropped the number: other
        // numbers are marked in between, which is when a store drops what it kept.
        for (step, later_ms) in (marked_ms..marked_ms + 3 * UsedNonces::KEPT_MS)
            .step_by(997)
            .enumerate()
        {
            let other = [(step % 200) as u8 + 8; 16];
            let _ = used.mark(other, later_ms + 1, later_ms);
            let refusal = used.mark(number, not_after_ms, later_ms);
            let expected = match later_ms < not_after_ms {
                true => NonceRefusal::Used,
                false => NonceRefusal::OutOfTime,
            };
            assert_eq!(refusal, Err(expected), "{later_ms}");
        }
        assert!(used.len() < 200);

        // An envelope is marked within its time only: not at its end, not after it, and not
        // when its end lies further ahead than twice the life of an envelope.
        let mut used = UsedNonces::default();
        for (not_after_ms, now_ms) in [
            (5_000, 5_000),
            (5_000, 5_001),
            (5_000 + UsedNonces::KEPT_MS + 1, 5_000),
            (u64::MAX, 5_000),
        ] {
            assert_eq!(
                used.mark(number, not_after_ms, now_ms),
                Err(NonceRefusal::OutOfTime)
            );
        }
        assert_eq!(used.mark(number, 5_001, 5_000), Ok(()));
        assert_eq!(used.mark(number, 5_001, 5_000), Err(NonceRefusal::Used));
    }
}
