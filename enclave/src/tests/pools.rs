//! The pools of a fleet (protocol.md 10.4): the delegation subset with `groups` and `skip` in
//! `peer/export`, `peer/import` and `grants/prune`, a pool of nodes of the reserve role that
//! takes the third group of every account, a change of the placement of a pool, in which
//! no account loses a node before its new nodes hold its delegation, and a fleet of two
//! pools that divide the accounts by their spans.

use std::collections::BTreeSet;

use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::subset::{span_number, Placement};
use serde_json::{json, Value};

use super::quiet_provider;
use crate::testing::{App, Harness, Provider};

const GROUPS: [&str; 3] = ["us-west-2a", "us-west-2b", "us-west-2c"];

/// The attestation response of a node, as the operator domain fetches it for the other node.
async fn attestation(harness: &Harness) -> Value {
    let (status, response) = harness
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await;
    assert_eq!(status, 200);
    response
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

/// The accounts of the tests, each with its app.
fn apps(count: u8) -> Vec<App> {
    (0..count)
        .map(|index| App::new(&format!("account-{index:02}"), index + 1))
        .collect()
}

/// The `subset` object of the node of ordinal `pod` of a pool.
fn subset(pool: &Value, pod: u32) -> Value {
    let mut subset = pool.clone();
    subset["pod"] = json!(pod);
    subset
}

/// The placement a pool object states.
fn placement(pool: &Value) -> Placement {
    let number = |key: &str| pool[key].as_u64().map_or(0, |number| number as u32);
    let groups: Option<Vec<&str>> = pool["groups"]
        .as_array()
        .map(|groups| groups.iter().map(|name| name.as_str().unwrap()).collect());
    Placement::new(
        number("pods"),
        number("copies"),
        groups.as_deref(),
        number("skip"),
    )
    .unwrap()
}

/// True when the node holds a grant of the account within its time.
async fn holds(harness: &Harness, user_id: &str) -> bool {
    let (status, response) = harness
        .post("/v1/status", json!({"user_id": user_id}))
        .await;
    assert_eq!(status, 200, "{response}");
    response["grant"]["state"] == "active"
}

/// The ordinals of `nodes` that hold a grant of the account.
async fn holders(nodes: &[Harness], user_id: &str) -> Vec<u32> {
    let mut holders = Vec::new();
    for (ordinal, node) in nodes.iter().enumerate() {
        if holds(node, user_id).await {
            holders.push(ordinal as u32);
        }
    }
    holders
}

/// Hands the share of `receiving`, the node the `subset` is about, from `giving` to it: every
/// page of `peer/export` with the subset, each taken by `peer/import` with the same subset.
/// Returns the number of grants the imports put in place, and the accounts they named: the
/// accounts whose grant of the transfer the receiving node holds afterwards.
async fn fill(giving: &Harness, receiving: &Harness, subset: &Value) -> (usize, Vec<String>) {
    let (to, from) = (attestation(receiving).await, attestation(giving).await);
    let mut placed = 0;
    let mut taken = Vec::new();
    let mut after = String::new();
    loop {
        let (status, page) = giving
            .post(
                "/v1/peer/export",
                json!({"peer": to, "after": after, "limit": 7, "subset": subset}),
            )
            .await;
        assert_eq!(status, 200, "{page}");
        if !page["envelope"].is_null() {
            let import = json!({"peer": from, "envelope": page["envelope"], "subset": subset});
            let (status, imported) = receiving.post("/v1/peer/import", import).await;
            assert_eq!(status, 200, "{imported}");
            placed += imported["imported"].as_u64().unwrap() as usize;
            let accounts = imported["accounts"].as_array().unwrap().iter();
            taken.extend(accounts.map(|user_id| user_id.as_str().unwrap().to_string()));
        }
        after = page["next"].as_str().unwrap().to_string();
        if after.is_empty() {
            return (placed, taken);
        }
    }
}

/// Drops the grants outside the share of the node the `subset` is about, and returns the
/// accounts whose grants the node dropped.
async fn prune(harness: &Harness, subset: &Value) -> Vec<String> {
    let (status, pruned) = harness
        .post(
            "/v1/grants/prune",
            json!({"subset": subset, "after": "", "limit": 1000}),
        )
        .await;
    assert_eq!(status, 200, "{pruned}");
    assert_eq!(pruned["next"], "");
    let pruned = pruned["pruned"].as_array().unwrap().iter();
    pruned
        .map(|user_id| user_id.as_str().unwrap().to_string())
        .collect()
}

/// A node that took the reserve role from its operator configuration.
async fn reserve_node(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    let (status, configured) = harness.post("/v1/config", json!({"role": "reserve"})).await;
    assert_eq!(status, 200, "{configured}");
    harness
}

#[tokio::test]
async fn the_three_calls_with_groups_follow_the_assignment_of_the_groups() {
    let provider = quiet_provider().await;
    let giving = Harness::new(&provider);
    let apps = apps(24);
    for app in &apps {
        app.grant(&giving).await;
    }
    let user_ids: Vec<&str> = apps.iter().map(|app| app.user_id.as_str()).collect();
    // A pool of six nodes in three groups, two nodes per account, and the same pool with
    // the first group of an account passed over.
    let groups: Vec<&str> = (0..6).map(|ordinal| GROUPS[ordinal % 3]).collect();
    for skip in [0, 1] {
        let pool = json!({"pods": 6, "copies": 2, "groups": groups, "skip": skip});
        let placement = placement(&pool);
        let share = |pod: u32| -> Vec<String> {
            let held = |user_id: &&&str| placement.assign(user_id).contains(&pod);
            let share = user_ids.iter().filter(held);
            share.map(|user_id| user_id.to_string()).collect()
        };
        let mut shared = 0;
        for pod in 0..6u32 {
            // `peer/export` selects the accounts of the share of the receiving node, and the
            // receiving node takes them all.
            let receiving = Harness::new(&provider);
            let (placed, taken) = fill(&giving, &receiving, &subset(&pool, pod)).await;
            assert_eq!(taken, share(pod), "{pod} {skip}");
            assert_eq!(placed, taken.len(), "{pod} {skip}");
            shared += taken.len();

            // A giving node that hands every account over (a call without a subset, or a
            // node of a release that does not know the groups): `peer/import` keeps the
            // share of the receiving node, and `grants/prune` drops the rest of a node that
            // took everything.
            let (status, everything) = giving
                .post(
                    "/v1/peer/export",
                    json!({"peer": attestation(&receiving).await}),
                )
                .await;
            assert_eq!(status, 200);
            let from = attestation(&giving).await;
            let other = Harness::new(&provider);
            let (_, all) = giving
                .post(
                    "/v1/peer/export",
                    json!({"peer": attestation(&other).await}),
                )
                .await;
            let import = json!({
                "peer": from, "envelope": all["envelope"], "subset": subset(&pool, pod),
            });
            let (status, imported) = other.post("/v1/peer/import", import).await;
            assert_eq!(status, 200, "{imported}");
            assert_eq!(imported["accounts"], json!(share(pod)), "{pod} {skip}");
            let import = json!({"peer": from, "envelope": everything["envelope"]});
            let (status, imported) = receiving.post("/v1/peer/import", import).await;
            assert_eq!(status, 200, "{imported}");
            assert_eq!(receiving.health().await["grants"], 24);
            let outside: Vec<String> = user_ids
                .iter()
                .filter(|user_id| !share(pod).contains(&user_id.to_string()))
                .map(|user_id| user_id.to_string())
                .collect();
            assert_eq!(prune(&receiving, &subset(&pool, pod)).await, outside);
            assert_eq!(
                receiving.health().await["grants"].as_u64(),
                Some(share(pod).len() as u64)
            );
        }
        // Every account is in the share of two nodes of the pool.
        assert_eq!(shared, 2 * apps.len());
    }

    // A subset whose groups are not one name per ordinal, or name fewer groups than
    // `skip + copies`, is refused by the three calls, and nothing changes.
    let receiving = Harness::new(&provider);
    let (to, from) = (attestation(&receiving).await, attestation(&giving).await);
    let (_, everything) = giving.post("/v1/peer/export", json!({"peer": to})).await;
    for subset in [
        json!({"pods": 6, "pod": 0, "copies": 2, "groups": ["a", "b", "c"]}),
        json!({"pods": 3, "pod": 0, "copies": 2, "groups": ["a", "b", "c"], "skip": 2}),
        json!({"pods": 3, "pod": 0, "copies": 2, "groups": ["a", "a", "a"]}),
        json!({"pods": 3, "pod": 0, "copies": 1, "groups": ["a", "b", "us west"]}),
        json!({"pods": 3, "pod": 0, "copies": 1, "groups": [0, 1, 2]}),
        json!({"pods": 3, "pod": 0, "copies": 1, "groups": ["a", "b", "c"], "skip": "0"}),
    ] {
        let outcome = giving
            .post("/v1/peer/export", json!({"peer": to, "subset": subset}))
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{subset}");
        let import = json!({"peer": from, "envelope": everything["envelope"], "subset": subset});
        let outcome = receiving.post("/v1/peer/import", import).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{subset}");
        let outcome = giving
            .post("/v1/grants/prune", json!({"subset": subset}))
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{subset}");
    }
    assert_eq!(giving.health().await["grants"], 24);
    assert_eq!(receiving.health().await["grants"], 0);
}

#[tokio::test]
async fn a_fleet_takes_a_reserve_pool_and_then_its_groups_and_no_account_loses_a_node() {
    let provider = quiet_provider().await;
    let apps = apps(30);

    // The fleet as release v2.3.0 runs it: one pool of six nodes of the delegation role
    // without groups, two nodes per account. Every app granted on the nodes of its account.
    let calls: Vec<Harness> = (0..6).map(|_| Harness::new(&provider)).collect();
    let before = json!({"pods": 6, "copies": 2});
    let old = placement(&before);
    for app in &apps {
        for ordinal in old.assign(&app.user_id) {
            app.grant(&calls[ordinal as usize]).await;
        }
    }
    for app in &apps {
        assert_eq!(
            holders(&calls, &app.user_id)
                .await
                .into_iter()
                .collect::<BTreeSet<u32>>(),
            old.assign(&app.user_id).into_iter().collect()
        );
    }

    // The first change: a pool of three nodes of the reserve role, one in each group, takes
    // the third group of every account. Each of its nodes is filled from every node of the
    // delegation role with the subset of its own pool.
    let reserve = [
        reserve_node(&provider).await,
        reserve_node(&provider).await,
        reserve_node(&provider).await,
    ];
    let reserve_pool = json!({"pods": 3, "copies": 1, "groups": GROUPS, "skip": 2});
    let third = placement(&reserve_pool);
    for (pod, receiving) in reserve.iter().enumerate() {
        let pod = pod as u32;
        let mut taken = BTreeSet::new();
        for giving in &calls {
            taken.extend(fill(giving, receiving, &subset(&reserve_pool, pod)).await.1);
        }
        // What the node took is its share of the pool, and nothing else.
        let share: BTreeSet<String> = apps
            .iter()
            .filter(|app| third.assign(&app.user_id) == [pod])
            .map(|app| app.user_id.clone())
            .collect();
        assert_eq!(taken, share, "{pod}");
        assert_eq!(
            receiving.health().await["grants"].as_u64(),
            Some(share.len() as u64)
        );
    }
    // Every account has three nodes now, and a giving node dropped nothing.
    for app in &apps {
        assert_eq!(
            holders(&reserve, &app.user_id).await,
            third.assign(&app.user_id)
        );
        assert_eq!(
            holders(&calls, &app.user_id)
                .await
                .into_iter()
                .collect::<BTreeSet<u32>>(),
            old.assign(&app.user_id).into_iter().collect()
        );
    }

    // The second change: the pool of the delegation role takes the groups of its nodes.
    // Every node whose share grows is filled with the subset of the new placement, from
    // the other nodes of its pool and from the nodes of the reserve role.
    let groups: Vec<&str> = (0..6).map(|ordinal| GROUPS[ordinal % 3]).collect();
    let after = json!({"pods": 6, "copies": 2, "groups": groups, "skip": 0});
    let new = placement(&after);
    let mut moved = 0;
    for (pod, receiving) in calls.iter().enumerate() {
        let subset = subset(&after, pod as u32);
        for (other, giving) in calls.iter().enumerate() {
            if other != pod {
                moved += fill(giving, receiving, &subset).await.0;
            }
        }
        for giving in &reserve {
            moved += fill(giving, receiving, &subset).await.0;
        }
    }
    assert!(moved > 0);
    // Between the fill and the prune an account is on its nodes of both placements: no
    // account has fewer nodes than before, and the nodes of the reserve role hold what they
    // held.
    for app in &apps {
        let (was, is) = (old.assign(&app.user_id), new.assign(&app.user_id));
        let expected: BTreeSet<u32> = was.iter().chain(&is).copied().collect();
        let held: BTreeSet<u32> = holders(&calls, &app.user_id).await.into_iter().collect();
        assert_eq!(held, expected, "{}", app.user_id);
        assert_eq!(
            holders(&reserve, &app.user_id).await,
            third.assign(&app.user_id)
        );
    }

    // The prune of the new placement: every node of the delegation role drops what is
    // outside its new share, and a node of the reserve role, pruned with the subset of its
    // own pool, drops nothing.
    let mut dropped = 0;
    for (pod, node) in calls.iter().enumerate() {
        dropped += prune(node, &subset(&after, pod as u32)).await.len();
    }
    assert_eq!(dropped, moved);
    for (pod, node) in reserve.iter().enumerate() {
        assert!(prune(node, &subset(&reserve_pool, pod as u32))
            .await
            .is_empty());
    }
    // Every account has two nodes of the delegation role and one node of the reserve role,
    // in three different groups.
    for app in &apps {
        let of_calls = holders(&calls, &app.user_id).await;
        let of_reserve = holders(&reserve, &app.user_id).await;
        assert_eq!(
            of_calls.iter().copied().collect::<BTreeSet<u32>>(),
            new.assign(&app.user_id).into_iter().collect()
        );
        assert_eq!(of_reserve, third.assign(&app.user_id));
        let mut placed: BTreeSet<&str> = of_calls
            .iter()
            .map(|ordinal| groups[*ordinal as usize])
            .collect();
        placed.extend(of_reserve.iter().map(|ordinal| GROUPS[*ordinal as usize]));
        assert_eq!(placed.len(), 3, "{}", app.user_id);
    }
}

/// The `subset` object of the node of ordinal `pod` of a pool of two nodes with one node per
/// account, with the span `span`.
fn spanned(pod: u32, span: Value) -> Value {
    json!({"pods": 2, "pod": pod, "copies": 1, "span": span})
}

#[tokio::test]
async fn a_fleet_of_two_pools_divides_the_accounts_by_their_spans() {
    let provider = quiet_provider().await;
    // One node holds the delegation of every account. The fleet becomes two pools of two
    // nodes each, with one node per account: the pool of the lower half of the span numbers
    // and the pool of the upper half.
    let giving = Harness::new(&provider);
    let apps = apps(40);
    for app in &apps {
        app.grant(&giving).await;
    }
    let (lower, upper) = (
        json!([0, 2147483647]),
        json!([2147483648u32, 4294967295u32]),
    );
    let in_lower = |user_id: &str| span_number(user_id) <= 2_147_483_647;
    let pool = placement(&json!({"pods": 2, "copies": 1}));
    assert!(apps.iter().filter(|app| in_lower(&app.user_id)).count() >= 10);
    assert!(apps.iter().filter(|app| !in_lower(&app.user_id)).count() >= 10);

    // Every node is filled with the subset of its pool: the giving node hands over the
    // accounts of the span of that pool whose assignment names the node, and no other.
    let mut nodes = Vec::new();
    for (span, of_lower) in [(&lower, true), (&upper, false)] {
        for pod in 0..2u32 {
            let node = Harness::new(&provider);
            let (placed, taken) = fill(&giving, &node, &spanned(pod, span.clone())).await;
            let expected: Vec<String> = apps
                .iter()
                .map(|app| app.user_id.clone())
                .filter(|user_id| in_lower(user_id) == of_lower && pool.holds(user_id, pod))
                .collect();
            assert!(!expected.is_empty());
            assert_eq!((placed, &taken), (expected.len(), &expected), "{pod}");
            assert_eq!(node.health().await["grants"], expected.len());
            nodes.push(node);
        }
    }
    // Every account is on one node of the fleet: a node of the pool of its span.
    for app in &apps {
        let on = holders(&nodes, &app.user_id).await;
        let of_lower = in_lower(&app.user_id);
        let expected = pool.assign(&app.user_id)[0] + if of_lower { 0 } else { 2 };
        assert_eq!(on, [expected], "{}", app.user_id);
    }

    // A node that holds the accounts of its assignment of both halves, as a node filled
    // without a span does: the import with the span of its pool keeps the accounts of that
    // span alone, and the prune with the span drops the others.
    let whole = Harness::new(&provider);
    let (placed, _) = fill(&giving, &whole, &json!({"pods": 2, "pod": 0, "copies": 1})).await;
    let of_pod: Vec<String> = apps
        .iter()
        .map(|app| app.user_id.clone())
        .filter(|user_id| pool.holds(user_id, 0))
        .collect();
    assert_eq!(placed, of_pod.len());
    let pruned = prune(&whole, &spanned(0, lower.clone())).await;
    let expected: Vec<String> = of_pod
        .iter()
        .filter(|user_id| !in_lower(user_id))
        .cloned()
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(pruned, expected);
    for user_id in &of_pod {
        assert_eq!(holds(&whole, user_id).await, in_lower(user_id), "{user_id}");
    }
    assert!(prune(&whole, &spanned(0, lower.clone())).await.is_empty());
    // An envelope of every account of the assignment, taken with the span of the upper
    // half: the receiving node keeps the accounts of that half.
    let receiving = Harness::new(&provider);
    let (to, from) = (attestation(&receiving).await, attestation(&giving).await);
    let without = json!({"pods": 2, "pod": 0, "copies": 1});
    let export = json!({"peer": to, "after": "", "limit": 1000, "subset": without});
    let (status, page) = giving.post("/v1/peer/export", export).await;
    assert_eq!(status, 200, "{page}");
    let import = |subset: Value| {
        receiving.post(
            "/v1/peer/import",
            json!({"peer": from, "envelope": page["envelope"], "subset": subset}),
        )
    };
    let (status, imported) = import(spanned(0, upper.clone())).await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(imported["imported"], expected.len());
    assert_eq!(imported["accounts"], json!(expected));

    // A span that is not two integers below 4,294,967,296, the first not above the last, is
    // refused by the three calls: no call computes another share from it, and nothing
    // changes.
    let grants = (
        giving.health().await["grants"].clone(),
        whole.health().await["grants"].clone(),
        receiving.health().await["grants"].clone(),
    );
    for span in [
        json!([5, 4]),
        json!([0]),
        json!([0, 1, 2]),
        json!([0, 4294967296u64]),
        json!([-1, 5]),
        json!("0-5"),
        json!({"first": 0, "last": 5}),
    ] {
        let refused = (400, "invalid_request");
        let subset = spanned(0, span);
        let export = json!({"peer": to, "after": "", "limit": 7, "subset": subset});
        assert_eq!(
            code(&giving.post("/v1/peer/export", export).await),
            refused,
            "{subset}"
        );
        assert_eq!(code(&import(subset.clone()).await), refused, "{subset}");
        let body = json!({"subset": subset, "after": "", "limit": 1000});
        assert_eq!(
            code(&whole.post("/v1/grants/prune", body).await),
            refused,
            "{subset}"
        );
    }
    assert_eq!(
        grants,
        (
            giving.health().await["grants"].clone(),
            whole.health().await["grants"].clone(),
            receiving.health().await["grants"].clone(),
        )
    );
}
