//! The plaintext of a record of kind `vault_secret` (protocol.md section 6): a value under a
//! name, where that value may go, and which side made the record.
//!
//! ```text
//! {"value":"...","name":"OPENAI_API_KEY","sites":["api.openai.com"],"slots":["header:authorization"],"source":"device","pad":"..."}
//! ```
//!
//! This module holds the form of everything but the value: the name, the sites, the slots, the
//! source and the padding. `sites` and `slots` together are the reach of the record: the hosts
//! and the places its value may go to. They are part of the plaintext, so whoever cannot
//! encrypt under the user key cannot change them. The value is a secret of the node: the type
//! that holds an opened plaintext is in `enclave/src/vault.rs`.
//!
//! A host of `sites` and a slot of `slots` are read by the one reader of each,
//! [`is_site_host`] and [`Slot::parse`] of [`crate::secret_use`]: the request of a use of the
//! value names a host and a slot, and it is read by the same two functions. So a host and a
//! slot a record lists are a host and a slot a request can name, and the other way round.
//!
//! The slots of a record say how its value is used, and a record is of one of two kinds of
//! use. A record with the one slot `field` is typed into a page: `release` hands its value to
//! the caller. A record with slots of a request is put into requests by a node of the forward
//! role: no call hands its value out. No record lists `field` next to a slot of a request, so
//! which of the two a value is does not depend on the call that asks for it.

use serde_json::Value;

use crate::encoding::to_json;
use crate::limits;
use crate::secret_use::{is_site_host, Slot};

/// The field `release` is asked for to hand out the value of a record of kind `vault_secret`.
pub const FIELD: &str = "value";

/// The value of `sites` that names every host.
const ANY: &str = "any";

/// The character the padding of a plaintext is made of.
const PAD: char = '.';

/// True for the name of a record of kind `vault_secret`: an ASCII capital letter followed by at
/// most 63 ASCII capital letters, digits and underscores (`[A-Z][A-Z0-9_]{0,63}`).
pub fn is_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_uppercase())
        && text.len() <= limits::VAULT_SECRET_NAME_CHARS
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Which side made a record of the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// The device of the account encrypted a value its user entered.
    Device,
    /// A node encrypted a value the operator domain gave it (`vault/store`): the operator
    /// domain knew the value.
    Operator,
}

impl Source {
    /// The name the plaintext writes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Device => "device",
            Source::Operator => "operator",
        }
    }

    /// Reads a source name. Any other string is `None`.
    pub fn parse(text: &str) -> Option<Source> {
        [Source::Device, Source::Operator]
            .into_iter()
            .find(|source| source.as_str() == text)
    }
}

/// True when `host` is `site` or a host below it: `host` ends with a `.` followed by `site`,
/// and is a host itself ([`is_site_host`]), so what stands in front of that `.` is one label
/// or more. `site` is a host of a record.
///
/// The names are compared as they stand. A node knows no list of public suffixes: a record
/// whose site is a name under which other parties register names (`co.kr`) admits the hosts of
/// all of them, and whoever writes a record chooses its sites.
pub fn is_at_or_below(host: &str, site: &str) -> bool {
    host == site
        || (is_site_host(host)
            && host
                .strip_suffix(site)
                .is_some_and(|front| front.ends_with('.')))
}

/// `sites` of a plaintext: the hosts the value may go to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sites {
    /// The string `"any"`: every host.
    Any,
    /// 1 to 8 hosts ([`is_site_host`]), no two of them equal.
    Hosts(Vec<String>),
}

impl Sites {
    /// Reads `sites`: the string `"any"`, or an array of 1 to 8 hosts ([`is_site_host`]) in
    /// which no host stands twice.
    pub fn from_value(value: &Value) -> Option<Sites> {
        match value {
            Value::String(text) if text == ANY => Some(Sites::Any),
            Value::Array(items) if (1..=limits::VAULT_SECRET_SITES).contains(&items.len()) => {
                let mut hosts: Vec<String> = Vec::with_capacity(items.len());
                for item in items {
                    let host = item.as_str().filter(|host| is_site_host(host))?;
                    if hosts.iter().any(|listed| listed == host) {
                        return None;
                    }
                    hosts.push(host.to_string());
                }
                Some(Sites::Hosts(hosts))
            }
            _ => None,
        }
    }

    /// `sites` as the plaintext writes it.
    pub fn to_value(&self) -> Value {
        match self {
            Sites::Any => Value::from(ANY),
            Sites::Hosts(hosts) => Value::from(hosts.clone()),
        }
    }
}

/// The reach of a record of kind `vault_secret`: `sites` and `slots` of its plaintext, the
/// hosts and the places its value may go to. A value of this type has the form of protocol.md
/// section 6: only [`Reach::from_values`] creates one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reach {
    sites: Sites,
    slots: Vec<Slot>,
}

impl Reach {
    /// Reads `sites` and `slots`. `slots` is an array of 1 to 4 slots ([`Slot::parse`]) in
    /// which no slot stands twice. It is the one slot `field`, or slots of a request: a list
    /// that holds `field` next to another slot is no list of slots. A record whose `sites` is
    /// `"any"` has the one slot `field`: a value that may go to every host is typed into a
    /// page and is put into no request.
    pub fn from_values(sites: &Value, slots: &Value) -> Option<Reach> {
        let sites = Sites::from_value(sites)?;
        let items = slots
            .as_array()
            .filter(|items| (1..=limits::VAULT_SECRET_SLOTS).contains(&items.len()))?;
        let mut slots = Vec::with_capacity(items.len());
        for item in items {
            let slot = Slot::parse(item.as_str()?)?;
            if slots.contains(&slot) {
                return None;
            }
            slots.push(slot);
        }
        let typed = slots.as_slice() == [Slot::Field];
        if slots.contains(&Slot::Field) && !typed {
            return None;
        }
        if sites == Sites::Any && !typed {
            return None;
        }
        Some(Reach { sites, slots })
    }

    /// `sites`.
    pub fn sites(&self) -> &Sites {
        &self.sites
    }

    /// `slots`, in the order of the plaintext.
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// True when the value is typed into pages: the record has the one slot `field`. The
    /// value of every other record is put into requests, and no call hands it out.
    pub fn is_typed(&self) -> bool {
        self.slots.as_slice() == [Slot::Field]
    }

    /// True when the value may be typed into an input field of a document of `host`: the
    /// record has the slot `field`, and `sites` is `"any"` or holds `host` or a host `host`
    /// lies below ([`is_at_or_below`]). The document a value is typed into is often one of a
    /// host below the site of the value: the payment frame of a shop is served from a host of
    /// its own under the name of the shop.
    pub fn admits_field(&self, host: &str) -> bool {
        self.is_typed()
            && match &self.sites {
                Sites::Any => true,
                Sites::Hosts(hosts) => hosts.iter().any(|site| is_at_or_below(host, site)),
            }
    }

    /// True when the value may be put into `slot` of a request to `host` (protocol.md 10.5):
    /// `sites` is a list of hosts that holds the host, and `slots` holds the slot. The host is
    /// compared as it stands: a site of a record names itself and no host below it, because a
    /// request goes to one host, and a value for `api.example.com` is no value for
    /// `files.example.com`. A slot is the slot of a record when the two are the same string:
    /// the name of a query, form or JSON slot is compared as it stands, with the case of its
    /// letters.
    ///
    /// A record whose `sites` is `"any"` admits no request: its value is typed into a page and
    /// is put into no request. `field` is no slot of a request.
    pub fn admits_request(&self, host: &str, slot: &Slot) -> bool {
        match &self.sites {
            Sites::Any => false,
            Sites::Hosts(hosts) => {
                *slot != Slot::Field
                    && hosts.iter().any(|listed| listed == host)
                    && self.slots.contains(slot)
            }
        }
    }

    /// `slots` as the plaintext writes them.
    pub fn slot_texts(&self) -> Vec<String> {
        self.slots.iter().map(ToString::to_string).collect()
    }
}

/// The length the device of an account pads a plaintext of `length` bytes to: the shortest
/// length of [`limits::VAULT_SECRET_PADDED_BYTES`] that is not below it. `None` for a
/// plaintext above the longest of them.
pub fn padded_length(length: usize) -> Option<usize> {
    limits::VAULT_SECRET_PADDED_BYTES
        .into_iter()
        .find(|padded| *padded >= length)
}

/// The plaintext of a record of kind `vault_secret` as the device of an account writes it
/// (protocol.md section 6): `value`, `name`, `sites`, `slots`, the source `device` and `pad`,
/// in this order. `pad` is a string of `.` characters that brings the plaintext to the
/// shortest of the lengths of [`limits::VAULT_SECRET_PADDED_BYTES`] it fits, so the length of
/// a record tells the operator domain, which stores the record, one of seven steps and not
/// the length of the value. `None` for a name that is no name ([`is_name`]), for a value that
/// is empty or holds U+0000, and for a plaintext above the longest step.
///
/// A node does not call this function: it writes no record that says a device made it. The
/// generator of the test vectors and the tests use it in the place of the device.
pub fn device_plaintext(value: &str, name: &str, reach: &Reach) -> Option<Vec<u8>> {
    if !is_name(name) || value.is_empty() || value.contains('\0') {
        return None;
    }
    let written = |pad: usize| {
        to_json(&serde_json::json!({
            "value": value,
            "name": name,
            "sites": reach.sites.to_value(),
            "slots": reach.slot_texts(),
            "source": Source::Device.as_str(),
            "pad": PAD.to_string().repeat(pad),
        }))
    };
    let unpadded = written(0).len();
    let padded = padded_length(unpadded)?;
    Some(written(padded.saturating_sub(unpadded)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_name_is_a_capital_letter_and_up_to_63_capitals_digits_and_underscores() {
        for name in [
            "A",
            "OPENAI_API_KEY",
            "K2",
            "X_",
            &format!("A{}", "9".repeat(63)),
        ] {
            assert!(is_name(name), "{name}");
        }
        for name in [
            "",
            "a",
            "openai_api_key",
            "1KEY",
            "_KEY",
            "API-KEY",
            "API KEY",
            "KEY\n",
            "ÅPI",
            &format!("A{}", "9".repeat(64)),
        ] {
            assert!(!is_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_source_is_device_or_operator() {
        for (source, name) in [(Source::Device, "device"), (Source::Operator, "operator")] {
            assert_eq!(source.as_str(), name);
            assert_eq!(Source::parse(name), Some(source));
        }
        for other in ["", "Device", "node", "enclave", "operator "] {
            assert_eq!(Source::parse(other), None, "{other:?}");
        }
    }

    #[test]
    fn sites_is_the_string_any_or_one_to_eight_distinct_hosts() {
        assert_eq!(Sites::from_value(&json!("any")), Some(Sites::Any));
        let hosts = json!(["api.openai.com", "shop.example"]);
        let sites = Sites::from_value(&hosts).unwrap();
        assert_eq!(
            sites,
            Sites::Hosts(vec![
                "api.openai.com".to_string(),
                "shop.example".to_string()
            ])
        );
        assert_eq!(sites.to_value(), hosts);
        assert_eq!(Sites::Any.to_value(), json!("any"));
        let eight: Vec<String> = (0..8).map(|index| format!("h{index}.example")).collect();
        assert!(Sites::from_value(&json!(eight)).is_some());
        // A host and a host below it are two hosts.
        assert!(Sites::from_value(&json!(["a.example", "b.a.example"])).is_some());

        let nine: Vec<String> = (0..9).map(|index| format!("h{index}.example")).collect();
        for other in [
            json!([]),
            json!(nine),
            // No host stands twice.
            json!(["a.example", "a.example"]),
            json!(["a.example", "b.example", "a.example"]),
            json!("all"),
            json!("ANY"),
            json!(["any"]),
            json!(["Shop.example"]),
            json!(["shop.example", 1]),
            json!(["shop.example", null]),
            json!({"host": "shop.example"}),
            json!(null),
            json!(true),
        ] {
            assert_eq!(Sites::from_value(&other), None, "{other}");
        }
    }

    #[test]
    fn a_host_is_at_a_site_or_below_it() {
        for (host, site) in [
            ("shop.example", "shop.example"),
            ("www.shop.example", "shop.example"),
            ("pay.eu.shop.example", "shop.example"),
            ("rocketpay.coupang.com", "coupang.com"),
            ("a.b", "a.b"),
            ("x.a.b", "a.b"),
        ] {
            assert!(is_at_or_below(host, site), "{host} {site}");
        }
        for (host, site) in [
            // Another name, a name above the site, and a name that only ends like it.
            ("other.example", "shop.example"),
            ("example", "shop.example"),
            ("myshop.example", "shop.example"),
            ("notshop.example", "shop.example"),
            ("shop.example.evil.example", "shop.example"),
            ("shop.example", "www.shop.example"),
            // What stands in front of the site is no label.
            (".shop.example", "shop.example"),
            ("..shop.example", "shop.example"),
            ("a..shop.example", "shop.example"),
            ("-.shop.example", "shop.example"),
            ("a b.shop.example", "shop.example"),
            ("WWW.shop.example", "shop.example"),
            ("www.shop.example.", "shop.example"),
            ("", "shop.example"),
        ] {
            assert!(!is_at_or_below(host, site), "{host:?} {site}");
        }
        // A host of 253 bytes below a site is a host, and one byte more is none.
        let label = "l".repeat(63);
        let longest = format!("{label}.{label}.{label}.{}.shop.example", "l".repeat(48));
        assert_eq!(longest.len(), 253);
        assert!(is_at_or_below(&longest, "shop.example"));
        assert!(!is_at_or_below(&format!("l{longest}"), "shop.example"));
    }

    #[test]
    fn a_reach_has_one_to_four_distinct_slots() {
        let sites = json!(["api.openai.com"]);
        let reach =
            Reach::from_values(&sites, &json!(["header:authorization", "query:key"])).unwrap();
        assert_eq!(
            reach.sites(),
            &Sites::Hosts(vec!["api.openai.com".to_string()])
        );
        assert_eq!(
            reach.slots(),
            [
                Slot::Header("authorization".to_string()),
                Slot::Query("key".to_string())
            ]
        );
        assert!(!reach.is_typed());
        let four = json!(["path", "query:key", "json:key", "form:key"]);
        assert_eq!(Reach::from_values(&sites, &four).unwrap().slots().len(), 4);

        for slots in [
            // No slot at all: the value would go nowhere.
            json!([]),
            json!(["header:a", "path", "query:key", "json:key", "form:key"]),
            json!(["field", "field"]),
            json!(["query:key", "query:key"]),
            json!(["header:Authorization"]),
            json!(["path", 1]),
            json!("field"),
            json!({"field": true}),
            json!(null),
        ] {
            assert_eq!(Reach::from_values(&sites, &slots), None, "{slots}");
        }
        // Two slots of the same place with other names are two slots.
        assert!(Reach::from_values(&sites, &json!(["query:key", "query:token"])).is_some());
        // `sites` of another form.
        assert_eq!(Reach::from_values(&json!([]), &json!(["field"])), None);
    }

    #[test]
    fn the_slots_of_a_reach_are_the_slot_field_or_slots_of_a_request() {
        let sites = json!(["shop.example"]);
        let typed = Reach::from_values(&sites, &json!(["field"])).unwrap();
        assert!(typed.is_typed());
        assert_eq!(typed.slots(), [Slot::Field]);
        // `field` next to a slot of a request, in either order and at any length.
        for slots in [
            json!(["field", "header:authorization"]),
            json!(["header:authorization", "field"]),
            json!(["path", "field", "query:key"]),
            json!(["field", "basic:password"]),
        ] {
            assert_eq!(Reach::from_values(&sites, &slots), None, "{slots}");
        }
        for slots in [
            json!(["header:authorization"]),
            json!(["basic:user"]),
            json!(["path", "query:key", "form:key", "json:a.b"]),
        ] {
            let reach = Reach::from_values(&sites, &slots).unwrap();
            assert!(!reach.is_typed(), "{slots}");
        }
    }

    #[test]
    fn a_reach_lists_the_hosts_and_the_slots_a_request_can_name() {
        // A slot and a host of a record are read by the reader of a request: what that reader
        // refuses is no part of a reach.
        let sites = json!(["api.openai.com"]);
        for slots in [
            // A header a node of the forward role drops or refuses.
            json!(["header:host"]),
            json!(["header:content-length"]),
            json!(["path", "header:x-forwarded-host"]),
            // A JSON slot with an empty key.
            json!(["json:a..b"]),
            json!(["json:.token"]),
        ] {
            assert_eq!(Reach::from_values(&sites, &slots), None, "{slots}");
        }
        let nested = Reach::from_values(&sites, &json!(["json:auth.token"])).unwrap();
        assert_eq!(
            nested.slots(),
            [Slot::Json(vec!["auth".to_string(), "token".to_string()])]
        );
        let field = json!(["field"]);
        for sites in [
            json!(["-shop.example"]),
            json!(["shop-.example"]),
            json!(["shop.example", "pay.-example"]),
            json!(["shop.1example"]),
        ] {
            assert_eq!(Reach::from_values(&sites, &field), None, "{sites}");
        }
        assert!(Reach::from_values(&json!(["my-shop.example"]), &field).is_some());
    }

    #[test]
    fn a_reach_of_every_host_has_the_one_slot_field() {
        let any = json!("any");
        let reach = Reach::from_values(&any, &json!(["field"])).unwrap();
        assert_eq!(reach.sites(), &Sites::Any);
        assert_eq!(reach.slots(), [Slot::Field]);
        for slots in [
            json!([]),
            json!(["header:authorization"]),
            json!(["field", "header:authorization"]),
            json!(["path"]),
        ] {
            assert_eq!(Reach::from_values(&any, &slots), None, "{slots}");
        }
    }

    #[test]
    fn a_field_is_admitted_with_the_slot_field_on_a_site_or_on_a_host_below_it() {
        let reach = |sites: Value, slots: Value| Reach::from_values(&sites, &slots).unwrap();
        let listed = reach(json!(["shop.example", "pay.example"]), json!(["field"]));
        for host in [
            "shop.example",
            "pay.example",
            "www.shop.example",
            "checkout.eu.shop.example",
            "frame.pay.example",
        ] {
            assert!(listed.admits_field(host), "{host}");
        }
        for host in [
            "other.example",
            "example",
            "myshop.example",
            "shop.example.evil.example",
            ".shop.example",
            "",
        ] {
            assert!(!listed.admits_field(host), "{host:?}");
        }
        // A site that is a host below another name admits neither that name nor its other
        // hosts.
        let below = reach(json!(["pay.shop.example"]), json!(["field"]));
        assert!(below.admits_field("pay.shop.example"));
        assert!(below.admits_field("frame.pay.shop.example"));
        assert!(!below.admits_field("shop.example"));
        assert!(!below.admits_field("www.shop.example"));
        let anywhere = reach(json!("any"), json!(["field"]));
        assert!(anywhere.admits_field("other.example"));
        // Without the slot `field` no host is admitted, also not a host of the sites.
        let request_only = reach(json!(["api.openai.com"]), json!(["header:authorization"]));
        assert!(!request_only.admits_field("api.openai.com"));
        assert!(!request_only.admits_field("eu.api.openai.com"));
    }

    #[test]
    fn a_request_is_admitted_for_a_listed_slot_on_a_host_of_the_sites() {
        let reach = |sites: Value, slots: Value| Reach::from_values(&sites, &slots).unwrap();
        let slot = |text: &str| Slot::parse(text).unwrap();
        let listed = reach(
            json!(["api.openai.com", "api.example.com"]),
            json!(["header:authorization", "query:key", "json:auth.token"]),
        );
        for host in ["api.openai.com", "api.example.com"] {
            for text in ["header:authorization", "query:key", "json:auth.token"] {
                assert!(listed.admits_request(host, &slot(text)), "{host} {text}");
            }
        }
        // A host that is not listed: another name, a name below a site and a name above it.
        // A request goes to the host of a record and to no host below it.
        for host in ["other.example", "files.api.openai.com", "openai.com", ""] {
            assert!(
                !listed.admits_request(host, &slot("header:authorization")),
                "{host:?}"
            );
        }
        // A slot that is not listed: another place, another name of the same place, the same
        // name in another case, a key path that is longer or shorter.
        for text in [
            "path",
            "header:x-api-key",
            "query:authorization",
            "query:Key",
            "form:key",
            "json:auth",
            "json:auth.token.value",
        ] {
            assert!(
                !listed.admits_request("api.openai.com", &slot(text)),
                "{text}"
            );
        }
        // `field` is no place of a request, also for a record that lists it.
        assert!(!listed.admits_request("api.openai.com", &Slot::Field));
        let typed = reach(json!(["shop.example"]), json!(["field"]));
        assert!(!typed.admits_request("shop.example", &Slot::Field));
        assert!(!typed.admits_request("shop.example", &slot("header:authorization")));
        // A record of every host admits no request.
        let anywhere = reach(json!("any"), json!(["field"]));
        assert!(!anywhere.admits_request("api.openai.com", &Slot::Field));
        assert!(!anywhere.admits_request("api.openai.com", &slot("header:authorization")));
    }

    #[test]
    fn the_device_pads_a_plaintext_to_one_of_seven_lengths() {
        let reach =
            Reach::from_values(&json!(["api.openai.com"]), &json!(["header:authorization"]))
                .unwrap();
        let plaintext = device_plaintext("sk-example", "OPENAI_API_KEY", &reach).unwrap();
        assert_eq!(plaintext.len(), 256);
        let text = String::from_utf8(plaintext).unwrap();
        // The six members in their order.
        assert!(text.starts_with(concat!(
            "{\"value\":\"sk-example\",\"name\":\"OPENAI_API_KEY\",",
            "\"sites\":[\"api.openai.com\"],\"slots\":[\"header:authorization\"],",
            "\"source\":\"device\",\"pad\":\"..."
        )));
        let parsed: Value = serde_json::from_str(&text).unwrap();
        let pad = parsed["pad"].as_str().unwrap();
        assert!(!pad.is_empty() && pad.chars().all(|character| character == '.'));

        // Every length of a value gives one of the seven lengths, the shortest that fits.
        let unpadded = |value: &str| {
            json!({
                "value": value, "name": "K", "sites": ["a.example"], "slots": ["field"],
                "source": "device", "pad": "",
            })
            .to_string()
            .len()
        };
        let typed = Reach::from_values(&json!(["a.example"]), &json!(["field"])).unwrap();
        let frame = unpadded("");
        for (length, padded) in [
            (1, 256),
            (256 - frame, 256),
            (256 - frame + 1, 512),
            (512 - frame, 512),
            (1_024 - frame + 1, 2_048),
            (8_192 - frame, 8_192),
            (8_192 - frame + 1, 12_272),
            (12_272 - frame, 12_272),
        ] {
            let value = "v".repeat(length);
            let plaintext = device_plaintext(&value, "K", &typed).unwrap();
            assert_eq!(plaintext.len(), padded, "{length}");
            let parsed: Value = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(parsed["value"].as_str().unwrap().len(), length);
        }
        // A plaintext at a length has the empty padding, and one above the longest is none.
        let exact = device_plaintext(&"v".repeat(512 - frame), "K", &typed).unwrap();
        let parsed: Value = serde_json::from_slice(&exact).unwrap();
        assert_eq!(parsed["pad"], "");
        assert_eq!(
            device_plaintext(&"v".repeat(12_272 - frame + 1), "K", &typed),
            None
        );
        // The length of a value is counted as its JSON string: a quote is two bytes.
        let quoted = "\"".repeat((256 - frame) / 2 + 1);
        assert_eq!(device_plaintext(&quoted, "K", &typed).unwrap().len(), 512);
        // No name, no value.
        assert_eq!(device_plaintext("v", "k", &typed), None);
        assert_eq!(device_plaintext("", "K", &typed), None);
        assert_eq!(device_plaintext("a\0b", "K", &typed), None);
        assert_eq!(padded_length(0), Some(256));
        assert_eq!(padded_length(12_272), Some(12_272));
        assert_eq!(padded_length(12_273), None);
    }
}
