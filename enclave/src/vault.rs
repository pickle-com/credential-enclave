//! The vault kinds of a record (protocol.md section 6): values an account entered on its
//! device and encrypted there, and values the operator domain gave to `vault/store`, which a
//! node encrypted. The node opens them for `release` and for `vault/handoff`.
//!
//! This module owns the types that hold a vault plaintext. An opened value leaves it in two
//! ways, and where the operator domain can read it in one of them:
//!
//! - as a [`HandedOut`], created by [`Selected::hand_out`] (sink K4 of the egress policy,
//!   `docs/egress-policy.md`): the value in the response of `release`, as it is or under the
//!   seal of a key the caller of `release` named. The seed of a `vault_totp` record has not
//!   this way out: the only value this module makes of it is the 6-digit code. The value of a
//!   record of kind `vault_secret` has it when the record has the slot `field`;
//! - inside the envelope of a secret use, made by [`ForRequest::hand_off`] (a caller of sink
//!   K8): the value of a record of kind `vault_secret`, sealed to the sealing key of a
//!   verified node of the forward role together with the one request it is for. The record
//!   lists the slot of that request and the host of that request. The response of
//!   `vault/handoff` carries the envelope, a ciphertext, and no value.
//!
//! So the value of a record of kind `vault_secret` without the slot `field` leaves this module
//! inside that seal and in no other way. A value that `vault/store` took leaves as the
//! ciphertext of its record ([`OperatorValue::seal`], a caller of sink K1).
//!
//! The value of an opened record is read in these two functions, each of which runs after the
//! log store confirmed the entry of its call. Before that entry exists, a call is judged by
//! what does not depend on the content of a value: the kind of the record, the field or the
//! request that is asked for, and the name and the reach a record of kind `vault_secret`
//! states. So a caller learns nothing about a value from a call that leaves no entry.

use std::fmt;

use credential_enclave_protocol::encoding::to_json;
use credential_enclave_protocol::keys::NodeKeys;
use credential_enclave_protocol::record::{self, Kind, Record};
use credential_enclave_protocol::released::{seal_released, SealTo, SealedValue};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::{fits_header, BoundRequest, SecretUseEnvelope, Slot};
use credential_enclave_protocol::totp::totp;
use credential_enclave_protocol::vault_secret::{self, Reach, Source};
use credential_enclave_protocol::{limits, ProtocolError};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::api::responses::LogRef;
use crate::attest::ForwardNode;
use crate::state::{open_for, GrantView};

/// The `provider` of a vault record.
pub const PROVIDER: &str = "vault";

/// The opened plaintext of a vault record, before a field is taken from it. Only
/// [`open_record`] creates one.
pub enum VaultRecord {
    /// A record of kind `vault_password`, `vault_totp` or `vault_card`: the kind names the
    /// fields of the plaintext.
    Fixed {
        kind: Kind,
        plaintext: Secret<Vec<u8>>,
    },
    /// A record of kind `vault_secret`.
    Named(NamedValue),
}

/// Step 5 of the common front for `release` and for `vault/handoff`: opens a record and takes
/// it as a vault record. A record of kind `oauth`, `oauth_imported` or `app_password` is
/// `not_allowed`: no call hands out the plaintext of a token or of an application password,
/// and none seals one to another node. A record of kind `vault_secret` whose plaintext does
/// not state a name and a reach is `record_invalid` ([`NamedValue::read`]).
pub fn open_record(
    grant: &GrantView,
    user_id: &str,
    record: &Record,
) -> Result<VaultRecord, ProtocolError> {
    match open_for(grant, user_id, record)? {
        (kind @ (Kind::VaultPassword | Kind::VaultTotp | Kind::VaultCard), plaintext) => {
            Ok(VaultRecord::Fixed { kind, plaintext })
        }
        (Kind::VaultSecret, plaintext) => NamedValue::read(plaintext).map(VaultRecord::Named),
        (Kind::Oauth | Kind::OauthImported | Kind::AppPassword, _) => {
            Err(ProtocolError::NotAllowed)
        }
    }
}

/// The opened plaintext of a record of kind `vault_secret` (protocol.md section 6): the name
/// and the reach it states, and the bytes that hold its value.
///
/// The name and the reach are read when the record is opened. The value is not: it is read
/// where it is handed out ([`Selected::hand_out`]) or sealed for a request
/// ([`ForRequest::hand_off`]).
pub struct NamedValue {
    name: String,
    reach: Reach,
    plaintext: Secret<Vec<u8>>,
}

/// What a plaintext of kind `vault_secret` states next to its value. Every other member of
/// the object, `value` and `pad` among them, is passed over without being decoded.
#[derive(Deserialize)]
struct Stated {
    name: String,
    sites: Value,
    slots: Value,
    source: String,
}

impl NamedValue {
    /// Reads `name`, `sites`, `slots` and `source` of an opened plaintext. A plaintext that
    /// is not the text of a JSON object, that lacks one of the four or holds one of them
    /// twice, or in which one of them has not the form of protocol.md section 6, is
    /// `record_invalid`.
    ///
    /// The reader passes over `value` without decoding it: it follows the JSON text to the end
    /// of that member and reads neither its type nor the characters of a string. So this
    /// judgement falls the same way whatever JSON value the member holds, which is every
    /// value a JSON serializer writes. A plaintext in which that member is no JSON text (a
    /// control character inside a string, an escape JSON does not have) is no JSON text as a
    /// whole and does not open.
    fn read(plaintext: Secret<Vec<u8>>) -> Result<NamedValue, ProtocolError> {
        let bytes = plaintext.expose_secret();
        // A plaintext is an object: the reader would take an array of four elements for the
        // four members as well.
        if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
            return Err(ProtocolError::RecordInvalid);
        }
        let stated: Stated =
            serde_json::from_slice(bytes).map_err(|_| ProtocolError::RecordInvalid)?;
        let reach = Reach::from_values(&stated.sites, &stated.slots)
            .filter(|_| vault_secret::is_name(&stated.name))
            .filter(|_| Source::parse(&stated.source).is_some())
            .ok_or(ProtocolError::RecordInvalid)?;
        Ok(NamedValue {
            name: stated.name,
            reach,
            plaintext,
        })
    }
}

/// A record `release` is about to hand a value out of: the member of the plaintext that holds
/// the value is chosen, and the plaintext is not read for it yet.
pub struct Selected {
    kind: Kind,
    /// The member of the plaintext that holds the value.
    member: &'static str,
    is_totp: bool,
    /// The name of a record of kind `vault_secret`.
    name: Option<String>,
    plaintext: Secret<Vec<u8>>,
}

impl VaultRecord {
    /// Chooses the value of `field` (enclave.md 5.9). The pair of kind and field decides:
    ///
    /// | kind | field | value |
    /// | --- | --- | --- |
    /// | `vault_password` | `password` | the `value` of the plaintext |
    /// | `vault_totp` | `totp` | the 6-digit code of the seed, the `value` of the plaintext |
    /// | `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext |
    /// | `vault_secret` | `value` | the `value` of the plaintext |
    ///
    /// Any other pair is `not_allowed`. So is a record of kind `vault_secret` whose reach
    /// does not admit a field of a document of `host` (its `slots` are not the slot `field`,
    /// or its `sites` hold neither the host nor a host it lies below): `host` is the host of
    /// the origin the value is asked for.
    ///
    /// This function reads no plaintext. Whether the plaintext holds the value is judged by
    /// [`Selected::hand_out`], after the entry of the call.
    pub fn select(self, field: &str, host: &str) -> Result<Selected, ProtocolError> {
        match self {
            VaultRecord::Fixed { kind, plaintext } => {
                let (member, is_totp) = match (kind, field) {
                    (Kind::VaultPassword, "password") => ("value", false),
                    (Kind::VaultTotp, "totp") => ("value", true),
                    (Kind::VaultCard, "card_number") => ("number", false),
                    (Kind::VaultCard, "card_cvc") => ("cvc", false),
                    _ => return Err(ProtocolError::NotAllowed),
                };
                Ok(Selected {
                    kind,
                    member,
                    is_totp,
                    name: None,
                    plaintext,
                })
            }
            VaultRecord::Named(named) => {
                if field != vault_secret::FIELD || !named.reach.admits_field(host) {
                    return Err(ProtocolError::NotAllowed);
                }
                Ok(Selected {
                    kind: Kind::VaultSecret,
                    member: "value",
                    is_totp: false,
                    name: Some(named.name),
                    plaintext: named.plaintext,
                })
            }
        }
    }

    /// Chooses the value for one request to its site (enclave.md 5.9c): the value of a record
    /// of kind `vault_secret` whose reach admits the request. That is a record whose `sites`
    /// are a list of hosts that holds the host of `request` and whose `slots` hold its slot
    /// (`Reach::admits_request`). Every other record is `not_allowed`: a record of kind
    /// `vault_password`, `vault_totp` or `vault_card`, a record that lists neither that host
    /// nor that slot, and a record whose `sites` is `"any"`.
    ///
    /// This function reads no plaintext. Whether the plaintext holds a value a request can
    /// carry is judged by [`ForRequest::hand_off`], after the entry of the call.
    pub fn select_for_request(self, request: &BoundRequest) -> Result<ForRequest, ProtocolError> {
        match self {
            VaultRecord::Named(named)
                if named.reach.admits_request(request.host(), request.slot()) =>
            {
                Ok(ForRequest {
                    name: named.name,
                    plaintext: named.plaintext,
                })
            }
            _ => Err(ProtocolError::NotAllowed),
        }
    }
}

/// The string in the member `member` of a vault plaintext, as a secret. `record_invalid` for
/// a plaintext that is no JSON object, or that holds no string there.
fn member_of(plaintext: &Secret<Vec<u8>>, member: &str) -> Result<Secret<String>, ProtocolError> {
    let parsed = Secret::new(
        serde_json::from_slice::<Value>(plaintext.expose_secret())
            .map_err(|_| ProtocolError::RecordInvalid)?,
    );
    let stored = parsed
        .expose_secret()
        .get(member)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::RecordInvalid)?;
    Ok(Secret::new(stored.to_string()))
}

/// The key a call of `release` named for the value (`seal_to`), with the values of the call
/// the seal binds: the account, the record, the field and the origin, and the key material of
/// the seal.
pub struct Sealing<'a> {
    pub to: &'a SealTo,
    pub user_id: &'a str,
    pub record_id: &'a str,
    pub field: &'a str,
    pub origin: &'a str,
    /// 32 fresh random bytes: the input keying material of the ephemeral key pair.
    pub hpke_seed: &'a Secret<[u8; 32]>,
}

impl Selected {
    /// The kind of the record the value comes from.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// True when the value is a TOTP code. The log entry of such a release is `totp_issued`.
    pub fn is_totp(&self) -> bool {
        self.is_totp
    }

    /// The name of the record the value comes from, when the record is of kind
    /// `vault_secret`. The event of the release carries it.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Reads the value and hands it out. This is sink K4 of the egress policy: the one place
    /// where a vault value becomes part of a response. `log` is the `log` object of this
    /// release, which `log_store::commit` returned: the entry that names the release is on the
    /// chain of the account, and the log store confirmed it, before the plaintext is read for
    /// the value. `now_ms` is the node time the code of a TOTP seed is computed for.
    ///
    /// With `sealing`, the value leaves under the seal of the key the caller named
    /// (`seal_released` of the protocol crate) and not as it is. The caller chose that key, so
    /// a sealed value is a value the operator domain reads, as the value in the clear is: the
    /// seal keeps it from whoever carries the response to the holder of the key.
    ///
    /// A plaintext that is no JSON object or holds no string in the chosen member, and a seed
    /// that is not base32, are `record_invalid`: nothing leaves, and the entry stays on the
    /// chain as the entry of a release that did not take place.
    pub fn hand_out(
        self,
        _log: &LogRef,
        now_ms: u64,
        sealing: Option<Sealing<'_>>,
    ) -> Result<HandedOut, ProtocolError> {
        let stored = member_of(&self.plaintext, self.member)?;
        let value = match self.is_totp {
            true => Secret::new(totp(stored.expose_secret(), now_ms)?),
            false => stored,
        };
        match sealing {
            None => Ok(HandedOut::Value(ReleasedValue(
                value.expose_secret().clone(),
            ))),
            Some(sealing) => seal_released(
                sealing.to,
                sealing.user_id,
                sealing.record_id,
                sealing.field,
                sealing.origin,
                &value,
                sealing.hpke_seed,
            )
            .map(HandedOut::Sealed),
        }
    }
}

/// What `release` hands out (class V of the egress policy): the value under the key `value`,
/// or the value under the seal of the key the caller named under the key `sealed`. Only
/// [`Selected::hand_out`] creates one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandedOut {
    Value(ReleasedValue),
    Sealed(SealedValue),
}

/// A vault value in the response of `release` (class V of the egress policy). Only
/// [`Selected::hand_out`] creates one. The copy is overwritten with zeros when the response was
/// written.
pub struct ReleasedValue(String);

impl Serialize for ReleasedValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for ReleasedValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ReleasedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleasedValue(..)")
    }
}

/// A record `vault/handoff` is about to seal the value of for one request: the reach of the
/// record admits the request, and the plaintext is not read for the value yet.
pub struct ForRequest {
    /// The name the record states.
    name: String,
    plaintext: Secret<Vec<u8>>,
}

impl ForRequest {
    /// The name of the record the value comes from. The event of the use carries it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads the value and hands it, with the one request it is for, to a node of the forward
    /// role: the envelope of protocol.md 10.5, signed with the keys of this node and sealed to
    /// the sealing key of `to` (a caller of sink K8 of the egress policy). This is the one
    /// place where a vault value becomes part of an envelope. The value is in the clear
    /// nowhere in what this function returns.
    ///
    /// `log` is the `log` object of this use, which `log_store::commit` returned: the entry
    /// that names the request, the record, the slot and the node `to` is on the chain of the
    /// account, and the log store confirmed it, before the plaintext is read for the value.
    /// `to` is a node [`crate::attest::ForwardNodes::verify`] accepted. `time_ms` is the node
    /// time the envelope is made at: it ends 30 seconds later.
    ///
    /// What depends on the value is judged here, after the entry. A plaintext that is no JSON
    /// object or holds no string `value`, a value of fewer than 8 bytes or of more than 12,000
    /// (of a shorter one no reflection could be found in a response), for a slot
    /// `header:<name>`, `basic:user` and `basic:password` a value with a control character
    /// (it would end the line of its header, and the credentials of HTTP Basic hold none),
    /// and for the slot `basic:user` a value with a colon (the first colon of the credentials
    /// ends the user-id) are `record_invalid`: no envelope is made, and the entry stays on
    /// the chain as the entry of a use that did not take place.
    #[allow(clippy::too_many_arguments)]
    pub fn hand_off(
        self,
        _log: &LogRef,
        to: &ForwardNode,
        keys: &NodeKeys,
        time_ms: u64,
        nonce: &[u8; 16],
        user_id: &str,
        record_id: &str,
        request: &BoundRequest,
        hpke_seed: &Secret<[u8; 32]>,
    ) -> Result<SecretUseEnvelope, ProtocolError> {
        let value = member_of(&self.plaintext, "value")?;
        let stored = value.expose_secret().as_str();
        let sized = (limits::SECRET_USE_VALUE_BYTES_MIN..=limits::SECRET_USE_VALUE_BYTES_MAX)
            .contains(&stored.len());
        let fits = match request.slot() {
            Slot::Header(_) => fits_header(stored),
            // The slot names the half of the credentials the value stands for: neither half
            // holds a control character, and a user-id holds no colon.
            Slot::Basic(part) => part.admits(stored),
            _ => true,
        };
        if !sized || !fits {
            return Err(ProtocolError::RecordInvalid);
        }
        to.seal_secret_use(
            keys, time_ms, nonce, user_id, record_id, &value, request, hpke_seed,
        )
    }
}

/// A value the caller of `vault/store` gave, as the plaintext of the record it becomes
/// (protocol.md section 6). Only [`OperatorValue::named`] and [`OperatorValue::password`]
/// create one.
///
/// The operator domain knew this value before the node encrypted it, and the plaintext says
/// so: its `source` is `operator`. This type writes no other source, and no other function
/// makes a record of a value a caller gave: a node creates no record that says a device made
/// it.
pub struct OperatorValue {
    kind: Kind,
    plaintext: Secret<Vec<u8>>,
}

impl OperatorValue {
    /// The plaintext of a record of kind `vault_secret`: `value`, `name`, `sites`, `slots`
    /// and `source`, in this order. `None` for a plaintext of more than 12,272 bytes
    /// (`too_large` of `vault/store`): the value is counted as its JSON string, with the
    /// escapes of its characters.
    pub fn named(name: &str, reach: &Reach, value: &Secret<String>) -> Option<OperatorValue> {
        let object = Secret::new(json!({
            "value": value.expose_secret(),
            "name": name,
            "sites": reach.sites().to_value(),
            "slots": reach.slot_texts(),
            "source": Source::Operator.as_str(),
        }));
        OperatorValue::of(Kind::VaultSecret, &object)
    }

    /// The plaintext of a record of kind `vault_password`: `value` and `source`, in this
    /// order. A record of that kind the device of an account made has the one member `value`,
    /// so a password that came from the operator domain is told apart from one the user
    /// entered. `None` for a plaintext of more than 12,272 bytes.
    pub fn password(value: &Secret<String>) -> Option<OperatorValue> {
        let object = Secret::new(json!({
            "value": value.expose_secret(),
            "source": Source::Operator.as_str(),
        }));
        OperatorValue::of(Kind::VaultPassword, &object)
    }

    fn of(kind: Kind, object: &Secret<Value>) -> Option<OperatorValue> {
        let plaintext = Secret::new(to_json(object.expose_secret()));
        (plaintext.expose_secret().len() <= limits::VAULT_SECRET_PLAINTEXT_BYTES)
            .then_some(OperatorValue { kind, plaintext })
    }

    /// Creates the record of this value under the user key of the grant: its kind, provider
    /// `vault`. This is the one place where a value of `vault/store` leaves this module (sink
    /// K1). `id` and `nonce` are node randomness: the caller of `vault/store` chooses neither,
    /// so the node encrypts no value of a caller under the record key of another record.
    pub fn seal(
        &self,
        grant: &GrantView,
        id: &[u8; 16],
        nonce: &[u8; 12],
        user_id: &str,
    ) -> Record {
        record::seal(
            &grant.user_key,
            id,
            nonce,
            user_id,
            &grant.key_id,
            grant.custody,
            self.kind,
            PROVIDER,
            &self.plaintext,
        )
    }
}

/// The events of the vault calls (protocol.md 7.2). Each is an event of a type the calls of
/// the connections create as well (`crate::state::events`), with keys behind the keys of that
/// event that say what the act is.
///
/// The acts have no event type of their own. A reader of the log that meets an event type it
/// does not know cannot tell the entry from a damaged one, so a release records a new act
/// under a type the readers in use know, and says what is new in keys those readers pass over.
///
/// An event holds no secret: its values are identifiers, the request object of a use (which
/// holds the placeholder where the value goes), a name, a host and the context string of the
/// caller. No function here takes a secret type.
pub mod events {
    use credential_enclave_protocol::record::Kind;
    use credential_enclave_protocol::secret_use::BoundRequest;
    use serde_json::{json, Value};

    use super::PROVIDER;
    use crate::state::events as base;

    /// The event of `vault/store` for a record of kind `vault_secret`: a node made the record
    /// `record_id` of a value its caller gave and hands that record out. It is a
    /// `connection_created` event, as `oauth/complete` creates one when it hands out the
    /// record of a new connection: the first five keys are those of that event, with the
    /// provider `vault` and the empty scope, and `kind`, `name` (the name the call gave the
    /// value) and `context` follow them.
    pub fn secret_stored(record_id: &str, name: &str, context: &str) -> Value {
        let mut event = base::connection_created(record_id, PROVIDER, "");
        event["kind"] = json!(Kind::VaultSecret.as_str());
        event["name"] = json!(name);
        event["context"] = json!(context);
        event
    }

    /// The event of `vault/store` for a record of kind `vault_password`: the keys of
    /// [`secret_stored`] with `site` in the place of `name`. `site` is the host the caller
    /// stated for the login the password belongs to: the node writes the value it received,
    /// as it writes the `origin` of a release.
    pub fn password_stored(record_id: &str, site: &str, context: &str) -> Value {
        let mut event = base::connection_created(record_id, PROVIDER, "");
        event["kind"] = json!(Kind::VaultPassword.as_str());
        event["site"] = json!(site);
        event["context"] = json!(context);
        event
    }

    /// The event of a release: `secret_released`, and behind its keys `name` for a record of
    /// kind `vault_secret` (the name the record states in its plaintext). The event of a
    /// record of another kind carries no such key.
    pub fn released(
        record_id: &str,
        kind: Kind,
        field: &str,
        origin: &str,
        context: &str,
        name: Option<&str>,
    ) -> Value {
        let mut event = base::secret_released(record_id, kind.as_str(), field, origin, context);
        if let Some(name) = name {
            event["name"] = json!(name);
        }
        event
    }

    /// The event of `vault/handoff`: the value of the record `record_id` goes into `request`,
    /// one request to the site of the secret, which the node `to` sends. It is a
    /// `provider_request` event, as `forward` creates one for a request that carries a token:
    /// the first eleven keys are those of that event, with the provider `vault` and the
    /// method, the host, the path, the query, the size and the hash of the body as the
    /// request object states them, and `name` (the name the record states), `slot` (the place
    /// of the value in the request) and `to` (the node of the forward role the value was
    /// sealed to) follow them.
    ///
    /// The path and the query hold the placeholder where the value goes, and the hash is that
    /// of the body with the placeholder in it: no part of the value is in the event. The event
    /// carries no `window_s`: every use has an event of its own, also a `GET` without a body
    /// that repeats one of the last 300 seconds.
    pub fn use_requested(
        record_id: &str,
        request: &BoundRequest,
        context: &str,
        name: &str,
        to: &str,
    ) -> Value {
        json!({
            "t": "provider_request",
            "time_ms": 0,
            "record_id": record_id,
            "provider": PROVIDER,
            "method": request.method(),
            "host": request.host(),
            "path": request.path(),
            "query": request.query(),
            "body_bytes": request.body_bytes(),
            "body_sha256": request.body_sha256(),
            "context": context,
            "name": name,
            "slot": request.slot_text(),
            "to": to,
        })
    }
}
