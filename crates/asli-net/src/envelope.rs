//! The v1 JSON envelope.
//!
//! These types are the wire format, so they are deliberately dumb: they carry exactly the fields
//! `docs/PROTOCOL.md` defines, with the names and encodings it defines, and they validate shape
//! rather than meaning. Semantic checks (does this room match, is this sequence number a rollback)
//! live in [`crate::session`].
//!
//! Two rules from the specification are enforced here because they are easy to get wrong:
//!
//! - **Unknown fields are rejected**, not ignored. Silently accepting them hides version skew
//!   until it becomes a data bug.
//! - **Binary fields are standard base64 with padding**, decoded strictly. Base64url is not
//!   accepted as an alternative, because accepting two encodings invites a decoder mismatch that
//!   surfaces as an authentication failure with no useful diagnostic.

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The protocol version this client speaks.
pub const PROTOCOL_VERSION: u8 = 1;

/// Base64 helpers for binary fields.
mod b64 {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(|_| serde::de::Error::custom("not canonical base64"))
    }
}

/// Decodes a base64 field into a fixed size array, checking the length.
///
/// # Errors
///
/// Returns [`Error::FieldLength`] when the decoded length is wrong for that field.
pub fn fixed<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| Error::FieldLength {
        field,
        expected: N,
        got: bytes.len(),
    })
}

/// Any message on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Client to server, always first.
    Hello(Hello),
    /// Server to client, in reply to `hello`.
    Challenge(Challenge),
    /// Client to server, in reply to `challenge`.
    Auth(Auth),
    /// Server to client, the connection is ready.
    AuthOk(AuthOk),
    /// Server to client, authentication was rejected.
    AuthFail(AuthFail),
    /// An encrypted clipboard event, in either direction.
    Clip(Clip),
    /// Client to server, asking for the retained clip.
    FetchLast(FetchLast),
    /// Server to client, the room connection count changed.
    Presence(Presence),
    /// Application level liveness.
    Ping(Ping),
    /// Reply to [`Message::Ping`].
    Pong(Pong),
    /// Server to client, non fatal.
    Error(ErrorMessage),
    /// First chunk of a chunked clip.
    ClipBegin(ClipChunk),
    /// An interior chunk.
    ClipChunk(ClipChunk),
    /// Final chunk, completing the message.
    ClipEnd(ClipChunk),
}

/// Every message type this version understands, as spelled on the wire.
const KNOWN_TYPES: &[&str] = &[
    "hello",
    "challenge",
    "auth",
    "auth_ok",
    "auth_fail",
    "clip",
    "fetch_last",
    "presence",
    "ping",
    "pong",
    "error",
    "clip_begin",
    "clip_chunk",
    "clip_end",
];

impl Message {
    /// Parses a frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for invalid JSON, an unknown type, or an unknown field.
    pub fn parse(frame: &str) -> Result<Self> {
        serde_json::from_str(frame).map_err(|_| {
            // Worth telling apart: a type this version has never heard of is to be ignored, while a
            // known type that does not match its schema is a protocol error.
            #[derive(Deserialize)]
            struct Probe {
                #[serde(rename = "type")]
                kind: String,
            }
            match serde_json::from_str::<Probe>(frame) {
                Ok(probe) if !KNOWN_TYPES.contains(&probe.kind.as_str()) => Error::UnknownType,
                _ => Error::Malformed("frame did not match any type"),
            }
        })
    }

    /// Serializes a frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] only if serialization fails, which cannot happen for these
    /// types but is not worth a panic.
    pub fn to_frame(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| Error::Malformed("could not serialize"))
    }

    /// The protocol version carried by this message.
    #[must_use]
    pub const fn version(&self) -> u8 {
        match self {
            Self::Hello(m) => m.v,
            Self::Challenge(m) => m.v,
            Self::Auth(m) => m.v,
            Self::AuthOk(m) => m.v,
            Self::AuthFail(m) => m.v,
            Self::Clip(m) => m.v,
            Self::FetchLast(m) => m.v,
            Self::Presence(m) => m.v,
            Self::Ping(m) => m.v,
            Self::Pong(m) => m.v,
            Self::Error(m) => m.v,
            Self::ClipBegin(m) | Self::ClipChunk(m) | Self::ClipEnd(m) => m.v,
        }
    }
}

/// One chunk of a chunked clip.
///
/// The three chunk message types carry identical fields and differ only in position, so they share
/// one payload type. The position itself is authenticated: `idx`, `chunk_count` and the implied
/// final flag are bound into that chunk's associated data, so a relay cannot move a chunk without
/// the tag check failing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipChunk {
    /// Protocol version.
    pub v: u8,
    /// Room id, which must match the authenticated room.
    pub room: String,
    /// Key epoch, identical across every chunk of a message.
    pub epoch: u32,
    /// Message id, identical across every chunk of a message.
    #[serde(with = "b64")]
    pub msg_id: Vec<u8>,
    /// Zero based chunk index.
    pub idx: u32,
    /// Total chunks in this message.
    pub chunk_count: u32,
    /// AEAD nonce for this chunk alone, 24 bytes.
    #[serde(with = "b64")]
    pub n: Vec<u8>,
    /// Ciphertext of this chunk with the 16 byte tag appended.
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
}

/// Client to server. Always the first message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Protocol version.
    pub v: u8,
    /// Suites this client supports, in preference order.
    pub suites: Vec<String>,
    /// Envelope encodings supported. v1 clients send exactly `["json"]`.
    pub enc: Vec<String>,
    /// Short client identifier. Never a hostname, a username, or anything identifying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

/// Limits the relay announces, which the client honours in place of its own defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Largest accepted WebSocket frame, in bytes.
    pub max_frame_bytes: u64,
    /// Largest clipboard content to attempt, before encoding.
    pub max_content_bytes: u64,
    /// Messages at or below this size are retained for late joiners.
    pub retain_max_bytes: u64,
    /// Sustained per connection message rate.
    pub msgs_per_sec: u64,
    /// Rolling 24 hour per room byte quota.
    pub room_bytes_per_day: u64,
}

/// Server to client, in reply to `hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// Protocol version.
    pub v: u8,
    /// The suite the relay selected.
    pub suite: String,
    /// The envelope encoding the relay selected.
    pub enc: String,
    /// Server challenge nonce, 32 bytes, single use per connection.
    #[serde(with = "b64")]
    pub nonce_s: Vec<u8>,
    /// Server wall clock. Advisory, for diagnosing clock skew.
    pub server_time_ms: u64,
    /// The limits this relay enforces.
    pub limits: Limits,
}

/// Client to server, in reply to `challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// Protocol version.
    pub v: u8,
    /// Room id, Crockford base32, 26 characters.
    pub room: String,
    /// Ed25519 verifying key, 32 bytes.
    #[serde(with = "b64")]
    pub pub_key: Vec<u8>,
    /// Client nonce, 16 bytes, fresh per attempt.
    #[serde(with = "b64")]
    pub nonce_c: Vec<u8>,
    /// Client wall clock. Advisory only, and never a security input on the server.
    pub client_time_ms: u64,
    /// Ed25519 signature over `sig_input`, 64 bytes.
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
}

/// Server to client. The connection is ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthOk {
    /// Protocol version.
    pub v: u8,
    /// Server assigned connection identifier, for log correlation.
    pub conn_id: String,
    /// Connections currently in the room, including this one.
    ///
    /// This counts connections, never devices. The relay cannot count devices, because they are
    /// distinguishable only by `device_id`, which lives inside the ciphertext.
    pub peers: u32,
    /// Whether the relay holds a retained clip for this room.
    pub has_retained: bool,
    /// Server receive time of the retained clip, present only when `has_retained` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_at: Option<u64>,
}

/// Machine readable authentication failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuthFailCode {
    /// The relay does not speak this protocol version or suite. Permanent.
    UnsupportedVersion,
    /// The signature did not verify. Permanent.
    BadSignature,
    /// The room id is not the hash of the public key. Permanent.
    RoomMismatch,
    /// The auth message failed structural validation. A client bug.
    MalformedAuth,
    /// The server nonce was already used. Reconnect once.
    StaleNonce,
    /// Authentication did not complete inside the timeout. Transient.
    AuthTimeout,
}

impl AuthFailCode {
    /// Whether this failure will still fail on the next attempt.
    ///
    /// A client that retries a permanent failure once per second against the public relay is a
    /// self inflicted denial of service, so this drives a terminal state rather than a comment.
    #[must_use]
    pub const fn is_permanent(self) -> bool {
        matches!(
            self,
            Self::UnsupportedVersion | Self::BadSignature | Self::RoomMismatch
        )
    }

    /// A stable string for logs and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::RoomMismatch => "ROOM_MISMATCH",
            Self::MalformedAuth => "MALFORMED_AUTH",
            Self::StaleNonce => "STALE_NONCE",
            Self::AuthTimeout => "AUTH_TIMEOUT",
        }
    }
}

/// Server to client. Sent before closing when authentication fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFail {
    /// Protocol version.
    pub v: u8,
    /// Why authentication failed.
    pub code: AuthFailCode,
    /// Human readable detail. Never contains secrets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// An encrypted clipboard event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clip {
    /// Protocol version.
    pub v: u8,
    /// Room id, which must match the authenticated room.
    pub room: String,
    /// Key epoch used to seal this message.
    pub epoch: u32,
    /// Client generated message id, 16 bytes.
    #[serde(with = "b64")]
    pub msg_id: Vec<u8>,
    /// AEAD nonce, 24 bytes.
    #[serde(with = "b64")]
    pub n: Vec<u8>,
    /// Ciphertext with the 16 byte tag appended.
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
    /// Added by the relay when delivering a stored clip. Never sent by a client.
    ///
    /// Not covered by AAD, so a malicious relay can lie about it. That is acceptable because the
    /// receiver's real protections are inside the ciphertext.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained: Option<bool>,
    /// Added by the relay alongside `retained`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_at: Option<u64>,
}

impl Clip {
    /// Whether the relay marked this as a stored clip.
    #[must_use]
    pub fn is_retained(&self) -> bool {
        self.retained.unwrap_or(false)
    }
}

/// Client to server. Asks for the retained clip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchLast {
    /// Protocol version.
    pub v: u8,
}

/// Server to client. The room connection count changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    /// Protocol version.
    pub v: u8,
    /// Current connections in the room, including the receiver. Never a device count.
    pub peers: u32,
}

/// Application level liveness request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ping {
    /// Protocol version.
    pub v: u8,
    /// Echoed unchanged in the reply, for round trip measurement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<u64>,
}

/// Reply to a [`Ping`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pong {
    /// Protocol version.
    pub v: u8,
    /// Echoed from the ping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<u64>,
}

/// Non fatal error codes. A closed enum: the relay may not invent others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorCode {
    /// A rate limit tier was exceeded.
    RateLimited,
    /// The room's daily byte quota is exhausted.
    QuotaExceeded,
    /// The message exceeded an announced limit.
    MessageTooLarge,
    /// The message failed validation, but not fatally.
    Malformed,
    /// The type field is not in the registry.
    UnknownType,
    /// A message requiring a ready connection arrived too early.
    NotAuthenticated,
    /// `fetch_last` was sent but the relay holds no retained clip.
    NoRetained,
}

impl ErrorCode {
    /// A stable string for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "RATE_LIMITED",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::MessageTooLarge => "MESSAGE_TOO_LARGE",
            Self::Malformed => "MALFORMED",
            Self::UnknownType => "UNKNOWN_TYPE",
            Self::NotAuthenticated => "NOT_AUTHENTICATED",
            Self::NoRetained => "NO_RETAINED",
        }
    }
}

/// Server to client. The connection stays open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorMessage {
    /// Protocol version.
    pub v: u8,
    /// Why the message was rejected.
    pub code: ErrorCode,
    /// Human readable. Never clipboard content or a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Present for rate limiting and quota errors. The client must respect it as a floor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Encodes bytes the way every binary field on the wire is encoded.
#[must_use]
pub fn encode_b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_type_this_version_does_not_know_is_told_apart_from_a_malformed_frame() {
        assert!(matches!(
            Message::parse(r#"{"v":1,"type":"from_the_future","anything":1}"#),
            Err(Error::UnknownType)
        ));
        // A known type with a field it does not have is still a protocol error.
        assert!(matches!(
            Message::parse(r#"{"v":1,"type":"presence","peers":2,"extra":true}"#),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            Message::parse("not json"),
            Err(Error::Malformed(_))
        ));
    }

    use super::*;

    fn round_trip(frame: &str) -> Message {
        let parsed = Message::parse(frame).expect("parses");
        let reserialized = parsed.to_frame().expect("serializes");
        let reparsed = Message::parse(&reserialized).expect("reparses");
        assert_eq!(parsed, reparsed, "round trip changed the message");
        parsed
    }

    #[test]
    fn hello_round_trips() {
        let msg = round_trip(
            r#"{"v":1,"type":"hello","suites":["asli-v1"],"enc":["json"],"client":"asli/0.1.0"}"#,
        );
        let Message::Hello(hello) = msg else {
            panic!("wrong variant")
        };
        assert_eq!(hello.v, 1);
        assert_eq!(hello.suites, ["asli-v1"]);
        assert_eq!(hello.enc, ["json"]);
    }

    #[test]
    fn challenge_round_trips_and_decodes_its_nonce() {
        let nonce = encode_b64(&[7u8; 32]);
        let frame = format!(
            r#"{{"v":1,"type":"challenge","suite":"asli-v1","enc":"json","nonce_s":"{nonce}","server_time_ms":1789459200000,"limits":{{"max_frame_bytes":1048576,"max_content_bytes":716800,"retain_max_bytes":65536,"msgs_per_sec":2,"room_bytes_per_day":52428800}}}}"#
        );
        let Message::Challenge(challenge) = round_trip(&frame) else {
            panic!("wrong variant")
        };
        assert_eq!(challenge.nonce_s, vec![7u8; 32]);
        assert_eq!(challenge.limits.max_content_bytes, 716_800);
    }

    #[test]
    fn auth_ok_without_stored_at_round_trips() {
        let Message::AuthOk(ok) = round_trip(
            r#"{"v":1,"type":"auth_ok","conn_id":"c_9fK2xQ","peers":2,"has_retained":false}"#,
        ) else {
            panic!("wrong variant")
        };
        assert_eq!(ok.peers, 2);
        assert!(!ok.has_retained);
        assert_eq!(ok.stored_at, None);
    }

    #[test]
    fn auth_fail_codes_map_to_the_wire_strings() {
        let Message::AuthFail(fail) =
            round_trip(r#"{"v":1,"type":"auth_fail","code":"ROOM_MISMATCH"}"#)
        else {
            panic!("wrong variant")
        };
        assert_eq!(fail.code, AuthFailCode::RoomMismatch);
        assert!(fail.code.is_permanent());

        let Message::AuthFail(fail) =
            round_trip(r#"{"v":1,"type":"auth_fail","code":"AUTH_TIMEOUT"}"#)
        else {
            panic!("wrong variant")
        };
        assert!(!fail.code.is_permanent(), "auth timeout is transient");
    }

    #[test]
    fn clip_round_trips_with_and_without_relay_fields() {
        let msg_id = encode_b64(&[1u8; 16]);
        let nonce = encode_b64(&[2u8; 24]);
        let ct = encode_b64(&[3u8; 40]);
        let frame = format!(
            r#"{{"v":1,"type":"clip","room":"E5V0APG0E0QQ5MEGA99JBPFDHM","epoch":0,"msg_id":"{msg_id}","n":"{nonce}","ct":"{ct}"}}"#
        );
        let Message::Clip(clip) = round_trip(&frame) else {
            panic!("wrong variant")
        };
        assert!(!clip.is_retained());
        assert_eq!(clip.msg_id.len(), 16);
        assert_eq!(clip.n.len(), 24);

        let retained = format!(
            r#"{{"v":1,"type":"clip","room":"E5V0APG0E0QQ5MEGA99JBPFDHM","epoch":0,"msg_id":"{msg_id}","n":"{nonce}","ct":"{ct}","retained":true,"stored_at":1789455600000}}"#
        );
        let Message::Clip(clip) = round_trip(&retained) else {
            panic!("wrong variant")
        };
        assert!(clip.is_retained());
        assert_eq!(clip.stored_at, Some(1_789_455_600_000));
    }

    #[test]
    fn small_messages_round_trip() {
        assert!(matches!(
            round_trip(r#"{"v":1,"type":"fetch_last"}"#),
            Message::FetchLast(_)
        ));
        assert!(matches!(
            round_trip(r#"{"v":1,"type":"presence","peers":3}"#),
            Message::Presence(_)
        ));
        assert!(matches!(
            round_trip(r#"{"v":1,"type":"ping","t":1789459200412}"#),
            Message::Ping(_)
        ));
        assert!(matches!(
            round_trip(r#"{"v":1,"type":"pong"}"#),
            Message::Pong(_)
        ));
    }

    #[test]
    fn error_round_trips_with_retry_after() {
        let Message::Error(err) = round_trip(
            r#"{"v":1,"type":"error","code":"RATE_LIMITED","message":"slow down","retry_after_ms":5000}"#,
        ) else {
            panic!("wrong variant")
        };
        assert_eq!(err.code, ErrorCode::RateLimited);
        assert_eq!(err.retry_after_ms, Some(5000));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // Silently ignoring these would hide version skew until it became a data bug.
        let err = Message::parse(r#"{"v":1,"type":"presence","peers":3,"extra":true}"#);
        assert!(err.is_err(), "unknown field must be rejected");
    }

    #[test]
    fn unknown_types_are_rejected() {
        assert!(Message::parse(r#"{"v":1,"type":"telemetry","payload":1}"#).is_err());
    }

    #[test]
    fn invalid_json_is_rejected() {
        assert!(Message::parse("not json").is_err());
        assert!(Message::parse("").is_err());
        assert!(Message::parse("{}").is_err());
    }

    #[test]
    fn base64url_is_not_accepted_for_binary_fields() {
        // The spec names exactly one encoding. Accepting a second invites a decoder mismatch that
        // shows up as an unexplained authentication failure.
        let url_style = "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_g=";
        let frame = format!(
            r#"{{"v":1,"type":"challenge","suite":"asli-v1","enc":"json","nonce_s":"{url_style}","server_time_ms":1,"limits":{{"max_frame_bytes":1,"max_content_bytes":1,"retain_max_bytes":1,"msgs_per_sec":1,"room_bytes_per_day":1}}}}"#
        );
        assert!(Message::parse(&frame).is_err());
    }

    #[test]
    fn unpadded_base64_is_rejected() {
        let unpadded = "AAAA".repeat(10); // 40 chars, decodes fine
        let bad = format!("{unpadded}A"); // 41 chars, not canonical
        let frame = format!(
            r#"{{"v":1,"type":"challenge","suite":"asli-v1","enc":"json","nonce_s":"{bad}","server_time_ms":1,"limits":{{"max_frame_bytes":1,"max_content_bytes":1,"retain_max_bytes":1,"msgs_per_sec":1,"room_bytes_per_day":1}}}}"#
        );
        assert!(Message::parse(&frame).is_err());
    }

    #[test]
    fn fixed_checks_decoded_lengths() {
        assert!(fixed::<16>("msg_id", &[0u8; 16]).is_ok());
        assert_eq!(
            fixed::<16>("msg_id", &[0u8; 15]),
            Err(Error::FieldLength {
                field: "msg_id",
                expected: 16,
                got: 15
            })
        );
    }
}
