# Asli wire protocol, version 1

Status: **normative specification, not yet implemented.** No client or relay code exists at the time
of writing. This document defines what the implementation must do, and it is the reference an
independent implementer needs in order to build an interoperable client or relay without reading the
Rust source.

Protocol version: `1`. Suite identifier: `asli-v1`.

Related documents: `docs/THREAT_MODEL.md` (adversaries, accepted risks, what is and is not claimed).

---

## 1. Scope

This document specifies:

- the transport and framing between an Asli client and an Asli relay,
- the key hierarchy derived from a device's root secret,
- the join token format used for onboarding,
- the authentication handshake,
- the authenticated encryption of clipboard events,
- the validation every receiver must perform,
- the relay's obligations, limits and retention rules,
- close codes, error codes and reconnection behaviour.

This document does not specify: clipboard capture per operating system, tray behaviour, keychain
storage, or the relay's internal data structures. Those live in the architecture notes, and
in `docs/PLATFORM_NOTES.md` once written.

### 1.1 Design constraints that explain the shape of this protocol

1. The relay is untrusted. It MUST be able to route and rate limit without learning anything about
   clipboard content, and it MUST NOT hold any value that would let it, or anyone who steals its
   state, join a room.
2. Onboarding is one string. Every device derives everything from the same 32 byte root secret, with
   no per-device enrollment step and no server-side registration.
3. The protocol is versioned in-band so that a future change (binary framing, image chunking, key
   rotation, per-device keys) does not require a flag day.

---

## 2. Terminology and conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and
OPTIONAL are to be interpreted as described in RFC 2119.

| Term | Meaning |
|---|---|
| Client | An Asli desktop application instance on one machine. |
| Device | A client installation, identified to other clients (never to the relay) by `device_id`. |
| Relay | The WebSocket server that forwards ciphertext between clients in a room. |
| Room | The set of connections sharing one `room_id`. One room corresponds to one account, that is one root secret. |
| Account | One root secret and everything derived from it. |
| Peer | Another connection in the same room. |

Notation:

| Notation | Meaning |
|---|---|
| `\|\|` | Byte concatenation. |
| `u8(n)` | One byte with value n. |
| `u32be(n)` | Four bytes, big endian, unsigned. |
| `u64be(n)` | Eight bytes, big endian, unsigned. |
| `X[a..b]` | Bytes of X from index a inclusive to index b exclusive. |
| `"literal"` | ASCII bytes, no terminating NUL, no length prefix unless one is written explicitly. |

All multi-byte integers in sealed structures and in signature inputs are big endian. All label
strings are ASCII and are frozen: changing one byte of a label changes every derived value and
breaks interoperability, which is exactly what the known-answer tests in section 16 exist to catch.

### 2.1 Encoding of binary values in JSON

Every binary field in the v1 JSON envelope MUST be encoded as **standard base64 with padding**,
RFC 4648 section 4 (alphabet `A-Z a-z 0-9 + /`, padding character `=`).

Implementations MUST decode strictly:

- reject any character outside the alphabet, including whitespace and newlines,
- reject incorrect or missing padding,
- reject a decoded length that does not match the length this document requires for that field.

Implementations MUST NOT accept base64url (`-` and `_`) as an alternative in the JSON envelope, and
MUST NOT emit it. A single encoding is specified deliberately, because accepting two invites a
decoder mismatch that would surface as an authentication failure with no useful diagnostic.

Note that the join token (section 5) and the `room_id` string (section 4.4) use Crockford base32
instead, for human handling and QR density. Those are the only two exceptions, and neither travels in
the JSON envelope as base64.

---

## 3. Transport

| Property | Value |
|---|---|
| Transport | WebSocket (RFC 6455) over TLS |
| URL scheme | `wss://` REQUIRED in production. `ws://` MAY be used for loopback development only. |
| Path | `/v1` |
| WebSocket subprotocol | None. Version negotiation is in-band via `hello`, see section 7.1. |
| Frame type in v1 | Text frames containing UTF-8 JSON |
| Health endpoint | `GET /healthz` on the same origin, returning 200 with a minimal body |

A client connects to a single relay at a time. The relay URL is configurable, and the public relay is
the default. Self-hosted relays are first class and differ only in the limits they announce.

### 3.1 Framing

Every WebSocket message MUST contain exactly one JSON object with no leading or trailing content.
The object MUST contain at least:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Protocol version. MUST be `1` for this specification. |
| `type` | string | Message type from the registry in section 7. |

Receivers (both client and relay) MUST reject a message that contains any field not defined for its
type. Unknown fields are a protocol drift signal and silently ignoring them hides version skew until
it becomes a data bug. The relay responds to such a message with close code 4005.

Receivers MUST check the frame size before parsing. Parsing a 1 MiB hostile JSON document in order to
then reject it is the mistake this rule exists to prevent.

### 3.2 Binary framing, reserved

A future version MAY negotiate `bin1` in `hello` (section 7.1). `bin1` is a fixed binary layout, not
CBOR and not MessagePack:

```
u8 version | u8 type_code | u32be epoch | room_id[16] | msg_id[16] | nonce[24] | ciphertext
```

The first 39 bytes of that layout are deliberately close to the AAD of section 9.1, so that the
binding between header and ciphertext is self evident. `bin1` is **specified as a direction, not as a
format, and is not implemented in v1.** A v1 relay MUST NOT offer `bin1` and a v1 client MUST NOT
send binary frames.

---

## 4. Cryptographic constructions

### 4.1 Suite `asli-v1`

| Parameter | Value |
|---|---|
| AEAD | XChaCha20-Poly1305-IETF (libsodium `crypto_aead_xchacha20poly1305_ietf`) |
| AEAD key length | 32 bytes |
| AEAD nonce length | 24 bytes, random per message |
| AEAD tag length | 16 bytes, appended to the ciphertext |
| KDF | HKDF-SHA-256 (RFC 5869) |
| Hash | SHA-256 |
| Signature | Ed25519 (RFC 8032) |
| Root secret | 32 bytes from the operating system CSPRNG |

XChaCha20-Poly1305 has no RFC. Its normative reference, `draft-irtf-cfrg-xchacha`, expired without
becoming a standard. The de facto specification is libsodium's implementation, so an implementation
MUST verify its output against libsodium (section 16, layer 3) rather than assuming compatibility.

### 4.2 Key hierarchy

```
secret          32 bytes, OS CSPRNG, stored in the OS keychain, never transmitted after onboarding

PRK             = HKDF-Extract(salt = "asli/v1/root-salt", IKM = secret)          -> 32 bytes
sign_seed       = HKDF-Expand(PRK, info = "asli/v1/device-sign",            L = 32)
enc_key[epoch]  = HKDF-Expand(PRK, info = "asli/v1/clip-enc" || u32be(epoch), L = 32)
```

| Label | Bytes | Length |
|---|---|---|
| `"asli/v1/root-salt"` | HKDF-Extract salt, a constant and not a secret | 17 |
| `"asli/v1/device-sign"` | HKDF-Expand info for the signing seed | 19 |
| `"asli/v1/clip-enc"` | HKDF-Expand info prefix for content keys, followed by `u32be(epoch)` | 16 + 4 |

Rules:

- The root secret MUST NOT be used directly as an AEAD key, a signing key or a MAC key. Every key is
  derived, with domain separation by label.
- `sign_seed` is independent of `epoch`, so the room identity is stable across key rotation.
- `epoch` is a `u32` starting at `0`.
- `PRK`, `sign_seed` and every `enc_key` SHOULD be held in memory wrappers that zero on drop, and
  implementations MUST NOT write them to disk outside the OS keychain.

### 4.3 Identity and room id

```
sign_key        = Ed25519 signing key constructed from the 32 byte seed sign_seed
pub_key         = Ed25519 verifying key                                   (32 bytes)

room_id_bytes   = SHA-256("asli/v1/room" || pub_key)[0..16]               (16 bytes, 128 bits)
room_id         = Crockford-Base32(room_id_bytes)                         (26 characters)
```

`"asli/v1/room"` is 12 ASCII bytes.

The room id is a deterministic function of the public key, which is a deterministic function of the
root secret. Two consequences are load bearing:

1. The relay verifies `room_id` against `pub_key` arithmetically on every connection, so there is no
   trust-on-first-use, no first-sight registration, no room squatting and no possibility of locking
   an owner out of their own room.
2. `room_id` is a routing label, not a credential. Knowing it grants nothing, because joining
   requires a signature under `sign_key`.

### 4.4 Crockford base32

`room_id` and the join token use Crockford base32.

| Property | Value |
|---|---|
| Alphabet | `0123456789ABCDEFGHJKMNPQRSTVWXYZ` |
| Excluded letters | `I`, `L`, `O`, `U` |
| Case emitted | Uppercase |
| Padding | None |
| Check symbol | Not used (this protocol carries its own checksum in the join token) |

Encoders MUST emit uppercase without padding. Decoders MUST accept lowercase, MUST map `I` and `L` to
`1` and `O` to `0` as Crockford specifies, and MUST reject `U` and any other character outside the
alphabet. Decoders MUST reject an input whose decoded length is not exactly the length expected for
the field.

16 bytes encode to 26 characters. 36 bytes encode to 58 characters.

---

## 5. Join token

The join token is the entire onboarding payload. It carries the root secret and nothing else.

```
payload   = u8(1) || secret[32]                                    (33 bytes)
checksum  = SHA-256("asli/v1/join-check" || payload)[0..3]         (3 bytes, 24 bits)
token     = "asli1_" || Crockford-Base32(payload || checksum)      (6 + 58 = 64 characters)
```

`"asli/v1/join-check"` is 18 ASCII bytes. The leading `u8(1)` is the **token format version**, which
is independent of the protocol version and allows the token shape to change without changing the wire
protocol.

The token deliberately does not contain `room_id`: the room id is derivable from the secret, so
carrying it would lengthen the QR for no benefit. Those characters buy a checksum instead, which
catches a truncated or mistyped token locally, before the user sees a confusing connection failure.

### 5.1 Parsing rules

A parser MUST perform these steps in order and MUST report a distinct, specific error for each
failure rather than a generic one:

| Step | Check | Error condition |
|---|---|---|
| 1 | Strip leading and trailing whitespace, including newlines pasted by chat clients | none |
| 2 | Prefix is exactly `asli1_`, case sensitive | `BadPrefix` |
| 3 | Remaining text is 58 characters and decodes as Crockford base32 | `BadCharacter` or `BadLength` |
| 4 | Decoded length is exactly 36 bytes | `BadLength` |
| 5 | First byte (token format version) is `1` | `UnsupportedTokenVersion` |
| 6 | Recomputed checksum over the first 33 bytes equals the last 3 bytes | `BadChecksum` |

Only after all six checks pass may the parser treat bytes `[1..33]` as the root secret.

Implementations MUST NOT log the token, any part of it, or the secret, at any log level.

### 5.2 Deep links

A URL form is OPTIONAL and is secondary to pasting the bare token. If implemented it MUST use the
app-specific scheme and MUST carry the token in the fragment:

```
asli://join#asli1_<58 characters>
```

The fragment is used because conventional URL handling does not transmit fragments to servers, which
limits the damage if the link escapes into a browser. Implementations MUST treat a token arriving by
deep link as untrusted input and run the full section 5.1 parse.

A generic scheme such as `clip://` MUST NOT be used. Scheme registration is first come or last write
on both Windows and macOS, so a generic scheme can be hijacked by any other application to harvest
join tokens.

---

## 6. Connection lifecycle

```
        connect (wss)
             |
             v
        [CONNECTED] --- client sends hello ------> 
             |
             v
        [CHALLENGED] <-- server sends challenge ---
             |
             v
        [AUTHENTICATING] --- client sends auth --->
             |
       +-----+------+
       |            |
   auth_ok      auth_fail  -> close (see section 12)
       |
       v
   [READY]  clip, fetch_last, presence, ping, pong, error
```

Requirements:

- The client MUST send `hello` as its first message. A relay MUST close with 4005 if the first
  message is anything else.
- The relay MUST close a connection with 4001 if it has not reached `[READY]` within **10 seconds**
  of the TCP connection being established. Unauthenticated connections are the cheapest resource for
  an attacker to create, so this timeout is a load bearing control, not a convenience.
- A client MUST NOT send `clip` or `fetch_last` before receiving `auth_ok`. A relay MUST respond to a
  premature message with `error` code `NOT_AUTHENTICATED` and MAY close with 4005 on repetition.
- The relay MUST issue `nonce_s` once per connection and MUST invalidate it on first use, whether
  verification succeeded or failed. A connection that fails `auth` MUST NOT be given a second
  challenge; the client reconnects instead.

---

## 7. Message types

Registry. Direction C is client, S is server.

| Type | Direction | Purpose | Section |
|---|---|---|---|
| `hello` | C to S | Version, suite and encoding advertisement | 7.1 |
| `challenge` | S to C | Server nonce, server time, announced limits | 7.2 |
| `auth` | C to S | Room id, public key, client nonce, signature | 7.3 |
| `auth_ok` | S to C | Connection accepted, peer count, retained state | 7.4 |
| `auth_fail` | S to C | Machine readable failure code, followed by close | 7.5 |
| `clip` | C to S, S to C | Encrypted clipboard event | 7.6 |
| `fetch_last` | C to S | Explicit request for the retained clip | 7.7 |
| `presence` | S to C | Room connection count changed | 7.8 |
| `ping`, `pong` | C to S, S to C | Optional application level liveness and RTT | 7.9 |
| `error` | S to C | Non fatal, connection stays open | 7.10 |
| `clip_begin` | C to S, S to C | First chunk of a chunked clip | 7.11 |
| `clip_chunk` | C to S, S to C | An interior chunk | 7.11 |
| `clip_end` | C to S, S to C | Final chunk, completing the message | 7.11 |

Sealed message types additionally have a numeric **type code**, bound into AAD (section 9.1):

| Type code | Type | Status |
|---|---|---|
| 1 | `clip` | v1 |
| 2 | `clip_begin` | v1 |
| 3 | `clip_chunk` | v1 |
| 4 | `clip_end` | v1 |
| 5 to 255 | unassigned | Reserved |

Type codes are reserved now so that a v1.1 chunked message cannot collide with a v1 `clip` in AAD.

All JSON examples below are **illustrative and are not test vectors**. Authoritative values live in
`testdata/vectors.json`, described in section 16.

### 7.1 `hello`

Client to server. MUST be the first message.

| Field | Type | Encoding | Required | Meaning |
|---|---|---|---|---|
| `v` | integer | | yes | Protocol version, `1` |
| `type` | string | | yes | `"hello"` |
| `suites` | array of string | | yes | Suites the client supports, in preference order. MUST contain at least `"asli-v1"` |
| `enc` | array of string | | yes | Envelope encodings supported. v1 clients MUST send exactly `["json"]` |
| `client` | string | | no | Short client identifier and version, for example `"asli/0.1.0"`. MUST NOT contain a hostname, username, or any other identifying value |

```json
{
  "v": 1,
  "type": "hello",
  "suites": ["asli-v1"],
  "enc": ["json"],
  "client": "asli/0.1.0"
}
```

If the relay supports none of the offered suites, or the protocol version is unsupported, it MUST
reply `auth_fail` with code `UNSUPPORTED_VERSION` and close with 4004.

### 7.2 `challenge`

Server to client, in reply to `hello`.

| Field | Type | Encoding | Required | Meaning |
|---|---|---|---|---|
| `v` | integer | | yes | `1` |
| `type` | string | | yes | `"challenge"` |
| `suite` | string | | yes | The suite the relay selected, `"asli-v1"` |
| `enc` | string | | yes | The envelope encoding selected, `"json"` |
| `nonce_s` | string | base64, 32 bytes | yes | Server challenge nonce, from the server CSPRNG, single use, per connection |
| `server_time_ms` | integer | | yes | Server wall clock, milliseconds since the Unix epoch. Advisory, for diagnosing clock skew |
| `limits` | object | | yes | See below |

`limits` object:

| Field | Type | Required | Meaning | Public relay default |
|---|---|---|---|---|
| `max_frame_bytes` | integer | yes | Largest accepted WebSocket frame, in bytes | 1048576 (1 MiB) |
| `max_content_bytes` | integer | yes | Largest clipboard content the client should attempt, before encoding | 716800 (700 KiB) |
| `retain_max_bytes` | integer | yes | Messages at or below this size are retained for late joiners | 65536 (64 KiB) |
| `msgs_per_sec` | integer | yes | Sustained per connection message rate | 2 |
| `room_bytes_per_day` | integer | yes | Rolling 24 hour per room byte quota | 52428800 (50 MiB) |

```json
{
  "v": 1,
  "type": "challenge",
  "suite": "asli-v1",
  "enc": "json",
  "nonce_s": "5m8aKQ0vT2xJ7Yw1cRk4bNf6hLpZsUeAqXdGvBnMtCo=",
  "server_time_ms": 1789459200000,
  "limits": {
    "max_frame_bytes": 1048576,
    "max_content_bytes": 716800,
    "retain_max_bytes": 65536,
    "msgs_per_sec": 2,
    "room_bytes_per_day": 52428800
  }
}
```

Clients MUST honour the announced limits rather than the defaults compiled into them, so that a self
hosted relay can raise or lower caps without a client update. A client SHOULD surface the effective
content limit to the user when a clip is skipped for size.

### 7.3 `auth`

Client to server, in reply to `challenge`.

| Field | Type | Encoding | Required | Meaning |
|---|---|---|---|---|
| `v` | integer | | yes | `1` |
| `type` | string | | yes | `"auth"` |
| `room` | string | Crockford base32, 26 chars | yes | `room_id` |
| `pub_key` | string | base64, 32 bytes | yes | Ed25519 verifying key |
| `nonce_c` | string | base64, 16 bytes | yes | Client nonce, fresh per attempt, from the OS CSPRNG |
| `client_time_ms` | integer | | yes | Client wall clock, milliseconds since the Unix epoch. Advisory only |
| `sig` | string | base64, 64 bytes | yes | Ed25519 signature over `sig_input`, section 8.1 |

```json
{
  "v": 1,
  "type": "auth",
  "room": "C8V4B1KQ7M3ZRXPT9WNJ0GHA2E",
  "pub_key": "3Dq1sV8mZ0pYxK5tA7cWnE2fRbLgH4uJ6iOyT9dQxNo=",
  "nonce_c": "T7xR2mQ9vL0bZ4cW8nKpAg==",
  "client_time_ms": 1789459200412,
  "sig": "kR3vN8mZ1qT5xY7wA0cJ6bL2fH9dPsUeGiOyX4tQnMoV2pB8rK1sW5zC7yD3aE6gF0hJ4lN9uT2xR7vM5q=="
}
```

### 7.4 `auth_ok`

Server to client. The connection enters `[READY]`.

| Field | Type | Encoding | Required | Meaning |
|---|---|---|---|---|
| `v` | integer | | yes | `1` |
| `type` | string | | yes | `"auth_ok"` |
| `conn_id` | string | opaque, at most 64 characters | yes | Server assigned connection identifier, for diagnostics and log correlation |
| `peers` | integer | | yes | Number of connections currently in the room, including this one |
| `has_retained` | boolean | | yes | Whether the relay currently holds a retained clip for this room |
| `stored_at` | integer | | no | Server receive time of the retained clip, milliseconds since the Unix epoch. Present only when `has_retained` is true |

```json
{
  "v": 1,
  "type": "auth_ok",
  "conn_id": "c_9fK2xQ",
  "peers": 2,
  "has_retained": true,
  "stored_at": 1789455600000
}
```

### 7.5 `auth_fail`

Server to client. The relay MUST send this before closing when authentication fails, so the client
can distinguish a permanent configuration problem from a transient one.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `type` | string | yes | `"auth_fail"` |
| `code` | string | yes | Closed enum, see below |
| `message` | string | no | Human readable, for logs and diagnostics. MUST NOT contain secrets |

| `code` | Close code that follows | Client behaviour |
|---|---|---|
| `UNSUPPORTED_VERSION` | 4004 | Permanent. Prompt the user to update |
| `BAD_SIGNATURE` | 4002 | Permanent. Surface a configuration error |
| `ROOM_MISMATCH` | 4003 | Permanent. Client bug or corrupted keychain entry |
| `MALFORMED_AUTH` | 4005 | Treat as a bug. Do not retry immediately |
| `STALE_NONCE` | 4005 | Reconnect once; repeated occurrences are a bug |
| `AUTH_TIMEOUT` | 4001 | Transient. Reconnect with backoff |

```json
{ "v": 1, "type": "auth_fail", "code": "ROOM_MISMATCH", "message": "room id does not match public key" }
```

### 7.6 `clip`

Client to server, then server to every other connection in the room.

| Field | Type | Encoding | Required | Meaning |
|---|---|---|---|---|
| `v` | integer | | yes | `1` |
| `type` | string | | yes | `"clip"` |
| `room` | string | Crockford base32, 26 chars | yes | MUST equal the connection's authenticated room |
| `epoch` | integer | u32 range | yes | Key epoch used to seal this message |
| `msg_id` | string | base64, 16 bytes | yes | Client generated, unique per message. Used for relay dedup, sender exclusion and receiver loop prevention |
| `n` | string | base64, 24 bytes | yes | AEAD nonce |
| `ct` | string | base64 | yes | Ciphertext with the 16 byte Poly1305 tag appended |
| `retained` | boolean | | no | Added **by the relay** when delivering a stored clip. Absent on live delivery. MUST NOT be sent by a client |
| `stored_at` | integer | | no | Added by the relay alongside `retained` |

```json
{
  "v": 1,
  "type": "clip",
  "room": "C8V4B1KQ7M3ZRXPT9WNJ0GHA2E",
  "epoch": 0,
  "msg_id": "9xK2mQ7vT1bZ4cW8nRpAgQ==",
  "n": "T5xY7wA0cJ6bL2fH9dPsUeGiOyX4tQnMoV2p",
  "ct": "hQ4kR9vN2mZ8qT1xY5wA7cJ0bL6fH3dPsUeGiOyT4xQnMoV2pB8rK5sW1zC9yD7aE3gF6hJ2lN4uT8xR0vM5q=="
}
```

Relay obligations for `clip`:

1. Verify `room` equals the authenticated room for the connection. If not, close with 4005.
2. Verify the frame size against `max_frame_bytes`. If exceeded, close with 1009 or reply `error`
   `MESSAGE_TOO_LARGE` and close with 4006.
3. Verify `msg_id` decodes to exactly 16 bytes, `n` to exactly 24 bytes, and `ct` to at least 17
   bytes (one byte of ciphertext plus the tag).
4. Drop the message without forwarding if `msg_id` was already seen for this room within the dedup
   window (the relay SHOULD keep the last 256 `msg_id` values per room).
5. Forward the message **unmodified** to every other connection in the room, excluding the sender.
6. Apply the retention rules of section 11.2.

The relay MUST NOT modify `v`, `type`, `room`, `epoch`, `msg_id`, `n` or `ct`. All six are bound
into AAD or are the ciphertext itself, so modification is detectable by receivers, but the relay is
still specified not to do it.

### 7.7 `fetch_last`

Client to server. Requests the retained clip, if any. The relay replies with a `clip` carrying
`retained: true`, or with `error` code `NO_RETAINED`.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `type` | string | yes | `"fetch_last"` |

```json
{ "v": 1, "type": "fetch_last" }
```

Retrieval is explicit and never automatic. The relay MUST NOT push the retained clip on connect.

### 7.8 `presence`

Server to client, when the room's connection count changes.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `type` | string | yes | `"presence"` |
| `peers` | integer | yes | Current number of connections in the room, including the receiver |

```json
{ "v": 1, "type": "presence", "peers": 3 }
```

`peers` counts **connections, not devices.** The relay cannot count devices, because devices are
distinguishable only by `device_id`, which lives inside the ciphertext. A client MUST NOT present
this number as a device count. One device briefly holding two connections during a reconnect will be
counted twice, which is why the relay SHOULD debounce presence events by one to two seconds and the
client SHOULD do the same before updating any UI.

### 7.9 `ping` and `pong`

Application level liveness, OPTIONAL, in either direction.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `type` | string | yes | `"ping"` or `"pong"` |
| `t` | integer | no | Echoed unchanged in the `pong`, for round trip measurement |

```json
{ "v": 1, "type": "ping", "t": 1789459200412 }
```

The **primary** liveness mechanism is the WebSocket protocol level ping, which the relay MUST send
every 30 seconds, terminating any connection that misses two consecutive intervals. 30 seconds also
keeps NAT and proxy idle timeouts, commonly 60 seconds, from silently dropping an idle connection.
The application level `ping` exists for clients that cannot observe protocol level pongs and for RTT
display. A receiver of `ping` MUST reply `pong` promptly.

### 7.10 `error`

Server to client. Non fatal: the connection stays open.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `type` | string | yes | `"error"` |
| `code` | string | yes | Closed enum, see section 12.2 |
| `message` | string | no | Human readable. MUST NOT contain clipboard content or any secret |
| `retry_after_ms` | integer | no | Present for `RATE_LIMITED` and `QUOTA_EXCEEDED`. The client MUST respect it |

```json
{ "v": 1, "type": "error", "code": "RATE_LIMITED", "message": "slow down", "retry_after_ms": 5000 }
```

---

### 7.11 `clip_begin`, `clip_chunk` and `clip_end`

A payload too large for one frame crosses as an ordered run of chunks. All three types carry the
same fields, and differ only in position: `clip_begin` is index 0 of a message with more to come,
`clip_end` is the final index, and `clip_chunk` is everything between. A single chunk message uses
`clip_end`, so a receiver can never be handed a `clip_begin` that silently completes.

| Field | Type | Encoding | Required | Meaning |
|---|---|---|---|---|
| `v` | number | | yes | Protocol version, 1 |
| `room` | string | Crockford base32, 26 chars | yes | Must match the authenticated room |
| `epoch` | number | u32 | yes | Key epoch, identical across every chunk of a message |
| `msg_id` | string | base64, 16 bytes | yes | Identical across every chunk of a message |
| `idx` | number | u32 | yes | Zero based chunk index |
| `chunk_count` | number | u32 | yes | Total chunks, identical across every chunk, at most 4096 |
| `n` | string | base64, 24 bytes | yes | AEAD nonce, fresh per chunk, never reused |
| `ct` | string | base64 | yes | Ciphertext of this chunk with its 16 byte tag appended |

```json
{"v":1,"type":"clip_begin","room":"PAJJVF67VX0M0RJKZ0FDAD8B2M","epoch":0,
 "msg_id":"sLGys7S1tre4ubq7vL2+vw==","idx":0,"chunk_count":4,
 "n":"EBESExQVFhcYGRobHB0eHyAhIiMkJSYn","ct":"..."}
```

A sender MUST emit chunks in ascending index order on one connection, and MUST NOT interleave two
chunked messages. A receiver MUST NOT rely on either: ordering is enforced cryptographically by
section 9.5, not by arrival order.

## 8. Authentication handshake

### 8.1 Signature input

The signed input is a fixed byte string. It MUST NOT be constructed by serializing JSON, because JSON
key order, whitespace and number formatting are not canonical and two implementations will eventually
disagree about the bytes they are signing.

```
sig_input = "asli/v1/auth"              (12 bytes)
         || u8(1)                        protocol version
         || u8(16) || room_id_bytes      (1 + 16 bytes)
         || u8(32) || pub_key            (1 + 32 bytes)
         || u8(32) || nonce_s            (1 + 32 bytes)
         || u8(16) || nonce_c            (1 + 16 bytes)
         || u64be(client_time_ms)        (8 bytes)

total = 12 + 1 + 17 + 33 + 33 + 17 + 8 = 121 bytes, fixed
```

```
sig = Ed25519-Sign(sign_key, sig_input)
```

The single byte length prefixes are fixed in v1. They exist so that a future version can introduce a
variable length field without creating parsing ambiguity.

### 8.2 Server verification

The relay MUST perform these checks in order and MUST fail closed at the first failure. It MUST NOT
reveal which check failed beyond the codes in section 7.5.

| Step | Check | Failure |
|---|---|---|
| 1 | `room` decodes from Crockford base32 to exactly 16 bytes | `MALFORMED_AUTH`, 4005 |
| 2 | `pub_key` decodes to exactly 32 bytes and is a valid Ed25519 verifying key encoding | `MALFORMED_AUTH`, 4005 |
| 3 | `nonce_c` decodes to exactly 16 bytes, `sig` to exactly 64 bytes | `MALFORMED_AUTH`, 4005 |
| 4 | `SHA-256("asli/v1/room" \|\| pub_key)[0..16]` equals the decoded `room` | `ROOM_MISMATCH`, 4003 |
| 5 | `nonce_s` matches the nonce issued to this connection and has not been used. Invalidate it now, whether or not the remaining steps pass | `STALE_NONCE`, 4005 |
| 6 | `Ed25519-Verify(pub_key, sig_input, sig)` succeeds, where `sig_input` is reconstructed from the received fields | `BAD_SIGNATURE`, 4002 |
| 7 | The connection reached this point within the 10 second auth timeout | `AUTH_TIMEOUT`, 4001 |

`client_time_ms` MUST NOT drive any server side security decision. It is carried so that gross clock
skew is diagnosable from logs, nothing more.

The relay stores **no per room secret and no first sight state.** It holds, per live connection, the
authenticated `room_id`. It MAY log a salted derivative of `room_id`
and MUST NOT log `pub_key`, `sig`, `nonce_s` or `nonce_c`.

---

## 9. Sealing a clip

### 9.1 Additional authenticated data

AAD is a fixed 51 byte, length prefixed byte string. It MUST NOT be serialized JSON.

```
AAD = "asli/v1/aad"                 (11 bytes)
   || u8(v)                          protocol version                  (1)
   || u8(type_code)                  1 for clip                        (1)
   || u32be(epoch)                                                     (4)
   || u8(16) || room_id_bytes                                          (1 + 16)
   || u8(16) || msg_id                                                 (1 + 16)

total = 11 + 1 + 1 + 4 + 17 + 17 = 51 bytes, fixed
```

What is deliberately **not** in AAD: `device_id`, `seq`, `ts_ms` and `content_type`. All four live
inside the ciphertext. Putting `device_id` in AAD would hand the relay a stable per device identifier
for free, which is exactly the metadata this design withholds. `msg_id` must be public because the
relay uses it for dedup and sender exclusion, so it is bound in AAD instead.

### 9.2 Inner plaintext

```
inner = u8(inner_version)            = 1                               (1)
     || u8(content_type)                                               (1)
     || u8(16) || device_id                                            (1 + 16)
     || u64be(seq)                                                     (8)
     || u64be(ts_ms)                                                   (8)
     || u32be(content_len)                                             (4)
     || content[content_len]
     || padding                       zero bytes to the bucket boundary

header length = 1 + 1 + 17 + 8 + 8 + 4 = 39 bytes
```

| Field | Type | Meaning |
|---|---|---|
| `inner_version` | u8 | `1`. Independent of the protocol version, so the sealed layout can evolve separately |
| `content_type` | u8 | `1` = `text/plain; charset=utf-8`. `2` = `image/png`, specified but not implemented in v1 |
| `device_id` | 16 bytes | Random, generated once per device installation, persisted. Never sent outside the ciphertext |
| `seq` | u64be | Per device monotonic counter, persisted across restarts, incremented once per sent clip |
| `ts_ms` | u64be | Client wall clock at capture, milliseconds since the Unix epoch |
| `content_len` | u32be | Length of `content` in bytes, so de-padding needs no heuristics |
| `content` | bytes | UTF-8 text for `content_type` 1 |
| `padding` | zero bytes | Length is `padded_len - 39 - content_len` |

Text content MUST be normalized before sealing: strip a UTF-8 BOM, strip a single trailing NUL,
and convert CRLF and lone CR to LF. Leading and trailing whitespace MUST NOT be trimmed. Empty and
whitespace-only content MUST NOT be sent. These rules exist so that a round trip between platforms is
byte identical, which is what makes the receiver's loop prevention hash work at all.

### 9.3 Padding buckets

Let `L = 39 + content_len`. The padded length `P` is the smallest value satisfying:

| Condition | Rule |
|---|---|
| `L <= 65536` | `P` is the smallest power of two that is at least `max(L, 256)` |
| `L > 65536` | `P` is the smallest multiple of 65536 that is at least `L` |

Bucket table for the common cases:

| `L` range | `P` |
|---|---|
| 1 to 256 | 256 |
| 257 to 512 | 512 |
| 513 to 1024 | 1024 |
| 1025 to 2048 | 2048 |
| 2049 to 4096 | 4096 |
| 4097 to 8192 | 8192 |
| 8193 to 16384 | 16384 |
| 16385 to 32768 | 32768 |
| 32769 to 65536 | 65536 |
| above 65536 | next multiple of 65536 |

Powers of two above 64 KiB would nearly double the traffic for a large payload, which is why the rule
switches to a fixed 64 KiB step. All of v1's text traffic lands in the small buckets, where the
absolute overhead is at most a few kilobytes.

Padding removes exact length leakage, which is the part that would otherwise reveal password and
token lengths. It does not hide the bucket, and correlated bucket sizes over time remain informative.
This is stated as a limit, not as a solved problem.

### 9.4 Sealing

```
nonce = 24 bytes from the OS CSPRNG
ct    = XChaCha20Poly1305-Seal(key = enc_key[epoch], nonce, aad = AAD, plaintext = inner_padded)
```

Requirements:

- The nonce MUST come from the operating system CSPRNG, fresh for every message.
- A CSPRNG failure MUST be fatal to the operation. Implementations MUST NOT fall back to a user space
  PRNG, MUST NOT derive a nonce from a counter or timestamp, and MUST NOT reuse a previous nonce.
- 192 bit random nonces are the reason this protocol uses XChaCha rather than ChaCha20-Poly1305-IETF:
  multiple devices share one `enc_key` with no coordination, so a counter based nonce scheme would
  require partitioning the nonce space, which a stateless design cannot do.

### 9.5 Opening

A receiver reconstructs AAD from the public header fields it received, selects `enc_key[epoch]`, and
opens the ciphertext. If the tag does not verify, the message MUST be discarded silently, counted for
diagnostics, and MUST NOT be retried or reported to the relay. A verification failure means either
corruption or an active attack, and neither warrants a response that would confirm anything to the
relay.

---

### 9.5 Sealing and opening a chunk

A chunked message is encoded and padded exactly as a single clip would be, by section 9.2 and
section 9.3, and only then split. That order matters: padding the whole message hides the true
content length, whereas padding each chunk would leak the length of the final one.

Each chunk is sealed independently under its own fresh nonce, with associated data that binds its
position:

```
AAD = "asli/v1/caad"                 (12 bytes)
   || u8(v)                           protocol version                  (1)
   || u8(type_code)                   2, 3 or 4                         (1)
   || u32be(epoch)                                                      (4)
   || u8(16) || room_id_bytes                                           (1 + 16)
   || u8(16) || msg_id                                                  (1 + 16)
   || u32be(idx)                                                        (4)
   || u32be(chunk_count)                                                (4)
   || u8(final)                       1 for the last chunk, else 0      (1)

total = 12 + 1 + 1 + 4 + 17 + 17 + 4 + 4 + 1 = 61 bytes, fixed
```

The label differs from the 51 byte clip AAD in section 9.1, so the two constructions can never be
confused. The clip AAD is unchanged.

Binding `idx`, `chunk_count` and the final flag is the point of the whole construction. Without
them every chunk of a message is interchangeable to the AEAD, and a relay can reorder chunks, drop
one from the middle, or truncate the stream, while each individual chunk still verifies. The
receiver would then reassemble attacker chosen content with no way to detect it. With them, a chunk
verifies only in the exact position it was sealed for.

Receiver rules, all of which MUST hold:

- A chunk whose `msg_id`, `epoch` or `chunk_count` differs from the assembly in progress is
  rejected.
- An `idx` outside `0 ..= chunk_count - 1`, or one that has already arrived, is rejected. A
  repeated index means either a broken sender or a relay replaying a chunk, and the assembly is no
  longer trustworthy either way.
- The accumulated payload is measured as chunks arrive and rejected the moment it exceeds the cap,
  not at the end.
- Nothing is committed to the clipboard until every index has arrived and the reassembled inner
  plaintext decodes. A partial assembly is discarded.
- `chunk_count` above 4096 is rejected outright, so a hostile count cannot drive an allocation.

### 9.6 Image content

Images travel as PNG and nothing else in v1. One format on the wire means no transcoding
ambiguity, no format sniffing on the receiving side, and no second decoder to harden. A client that
captures a clipboard image in another format normalizes it to PNG before sealing, or does not sync
it.

The relay never inspects content type: it is inside the ciphertext, exactly as for text.

## 10. Receiver validation

A receiving client MUST apply these checks, in this order, after a successful AEAD open. Every
failure results in the message being discarded.

| Order | Check | Rationale |
|---|---|---|
| 1 | `inner_version` is `1`, `content_type` is supported, `content_len` fits within the padded plaintext | Structural sanity |
| 2 | `device_id` is not this device's own `device_id` | The relay excludes the sender, but a malicious relay may not. This is the last line against a self echo loop |
| 3 | `msg_id` has not been seen. Maintain an LRU set of the **last 256** `msg_id` values | Authoritative anti replay, and it doubles as the loop prevention the design requires |
| 4 | `seq` is strictly greater than the highest `seq` already accepted from this `device_id` | Detects a relay replaying or rolling back one device's messages |
| 5 | For a live message, `now - ts_ms <= 120000` (120 seconds) | Bounds how stale an applied clip can be |
| 6 | For a message marked `retained`, the age window extends to the relay's retention period instead | A retained clip is legitimately old |
| 7 | `ts_ms` no more than 60000 ms (60 seconds) in the future | Clock skew tolerance. `ts_ms` is advisory; `seq` and `msg_id` carry the security weight |

### 10.1 Retained clips

A clip delivered with `retained: true` MUST NOT be written to the system clipboard automatically on
connect. The client SHOULD offer it as an explicit action, for example a tray item reading "Paste
last synced clip".

If an implementation does apply retained clips automatically, it MUST compare the inner `ts_ms`
against the timestamp of the last clip applied locally and MUST NOT overwrite a newer local
clipboard. A device that just copied something locally losing it to a stale clip from the relay is a
real and easily reproduced bug.

The `retained` and `stored_at` fields are added by the relay and are **not** covered by AAD, so a
malicious relay can lie about both. This is acceptable because the receiver's real protections are
the `msg_id`, `seq` and `ts_ms` checks inside the ciphertext, which the relay cannot forge. A client
MUST NOT grant a message any additional trust because it is marked retained, and MUST NOT extend the
age window (check 6) beyond the announced retention period.

### 10.2 Loop prevention outside the protocol

Loop prevention is not solely a protocol concern. A client MUST also record the hash of normalized
content **before** writing it to the system clipboard, never after, so that the clipboard change
event its own write produces can be suppressed.

---

## 11. Relay behaviour

### 11.1 Forwarding

- The relay forwards `clip` to every connection in the room except the sender.
- The relay MUST NOT forward any other message type between clients.
- The relay MUST NOT decrypt, inspect, transform, re-encode or persist plaintext, because it holds no
  key capable of any of that. It MUST NOT log `ct`, `n`, `sig`, `pub_key` or any decoded form.
- The relay SHOULD store the retained payload as raw bytes rather than as a parsed object or a
  string, decoding base64 once at ingest.

### 11.2 Retention

| Parameter | Default | Rule |
|---|---|---|
| `RETAIN_MAX_BYTES` | 65536 (64 KiB) | Messages above this are forwarded live but MUST NOT be retained |
| `RETAIN_TTL` | 24 hours | Swept periodically **and** checked lazily on read, so an expired entry is never served even if the sweep is behind |
| `RETAIN_GLOBAL_BUDGET_BYTES` | 268435456 (256 MiB) | Global ceiling across all rooms, with LRU eviction of the least recently active rooms |
| `MAX_ROOMS` | configurable | New room creation is refused past the cap, with close code 4009 |

Exactly one clip is retained per room: the most recent one that satisfies the size rule. The
clipboard is last write wins, so there is no value in retaining a history, and retaining one is
explicitly out of scope.

### 11.3 Limits

| Limit | Public relay default | Enforced by |
|---|---|---|
| `max_frame_bytes` | 1 MiB | The WebSocket layer, before JSON parsing |
| `max_content_bytes` | 700 KiB | The client, at capture time |
| Base64 expansion | 4/3 | Why the two numbers above differ |

Worked example of the worst case, which is why 700 KiB is the content cap for a 1 MiB frame: 716800
bytes of content gives an inner length of 716839, which pads to 720896 (11 times 65536), plus the 16
byte tag is 720912 bytes of ciphertext, which base64 encodes to 961216 characters, leaving roughly
85 KiB of headroom inside a 1 MiB frame for the rest of the envelope.

### 11.4 Rate limiting

| Tier | Default | Action on breach |
|---|---|---|
| Per connection, messages | burst 10, refill 2 per second | `error` `RATE_LIMITED`, then close 4007 on repetition |
| Per connection, bytes | burst 2 MiB, refill 256 KiB per second | close 4007 |
| Per room, daily bytes | 50 MiB per rolling 24 hours | close 4008 |
| Per IP, concurrent connections | 20 | reject at upgrade, close 4009 |
| Per IP, new connections | burst 10, refill 1 per 5 seconds | reject at upgrade |
| Per room, concurrent connections | 16 | close 4009 |
| Global connections | configurable | reject at upgrade |

A self hosted relay MAY set any of these higher and MUST announce the values it uses in `challenge`.

### 11.5 Backpressure

Because the clipboard is last write wins, a relay MUST NOT queue multiple clips for a slow consumer.
It SHOULD keep a single pending slot per connection, overwriting it with the newest clip, and flush
when the socket drains. A connection whose send buffer stays above a hard threshold past a timeout
MUST be closed with 1009 or 4007.

---

## 12. Close codes and error codes

### 12.1 WebSocket close codes

The 4000 to 4999 range is reserved for private application use and requires no registration.

| Code | Meaning | Permanent? | Client action |
|---|---|---|---|
| 1000 | Normal closure | n/a | Do not reconnect if the user initiated it |
| 1001 | Server going away or restarting | no | Reconnect with backoff and jitter |
| 1009 | Message too big | no | Do not resend that message. Surface a size error |
| 1011 | Server internal error | no | Reconnect with backoff |
| 4001 | Auth timeout | no | Reconnect with backoff |
| 4002 | Auth failed, bad signature | **yes** | Do not retry. Surface a configuration error |
| 4003 | Room id does not match public key | **yes** | Do not retry. Client bug or corrupted keychain entry |
| 4004 | Unsupported protocol version | **yes** | Do not retry. Prompt the user to update |
| 4005 | Malformed message | no | Do not retry immediately. Log it, this is a bug |
| 4006 | Message exceeds a server limit | no | Do not resend that message |
| 4007 | Rate limited | no | Back off with a 60 second floor |
| 4008 | Room daily quota exceeded | no | Back off with a 1 hour floor, surface it in the tray |
| 4009 | Too many connections (IP, room or global) | no | Back off with a long floor |
| 4010 | Server shutting down | no | Reconnect with backoff and jitter |

Codes 4002, 4003 and 4004 are **permanent**. A client MUST represent them as explicit terminal states
in its connection state machine rather than letting "do not retry" be an emergent property. A client
that retries a bad signature once per second against the public relay is a self inflicted denial of
service.

### 12.2 `error` codes

A closed enum. A relay MUST NOT invent codes outside this list, and a code MUST NOT be reused with a
different meaning in a later version.

| Code | Meaning | Connection stays open |
|---|---|---|
| `RATE_LIMITED` | A rate limit tier was exceeded. `retry_after_ms` is present | yes |
| `QUOTA_EXCEEDED` | The room's daily byte quota is exhausted. `retry_after_ms` is present | yes |
| `MESSAGE_TOO_LARGE` | The message exceeded `max_frame_bytes` or another announced limit | yes |
| `MALFORMED` | The message failed validation but not fatally | yes |
| `UNKNOWN_TYPE` | The `type` field is not in the section 7 registry | yes |
| `NOT_AUTHENTICATED` | A message requiring `[READY]` arrived before `auth_ok` | yes |
| `NO_RETAINED` | `fetch_last` was sent but the relay holds no retained clip | yes |

---

## 13. Reconnection

A client MUST reconnect automatically and indefinitely for every non permanent close code.

```
delay = random(0, min(CAP, BASE * 2^attempt))
BASE  = 500 ms
CAP   = 30 s     (60 s after close code 4007, 3600 s after 4008)
```

Requirements:

| Rule | Reason |
|---|---|
| Full jitter, a uniform draw over the whole interval, not exponential plus a small random addition | The purpose is to decorrelate every client in the fleet when the relay restarts and they all disconnect in the same second |
| Reset `attempt` only after a connection has been authenticated and stable for **60 seconds** | Resetting on connect alone produces a tight loop against a relay that accepts and immediately closes |
| Bypass the backoff exactly once on an OS network change (interface up, wake from sleep, VPN connect) | A tray app that waits 30 seconds after the laptop lid opens feels broken |
| Respect `retry_after_ms` when present, as a floor | The relay knows its own limits better than the client does |
| Never stop retrying on a transient code. Keep retrying at `CAP` indefinitely | A tray app is expected to recover unattended |
| Surface the state honestly, distinguishing Connected, Reconnecting and Offline | This is the diagnostic that every competitor lacks |

---

## 14. Versioning and compatibility

| Mechanism | Purpose |
|---|---|
| `v` in every message | Protocol version. A relay that does not support the offered version fails the handshake cleanly with `UNSUPPORTED_VERSION` and 4004 rather than on a malformed message |
| `suites` in `hello` | Cryptographic suite negotiation, so an AEAD or KDF change does not need a new protocol version |
| `enc` in `hello` | Envelope encoding negotiation, the path to `bin1` |
| `epoch` in the public header, bound in AAD | Key rotation without re-onboarding |
| `inner_version` inside the ciphertext | The sealed layout can change independently of the envelope |
| Type code registry, section 7 | A future chunked message cannot collide with a v1 `clip` in AAD |

Compatibility policy:

- **No flag day upgrades.** A new client MUST keep speaking the version its peers understand until
  every device in the room has upgraded. Shipping a release that breaks every client at once, which
  at least one competitor has done, is prohibited by this policy.
- A receiver MUST ignore an unknown **message type** by responding with `error` `UNKNOWN_TYPE` and
  keeping the connection open, but MUST reject an unknown **field** inside a known type.
- During a key rotation window, receivers MUST accept `epoch` values in the range
  `[current - 1, current + 1]`, so a device that has not yet observed the bump can still decrypt.

### 14.1 What rotation does and does not provide

Bumping `epoch` derives a fresh `enc_key`. Because every device derives any epoch from the root
secret, a device that was offline during a rotation catches up with no coordination, which preserves
the stateless property that makes one string onboarding possible.

Rotation does **not** provide device revocation. A revoked device still holds the root secret and can
derive every past and future epoch. In v1, revocation means: create a new account, re-onboard the
devices you still trust, and abandon the old room. Documentation MUST NOT imply otherwise.

---

## 15. Security considerations

This section summarizes. `docs/THREAT_MODEL.md` is authoritative.

### 15.1 What the relay can do

- Observe connection times, source IP addresses, message timing and message sizes rounded to the
  padding bucket.
- Count connections per room, and correlate connections that share a room.
- Drop messages, delay messages, or refuse service entirely.
- Lie about `peers`, `has_retained`, `retained` and `stored_at`, none of which are authenticated.
- Attempt to replay a stored ciphertext, which receivers detect through `msg_id` dedup, the per
  device `seq` check and the `ts_ms` age window.

### 15.2 What the relay cannot do

- Decrypt any clipboard content. It holds no key and is never sent one.
- Forge a `clip` that a client will accept, because it cannot produce a valid Poly1305 tag.
- Join a room or authenticate as a device, because it stores only a public key and authentication
  requires a signature over a fresh nonce under the corresponding private key.
- Roll back a specific device undetectably, because `seq` is monotonic per device and checked.
- Learn `device_id`, `seq`, `ts_ms` or the content type, all of which are inside the ciphertext.

### 15.3 Properties this protocol does not claim

- **No forward secrecy.** A root secret compromised at any time decrypts every ciphertext an observer
  archived, past and future. Fixing this requires a ratchet, which is incompatible with stateless one
  string onboarding.
- **No post compromise security and no device revocation in v1**, per section 14.1.
- **No key commitment.** XChaCha20-Poly1305 is not key committing. With a single key this is
  harmless, and `epoch` in AAD is a partial mitigation, but the limitation must be revisited before
  any feature that puts two keys in play at once.
- **No anonymity from the relay operator**, who sees IP addresses and timing.
- **No protection against a compromised endpoint.** Any application on a machine can read that
  machine's clipboard, by design of every desktop operating system.

### 15.4 Handling requirements

- The join token and the root secret MUST NOT be logged, at any level, by client or relay.
- A client MUST suppress its own capture of the join token when it is copied to the clipboard during
  onboarding, by recording its normalized hash in the loop prevention ring **before** writing it, by
  setting the platform exclusion formats, and by clearing the clipboard after a timeout.
- Implementations SHOULD zero key material in memory when it is no longer needed, while documenting
  that this does not defend against swap, hibernation images or a memory capture of a running
  process.

---

## 16. Test vectors

Authoritative vectors live in `testdata/vectors.json`. That file does not exist yet; it is created
alongside the `asli-crypto` implementation, and CI treats a mismatch as a hard failure. Any change to
a label, a length prefix, a field order or a truncation length MUST break these tests loudly.

Four layers:

| Layer | Source | Purpose |
|---|---|---|
| 1, upstream primitives | RFC 8439 (ChaCha20 and the AEAD), draft-irtf-cfrg-xchacha-03 sections 2.2.1, A.1 and A.3.1 (HChaCha20 and the XChaCha AEAD), RFC 5869 SHA-256 cases, RFC 8032 (Ed25519) | Proves the primitives are driven correctly |
| 2, project known answer | `testdata/vectors.json` | Freezes this specification's own constructions |
| 3, libsodium interop | A script that verifies layer 2 ciphertext with libsodium | Proves the libsodium compatibility claim rather than assuming it. Runs on every build, not only at release |
| 4, negative | Listed below | Every failure mode must fail closed |

### 16.1 Expected shape of `testdata/vectors.json`

For a fixed test secret of `00 01 02 ... 1f` (32 bytes), the file records, as lowercase hex unless
noted:

| Key | Value |
|---|---|
| `secret` | The 32 byte test secret |
| `prk` | HKDF-Extract output |
| `sign_seed` | 32 bytes |
| `pub_key` | 32 bytes |
| `room_id_bytes` | 16 bytes |
| `room_id` | The 26 character Crockford base32 string |
| `join_token` | The full 64 character token, including the `asli1_` prefix |
| `join_checksum` | 3 bytes |
| `enc_key_0`, `enc_key_1` | 32 bytes each, for epochs 0 and 1 |
| `aad` | The exact 51 AAD bytes for a fixed `epoch`, `msg_id` and room |
| `nonce` | The fixed 24 byte nonce used for the sealing vector |
| `inner` | The exact padded inner plaintext bytes for a fixed content string |
| `ciphertext` | The exact sealed output, ciphertext with tag appended |
| `sig_input` | The exact 121 byte signature input for a fixed `nonce_s` and `nonce_c` |
| `sig` | The 64 byte signature |
| `chunked` | A four chunk message: the fixed `msg_id`, `content`, `chunk_bytes`, `chunk_count`, `padded_plaintext_len`, and per chunk the `idx`, `final`, `type_code`, `nonce`, the exact 61 AAD bytes and the exact ciphertext |

### 16.2 Negative tests

Each of these MUST fail closed:

- A flipped bit in the ciphertext, in the tag, or in the nonce.
- A truncated tag, a truncated ciphertext, an empty ciphertext.
- AAD with a changed `epoch`, `type_code`, `room_id` or `msg_id`.
- AAD assembled in a different field order.
- Opening with the wrong epoch's key.
- A replayed `msg_id`.
- A `ts_ms` beyond the max age window.
- A `seq` at or below the highest already seen for that `device_id`.
- A chunk presented at an index other than the one it was sealed for.
- A chunk stream missing an interior index, or truncated before its final chunk.
- A chunk repeating an index already accepted.
- A chunk claiming a `chunk_count` that differs from the assembly in progress.
- A `room_id` that does not match `pub_key`.
- A signature over a stale or already used `nonce_s`.
- Malformed join tokens: bad prefix, bad checksum, wrong length, wrong version byte, invalid
  characters.

---

## 17. Reserved for future versions

| Feature | Status | Notes |
|---|---|---|
| `bin1` binary framing | Reserved, not implemented | Section 3.2. Negotiated through `enc` in `hello` |
| Image content (`content_type` 2) | Specified and implemented at the transport layer | PNG only, see section 9.6. Clipboard capture of images is a client concern and lands separately |
| Chunked transfer | Specified and implemented | See sections 7.11 and 9.5 |
| Per device keys and a signed device roster | Not specified | The v2 path to real revocation, noted in the architecture notes It changes onboarding and is deliberately not in v1 |
| Files as a content type | Not planned | Out of scope |
