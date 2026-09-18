# Threat model

Status: this describes the approved design and the code that now implements it. Linux is verified on real hardware for text and images; the Windows and macOS backends compile but have never executed. Where a control is designed but not built, the table says so in the row itself rather than in a summary that can drift out of date.

Related reading: `docs/PROTOCOL.md` for the wire format, the architecture notes for the crypto
spec, `SECURITY.md` for how to report a problem.

## 1. What Asli is, in one paragraph

Asli syncs clipboard text between the machines of one person. Every device holds the same 32 byte
root secret, obtained once by pasting a join token or scanning a QR code. Clipboard content is
sealed with XChaCha20-Poly1305 before it leaves the device. A relay server forwards sealed messages
between devices in the same room and retains at most the last small message. The relay never holds a
key that can decrypt anything.

## 2. Assets

| Asset | Where it lives | Value to an attacker |
|---|---|---|
| **Clipboard plaintext** | OS clipboard buffers on each device, in our process briefly, sealed in transit | Immediately actionable. Real clipboards carry passwords, API tokens, one time codes, private URLs, source code and personal messages. This is the reason the product needs encryption at all |
| **Root secret (32 bytes)** | OS keychain on each device, in the join token and QR during onboarding | Total compromise of one account. It decrypts every message ever archived by an observer and every future message, allows joining the room, and allows sending clips that every device will accept |
| **Device linkage metadata** | Visible to the relay: source IPs, connection times, message timing, padded sizes, connection count per room | Shows that a set of IP addresses belongs to one person, and when that person is active. Valuable to a surveillance oriented adversary even without content |
| **Room id** | Public routing label in every frame and in relay logs (salted) | Low. By design it is a hash of a public key and grants nothing on its own |

## 3. System model

Three trust domains:

1. **The device.** Holds the root secret, derives subkeys, reads and writes the OS clipboard.
   Everything is plaintext here. This is the only place plaintext exists.
2. **The relay.** A Node process holding, per connection, a public key and a room id, and per room,
   at most one retained sealed message under a size cap and a TTL. Memory only, no database, no disk
   writes. Treated as untrusted.
3. **The network.** TLS to the relay. Treated as hostile.

What crosses each boundary:

| Boundary | What crosses | Protection |
|---|---|---|
| Device to OS clipboard | Plaintext | None available. Every desktop OS lets local processes read the clipboard. See adversary 6 |
| Device to relay | Sealed ciphertext plus a public header (`v`, `type`, `room`, `epoch`, `msg_id`, nonce) | XChaCha20-Poly1305 with the header bound as AAD, over TLS |
| Device to keychain | Root secret | OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service) |
| Relay to disk | Nothing | Storage is in memory by design, which is also the honest answer to a legal demand |
| Relay to logs | Salted room id, event name, byte count, message id, coarse error code | Allowlist logging, never content, never the join token |

## 4. Adversaries

### 4.1 Passive network observer

**Capabilities.** Sits on the path between a device and the relay. Records everything. Can retain
recordings indefinitely.

**Gains.** That the user runs a clipboard sync tool, which relay they use, the IP addresses involved,
when each device is online, and the approximate size of each message after padding and TLS framing.

**Cannot.** Read content. TLS protects the transport and the payload is separately sealed, so even a
TLS interception (corporate MITM with an installed root) yields ciphertext.

**Residual risk that matters.** There is **no forward secrecy**. An observer who archives traffic
today and obtains the root secret in five years decrypts all of it retroactively. This is an accepted
limitation, see section 5.

### 4.2 Malicious or compromised relay operator

This is the adversary the design is actually built around, because the app ships pointed at a public
relay by default.

**What the operator CAN do:**

- Observe connection times, message timing, message sizes bucketed by padding, source IP addresses,
  and the number of connections per room.
- Link all devices in a room to each other, which is inherent to being the thing that connects them.
- Drop, delay, withhold or reorder messages. Availability is always the relay's to deny.
- Serve a stale retained message to a device that asks for it.
- Attempt to replay a stored ciphertext.
- Inject arbitrary frames into a room. They will fail authentication at the AEAD and be discarded,
  but this costs the client some work and pollutes nothing beyond the replay cache.
- Deny service by rate limiting, disconnecting, or simply switching off.

**What the operator CANNOT do:**

- **Decrypt.** It holds no key material capable of decryption. `enc_key` is derived from the root
  secret, which never leaves a device.
- **Forge a clip.** Producing a message that a client accepts requires `enc_key`.
- **Authenticate as a device.** The server stores only an Ed25519 **public** key and verifies a
  signature over a nonce it generated for that connection. There is no stored credential that can be
  replayed, so a leaked log line, crash dump or memory scrape of the relay grants no room access.
  This is the single most important difference from the original design, which used a static HMAC
  bearer token.
- **Squat or lock out a room.** `room_id = SHA-256("asli/v1/room" || pub_key)[0..16]`, checked
  arithmetically on every connect. There is no trust on first use and no stored identity state, so
  there is no first sight to win and no pinned key to corrupt.
- **Replay undetected.** Receivers keep an LRU of the last 256 `msg_id` values, reject anything
  older than 120 seconds for live messages, and reject any `seq` at or below the highest already
  seen from that `device_id`. Replay and per device rollback are detected and dropped.

**Residual risks the operator keeps.** Metadata and availability, both listed above. Neither is
fixable by a single relay design. The answer for anyone who will not accept them is self-hosting,
which is a first class path running the identical published compose file.

### 4.3 Attacker who obtains the join token or a QR screenshot

**Capabilities.** The join token **is** the root secret with a version byte and a checksum. Whoever
holds it holds the account.

**Gains.** Everything: decryption of archived and future traffic, the ability to join the room, and
the ability to send clips that every device will accept.

**How it leaks in practice, and what we do about it:**

| Leak path | Mitigation | Implemented |
|---|---|---|
| The user copies the token, and our own clipboard watcher captures and uploads it | Hash the token into the loop suppression ring **before** writing it to the clipboard | Not implemented, and not currently reachable: the echo guard is private to the transport's session with no way to seed it from the application. The leak itself is closed by a different mechanism, since the token is written with the concealment markers and the watcher skips marked content without reading it, verified live. The guard remains the right belt to the marker's braces, because a platform that cannot express concealment would otherwise have no protection at all |
| Windows Clipboard History and Cloud Clipboard persist and sync it to Microsoft | Set `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` 0 and `CanUploadToCloudClipboard` 0 when writing it | Implemented. The equivalent Linux marker, `x-kde-passwordManagerHint`, is verified on a real session. The Windows formats are compile checked only, since no Win32 call in this project has ever executed. macOS refuses a concealed write rather than writing unmarked content |
| A third party clipboard manager writes it to disk, often forever | The OS markers above are hints that well behaved managers respect. They are not enforcement, so the token display says so in as many words and recommends the QR instead | Implemented |
| The token sits in the clipboard indefinitely | Auto clear after 90 seconds, and only if nothing has been copied since, so a later copy by the user is never destroyed | Implemented and verified live. The first attempt compared against what this app last wrote, which is stale the moment someone copies elsewhere, and it wiped out a newer copy. It now tracks a generation counter that any clipboard change bumps, so a stale clear is dropped |
| Shoulder surfing, screenshots, screen sharing, screen recording | QR and token start concealed behind an explicit reveal, auto hide after 2 minutes, never written to a file, rendered no larger than needed | Designed |
| Pasting the token into a browser or a chat client that unfurls links | The token is not a URL. If a deep link is ever used it is app specific and carries the token in the **fragment**, which conventional URL handling does not transmit | Designed |
| A malicious app registers a generic `clip://` scheme and harvests join links | We do not use a generic scheme, and paste the token remains the primary path | Designed |

**Recovery.** There is no device revocation in v1. If a token leaks, the answer is "Reset account":
generate a new secret, re-onboard the devices you still trust, abandon the old room. This is a first
class menu action, not a documentation workaround. See section 5.

### 4.4 Local attacker on an unlocked device

**Capabilities.** Runs code as the user on a machine that is unlocked and logged in.

**Gains.** Everything. The keychain is unlocked, so the root secret is readable. The OS clipboard is
readable directly, so our encryption is irrelevant to this attacker.

**Mitigation.** None, and none is possible. An attacker executing as you on your unlocked machine has
already won, and any product claiming otherwise is lying. This is out of scope.

### 4.5 Local attacker on a locked or powered off device

**Capabilities.** Physical possession. Can image the disk and inspect swap and hibernation files.

**What protects the root secret.** The OS keychain: Windows Credential Manager (tied to the user
login), macOS Keychain, Linux Secret Service. On a Linux session with no Secret Service provider (a
bare Hyprland or Sway session with no gnome-keyring or kwallet running is the realistic case), the
designed fallback chain ends in an encrypted file in the config directory. **That fallback is weaker
than a real keychain and must be labelled as such in the UI**, because a file encrypted with a key
that also lives on the same disk protects against casual inspection and not against a determined
attacker with the image.

**What does not protect it.** Zeroization is defence in depth, not a guarantee. Rust moves values,
and a move may leave a copy that `Drop` never sees. The keychain API hands us memory we do not own
and may not zero. The clipboard plaintext lives in OS owned buffers we cannot zero at all, which for
this product is the dominant exposure and is unfixable. Swap and hibernation can capture any of it.

**The real control is full disk encryption**, which is the user's responsibility and which we should
recommend in the README rather than pretending our process hygiene substitutes for it.

### 4.6 Malicious application on the same machine

**Capabilities.** Runs as the user, alongside us.

**Gains.** It can read the clipboard directly through documented OS APIs. Nothing we do changes this:
the clipboard is a shared, unauthenticated bus on every desktop operating system. A tool that syncs
the clipboard cannot defend the clipboard.

**What we do control.** We do not register a generic URL scheme that another app could claim in order
to intercept join links, we keep the root secret in the OS keychain rather than a config file, and we
do not write the QR or the token to disk.

**Worth noting.** The macOS 15.4 and later pasteboard access alert exists precisely because of this
adversary. It makes our own life harder while making the platform
better, and we treat it as legitimate rather than something to work around.

### 4.7 Abusive user of the public relay

**Capabilities.** Anyone can create a room. There is no account, no email and no payment, by design.

**Gains.** A free, anonymous, unauthenticated, encrypted blob relay: a covert channel, a command and
control transport, or a small file drop.

**Mitigations.** A per room daily byte quota (50 MiB default), a small retention cap
(`RETAIN_MAX_BYTES` 64 KiB) so the relay cannot be used as a file host at all, a 24 hour TTL,
per IP and per room connection caps plus a global cap, memory only storage so there is nothing to
seize, a published abuse contact and transparency statement, and a kill switch that can block a
specific room id or stop new room creation without a redeploy.

**Honest tension.** Every one of those limits constrains a legitimate user too. The self hosted path
exists so that anyone who needs higher limits can raise them, which is what makes tight defaults on
the public instance defensible.

## 5. Accepted risks, not mitigated in v1

| Risk | Why it is accepted | Cost of fixing |
|---|---|---|
| **No forward secrecy.** A secret compromised at any time decrypts all archived and future traffic | Real forward secrecy needs a ratchet with per device pairwise state, which destroys the stateless one string join that is the entire product thesis. Key epochs do **not** help: every device must be able to derive any epoch from the root secret so an offline device can catch up, therefore old epoch keys are always recoverable | A full rekeying protocol plus device enrollment. Changes onboarding fundamentally |
| **No device revocation.** A device that holds the root secret can derive every past and future epoch | v1 has no intra account security boundary by design. All devices are equally trusted | Per device keypairs, a signed device roster, and per epoch group keys wrapped to each device. Onboarding becomes "paste a string, then approve on an existing device". Planned as the v2 path, and v1 keeps the fields (`v`, `epoch`, suite id) that make it possible |
| **The relay learns timing and padded sizes** | Unavoidable for any relay that forwards messages. Padding removes exact length leakage, including password and token lengths, but the bucket is still visible and timing is not hidden at all | Cover traffic and constant rate sending, which is disproportionate for a clipboard tool and would hurt battery life |
| **XChaCha20-Poly1305 is not key committing** | Harmless with a single key. A ciphertext could in principle be made to decrypt under two different keys, which only becomes relevant once multiple keys exist | Bind `epoch` in AAD (done, partial), and adopt a committing construction before any multi key feature. Must be revisited before per device keys |
| **VM snapshot nonce reuse.** A virtual machine snapshot restored twice can repeat OS CSPRNG output and therefore repeat a nonce | Low relevance for a desktop clipboard tool, and no cheap general defence exists | Nonce misuse resistant AEAD, or persistent nonce state, both of which add complexity for a rare case |
| **Clipboard content is readable by any local app** | This is how every desktop OS works. Not our bug and not ours to fix | Nothing available at the application layer |
| **The relay can drop, delay or withhold messages** | Availability is always the forwarder's to deny | Self host, or use multiple relays, which is not v1 |

## 6. Sensitive content, and the honest gap

A clipboard sync tool that replicates password manager output to three machines, where it sits in
clipboards and clipboard histories that never expire it, is a security regression compared to not
using the tool. KDE Connect has a public bug for exactly this. We default to **not** syncing content
that is marked sensitive, rather than offering it as an opt in.

We skip a clip entirely (do not encrypt it, do not send it, do not even hash it) when:

| Platform | Condition |
|---|---|
| Windows | `ExcludeClipboardContentFromMonitorProcessing` present at all |
| Windows | `CanIncludeInClipboardHistory` present with a serialized DWORD of 0 |
| Windows | `CanUploadToCloudClipboard` present with a serialized DWORD of 0 |
| macOS | Pasteboard types include `org.nspasteboard.ConcealedType`, `org.nspasteboard.TransientType` or `org.nspasteboard.AutoGeneratedType` |
| Linux | Offered MIME types include `x-kde-passwordManagerHint` |

`CanUploadToCloudClipboard` set to 0 deserves emphasis: it is the precise semantic of what this
product does. An application setting it is explicitly saying "do not send this to my other devices",
and honouring it is not optional.

**The gap, stated plainly.** KeePassXC sets these markers on every platform. **1Password and
Bitwarden coverage is unverified**: neither documents these registered formats publicly, so we must
assume their copies can reach us. If your password manager does not mark its clipboard writes as
sensitive, we cannot distinguish a password from any other text, because we refuse to guess.

We deliberately do **not** implement entropy or shape heuristics. Short, high entropy strings with no
whitespace are exactly what developers copy all day (git SHAs, UUIDs, API keys, base64 blobs), and a
tool that randomly refuses to sync a git SHA is worse than one that syncs a password the user was
warned about. We do plan a password manager process denylist on Windows and macOS, where the
clipboard owner is identifiable, default on. On Wayland the source client cannot be identified at
all, so marker detection is the only control there.

Users who need certainty have two controls that always work: pause sync, or use their password
manager's auto type feature instead of the clipboard.

## 7. Cryptographic dependencies

| Crate | Role | Why trusted |
|---|---|---|
| `chacha20poly1305` 0.11 | XChaCha20-Poly1305 AEAD | RustCrypto, widely deployed, has been through third party audit of the AEAD family |
| `hkdf` 0.13 | Key derivation | RustCrypto, thin wrapper over HMAC, RFC 5869 vectors in CI |
| `sha2` 0.11 | Hashing, room id derivation | RustCrypto, ubiquitous |
| `ed25519-dalek` 3.0 | Relay authentication signatures | The reference Rust Ed25519 implementation, audited, with strict verification semantics |
| `getrandom` 0.4 | All randomness, direct from the OS CSPRNG | No user space PRNG in the design at all. RNG failure is fatal by policy, never a fallback |
| `zeroize` 1.9 | Best effort memory hygiene | Defence in depth only, see 4.5 |
| `data-encoding` 2.11 | Crockford base32 for tokens and room ids | Constant time where it matters, no ambiguous alphabet |

Rejected, with reasons: `orion` and `dryoc` both self declare that they have had no third party
audit. `libsodium-sys` has been unmaintained since 2021. `rand` is dropped entirely in favour of
`getrandom` directly, which avoids a migration and an advisory.

**A note on the standard.** XChaCha20-Poly1305 has no RFC. Its normative reference,
`draft-irtf-cfrg-xchacha`, expired without being published. The de facto specification is libsodium's
`crypto_aead_xchacha20poly1305_ietf`. The frozen vectors in `testdata/vectors.json` pin our
output, but no check against libsodium itself exists yet, so "libsodium compatible" is a design
intent that has not been independently tested. An interop check is item 4 in the list below.

## 8. What we do NOT claim

- **We do not claim forward secrecy.** We claim the opposite: if the root secret leaks, archived
  traffic is retroactively readable.
- **We do not claim anonymity from the relay operator.** The operator sees your IP address, when you
  are online, when you copy, and roughly how much. Self host if that matters.
- **We do not claim protection against a compromised endpoint.** Malware on your machine reads your
  clipboard directly and reads your keychain. Nothing in this design changes that.
- **We do not claim device revocation.** v1 has none. Resetting the account is the answer.
- **We do not claim the relay cannot deny you service.** It can, trivially.
- **We do not claim to detect all passwords.** We honour the markers that exist and refuse to guess
  beyond them.
- **We do not claim any of this is audited.** No third party has reviewed this design or the code
  that does not exist yet.

## 9. Items to verify before the first release

1. Empirical confirmation that the `keyring` fallback behaves sanely on a bare Hyprland session with
   no Secret Service provider, and that the weaker file fallback is clearly labelled in the UI.
2. Whether `x-kde-passwordManagerHint` survives Mutter's XWayland selection bridge, which determines
   whether sensitive content filtering works at all on GNOME Wayland.
3. Whether 1Password and Bitwarden set any of the documented exclusion markers on any platform.
4. A libsodium interop check, run before any release is tagged.
5. A manual USPTO and EUIPO check is unrelated to security but is tracked separately.
