# Threat model

Status: this describes the design and the code that implements it, which runs in daily use on
Linux, Windows 11 and macOS. Where a control is designed but not built, the text says so where the
control is described rather than in a summary that can drift out of date.

Related reading: `docs/PROTOCOL.md` for the wire format and the cryptography, `SECURITY.md` for how
to report a problem.

## 1. What Asli is, in one paragraph

Asli syncs clipboard text and images between the machines of one person, and sends files between
them when a person on the receiving machine accepts. Every device holds the same 32 byte root secret,
which reaches a new device once, sealed to that device's own key, after a person types a join code
on it and approves it on a device already on the account. Clipboard content is sealed with
XChaCha20-Poly1305 before it leaves the device. A relay server forwards sealed messages between
devices in the same room and retains at most the last small clip. Files go directly between the two
machines when they share a local network, and through the relay otherwise. The relay never holds a
key that can decrypt anything.

## 2. Assets

| Asset | Where it lives | Value to an attacker |
|---|---|---|
| **Clipboard plaintext** | OS clipboard buffers on each device, in our process briefly, sealed in transit | Immediately actionable. Real clipboards carry passwords, API tokens, one time codes, private URLs, source code and personal messages. This is the reason the product needs encryption at all |
| **Root secret (32 bytes)** | OS keychain on each device, or an owner only file where there is no keychain (section 4.5). Handed to a new device sealed to that device's key, after a person approves it (protocol section 18). Never displayed. Accounts made before that change may have shown it as a join token | Total compromise of one account. It decrypts every message ever archived by an observer and every future message, allows joining the room, and allows sending clips that every device will accept |
| **Device secret (32 bytes)** | In the same keychain entry as the root secret, one per device. Never transmitted | Lets the holder speak as that one device: its card, a file offer or answer, a key change in its name. Gives nothing the root secret does not already give |
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
| Device to keychain | Root secret and device secret | OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service), or an unencrypted owner only file when no keychain is available (section 4.5) |
| Device to device, same network | File pieces, sealed under a key made for that transfer | XChaCha20-Poly1305, over a TCP connection on the local network (section 4.8) |
| Relay to disk | Nothing | Storage is in memory by design, which is also the honest answer to a legal demand |
| Relay to logs | Salted room id, event name, byte count, message id, coarse error code | Allowlist logging, never content |

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
- **Replay undetected.** Receivers keep the last 256 `msg_id` values and the highest `seq` seen from
  each `device_id`, saved across restarts, and reject a repeat of either. Replay and per device
  rollback are detected and dropped. Live clips more than 24 hours old or ahead are rejected too,
  as a sanity bound rather than the defence, so a wrong clock or time zone does not break sync.
  The one gap: a device with no saved state for a sender, new or just reset, can be shown one old
  clip from within those 24 hours on first contact. It cannot be read or altered.

**Residual risks the operator keeps.** Metadata and availability, both listed above. Neither is
fixable by a single relay design. The answer for anyone who will not accept them is self-hosting,
which is a first class path running the same published relay code.

### 4.3 Attacker who sees a join code, or an old join token

**A join code** (protocol section 18.5) carries no key. It names a meeting place on the relay for ten
minutes and one answer, and a fingerprint of the device that made it.

**Capabilities with a join code.** Someone who sees it in time can send a join request of their own,
and can answer the real new device's request with a grant of their own.

**Gains: none without the person's help.** Their request reaches the approving device, which shows it
with a six digit comparison code; the real new device shows a different six digits for its own
request, so approving the stranger means approving a request whose digits match nothing on the new
device. Their grant is refused by the new device, which accepts a grant only from the key the code
fingerprints. After ten minutes, or after one answer, the code is worth nothing.

**An old join token** (protocol section 5), shown by versions before join codes, **is** the root
secret. Whoever holds one holds the account until its key is replaced. Current versions neither show
nor accept tokens, and Home offers to replace the key of an account whose key was ever shown as
one; once replaced, every old token, screenshot and chat message carrying it is useless.

**How a code or an old token leaks, and what is done about it:**

| Leak path | Mitigation | Implemented |
|---|---|---|
| Shoulder surfing, screenshots, screen sharing | A code expires in ten minutes and is single use, and still needs approval with matching digits | Implemented, in the window and from the command line |
| Someone races the real new device with a request of their own | The comparison code, shown on both devices | Implemented and tested |
| Someone answers the new device's request with an account of their own | The grant must be signed by the key the code fingerprints | Implemented and tested |
| An old token survives in a screenshot, a chat or a clipboard manager | Replace the account key: a new root secret goes to every device sealed to its own key, and the old one opens nothing new | Implemented and run end to end |

**Recovery.** Remove the device, or replace the key: section 5 below, and protocol section 18.6.

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
keys go instead to `secret.key` in the configuration directory: **not encrypted**, written owner only
(mode 0600 on Linux). That protects against other users on the machine and nothing more. Anyone who
images the disk reads the key directly. `asli status` names the store in use and says this plainly;
the window does not show it.

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

**What we do control.** We do not register a URL scheme that another app could claim in order to
intercept join links, and we keep the root secret in the OS keychain rather than a config file
wherever a keychain exists (section 4.5 covers the case where none does). A join code carries no key,
so an app that reads one from the clipboard after Copy Code learns only what section 4.3 describes.

**Worth noting.** The macOS 15.4 and later pasteboard access alert exists precisely because of this
adversary. It makes our own life harder while making the platform
better, and we treat it as legitimate rather than something to work around.

### 4.7 Abusive user of the public relay

**Capabilities.** Anyone can create a room. There is no account, no email and no payment, by design.

**Gains.** A free, anonymous, unauthenticated, encrypted blob relay: a covert channel, a command and
control transport, or a small file drop.

**Mitigations.** A per room daily byte quota (50 MiB default) for clips, and a separate budget for
device to device messages, which carry files: 8 MiB a second per connection, 4 GiB a day per room
and 32 GiB a day for the whole relay, so a busy room slows down before it can starve the shared box.
Image pieces are charged to the same budget. Files are forwarded and never stored. A small
retention cap (`RETAIN_MAX_BYTES` 64 KiB) so the relay cannot be used as a file host at all, a 24
hour TTL, per IP and per room connection caps plus a global cap, and memory only storage so there is
nothing to seize. There is no mechanism to block a specific room; an operator's only levers are the
limits above and restarting with different ones.

**Honest tension.** Every one of those limits constrains a legitimate user too. The self hosted path
exists so that anyone who needs higher limits can raise them, which is what makes tight defaults on
the public instance defensible.

### 4.8 A file from another device

**Capabilities.** Any device on the account can offer a file to any other. So can anyone holding the
account key, who can seal frames the relay forwards.

**Gains.** A file on the receiving machine, if a person accepts it. A file's name is the classic
route: `../../.config/autostart/x.desktop`, a reserved Windows name, a leading dot to hide it, or a
right to left override that makes `gpj.exe` read as `exe.jpg`.

**Mitigations.** Nothing is written until a person on the receiving device accepts, and the prompt
names the device whose pinned signing key signed the offer, not a name the offer claims; an offer
from a device that is not pinned is ignored, so the room key alone cannot produce one. The receiver
makes its own name: the last path component only, with control characters, direction overrides,
zero width characters and reserved characters replaced, reserved device names and a leading dot
prefixed, and a number added rather than overwriting anything. The file is written under a temporary
name and kept only once its size and SHA-256 match the signed offer. It is marked as downloaded
(Mark of the Web on Windows, the quarantine attribute on macOS, mode 0644 on Linux) so the system
treats it as from the internet, and Asli never opens or runs it.

**Residual.** A person can still accept a harmful file from a device of theirs that was compromised,
and the content is never inspected. The prompt says to accept only files that are expected.

**On the same network.** While an offer waits, the sender listens on a port on its local network so
the receiver can fetch the file directly. Anyone on that network can connect, but the first frame
must be sealed under a key that went to the receiver alone, sealed to its device key, so a stranger
gets nothing and is disconnected; after 16 such attempts the sender stops listening. The receiver
connects only to private, carrier grade and link local addresses, so a forged or altered offer
cannot make it reach the internet. Someone on the same network learns that the two machines
exchanged a file of about that size, which the relay would otherwise learn instead. If nothing
arrives directly within 15 seconds, the receiver answers through the relay and the sender switches
to it, so a network that blocks the connection costs time, not the file.

**Old and orphaned offers.** A relay could hold on to a signed offer and deliver it again later. A
receiver ignores an offer made more than a day ago or more than a day in the future, and one that
names a connection its sender is known to have left, since an answer could not reach it. An offer
still waiting for an answer ends on either side once the other device has been off the connection
it was made on for 20 seconds.

**Same Network Only.** With this setting a device approves a new device only when the request
reaches it over the local network, sealed under a key that only the join code makes, and never takes
one through the relay. Someone who learns a code and is elsewhere cannot join even with an approval
click. It is a setting per device, and it does not restrict clips, which still sync from anywhere:
it narrows where a device can be added from and where files move, not who holds the account key.


## 5. Accepted risks, not mitigated in v1

| Risk | Why it is accepted | Cost of fixing |
|---|---|---|
| **No forward secrecy.** A secret compromised at any time decrypts all archived and future traffic | Real forward secrecy needs a ratchet with pairwise state between every pair of devices, while clips are sealed once, under a room key every device holds. Key epochs do **not** help: every device must be able to derive any epoch from the root secret so an offline device can catch up, therefore old epoch keys are always recoverable | A ratchet between every pair of devices, and clips sealed per recipient. Changes the protocol fundamentally |
| **Removing a device protects the future, not the past.** Removing one replaces the root secret and hands the new one to every other device sealed to its own key, so the removed device reads nothing sent after. It keeps whatever it already decrypted and kept, and it can still read anything an observer archived from before | A deleted copy cannot be recalled, and archived ciphertext stays decryptable under the old key by design (no forward secrecy, above) | Nothing short of forward secrecy |
| **A device offline during a key change is left behind** | The relay keeps no message for a device that is not connected, so a device that misses the new key stays on the old one, alone. It has to join again with a code. The window says which devices this will happen to before the change is made | Retained key change messages, which the relay would have to store |
| **All devices are equally trusted.** Every device holds the root secret, so a compromised device can read everything and can remove the others | Device keys stop one device speaking as another and make removal possible; they do not create a hierarchy of devices | Per device group keys and an admin role, which nobody has asked for |
| **The relay learns timing and padded sizes** | Unavoidable for any relay that forwards messages. Padding removes exact length leakage, including password and token lengths, but the bucket is still visible and timing is not hidden at all | Cover traffic and constant rate sending, which is disproportionate for a clipboard tool and would hurt battery life |
| **XChaCha20-Poly1305 is not key committing** | Harmless while every ciphertext is opened under exactly one key, which still holds with device keys: a message is opened with the room key of the epoch its header names, and a sealed box only with the recipient's own key derived for that box. A ciphertext that also decrypts under another key would only matter to a receiver that tries several keys, and none does | Adopt a committing construction before any feature that tries more than one key per message |
| **VM snapshot nonce reuse.** A virtual machine snapshot restored twice can repeat OS CSPRNG output and therefore repeat a nonce | Low relevance for a desktop clipboard tool, and no cheap general defence exists | Nonce misuse resistant AEAD, or persistent nonce state, both of which add complexity for a rare case |
| **Clipboard content is readable by any local app** | This is how every desktop OS works. Not our bug and not ours to fix | Nothing available at the application layer |
| **The relay can drop, delay or withhold messages** | Availability is always the forwarder's to deny | Self host, or use multiple relays, which is not v1 |

## 6. Sensitive content, and the honest gap

A clipboard sync tool that replicates password manager output to three machines, where it sits in
clipboards and clipboard histories that never expire it, is a security regression compared to not
using the tool. KDE Connect has a public bug for exactly this. We **never** sync content that is
marked sensitive, and there is no setting that changes this. History does not record it either.

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
| `hkdf` 0.13 | Key derivation | RustCrypto, thin wrapper over HMAC, tested upstream against the RFC 5869 vectors |
| `sha2` 0.11 | Hashing, room id derivation | RustCrypto, ubiquitous |
| `ed25519-dalek` 2 | Relay authentication signatures, and per device signatures on cards, file offers and answers | The reference Rust Ed25519 implementation, audited, with strict verification semantics |
| `x25519-dalek` 2 | Key agreement for sealing a secret to one device: the account key in a join grant or a key change, the key for a direct file transfer | Same project and same curve implementation as `ed25519-dalek`, so it adds one crate |
| `getrandom` 0.4 | All randomness, direct from the OS CSPRNG | No user space PRNG in the design at all. RNG failure is fatal by policy, never a fallback |
| `zeroize` 1.9 | Best effort memory hygiene | Defence in depth only, see 4.5 |
| `data-encoding` 2.11 | Strict base64 for binary fields on the wire | Rejects non canonical padding, which the protocol requires |

Crockford base32, used for room ids, is a short hand written module in `asli-crypto` rather than a
dependency.

Rejected, with reasons: `orion` and `dryoc` both self declare that they have had no third party
audit. `libsodium-sys` has been unmaintained since 2021. `rand` is dropped entirely in favour of
`getrandom` directly, which avoids a migration and an advisory.

**A note on the standard.** XChaCha20-Poly1305 has no RFC. Its normative reference,
`draft-irtf-cfrg-xchacha`, expired without being published. The de facto specification is libsodium's
`crypto_aead_xchacha20poly1305_ietf`. The frozen vectors in `testdata/vectors.json` pin our
output, but no check against libsodium itself exists yet, so "libsodium compatible" is a design
intent that has not been independently tested. An interop check is planned and not done; it is item
4 in the list below.

## 8. What we do NOT claim

- **We do not claim forward secrecy.** We claim the opposite: if the root secret leaks, archived
  traffic is retroactively readable.
- **We do not claim anonymity from the relay operator.** The operator sees your IP address, when you
  are online, when you copy, and roughly how much. Self host if that matters.
- **We do not claim protection against a compromised endpoint.** Malware on your machine reads your
  clipboard directly and reads your keychain. Nothing in this design changes that.
- **We do not claim a removed device forgets.** Removing a device stops it reading anything new. What
  it already decrypted and kept, it keeps.
- **We do not claim the relay cannot deny you service.** It can, trivially.
- **We do not claim to detect all passwords.** We honour the markers that exist and refuse to guess
  beyond them.
- **We do not claim any of this is audited.** No third party has reviewed this design or its code.

## 9. Items to verify before the first release

1. Empirical confirmation that the `keyring` fallback behaves sanely on a bare Hyprland session with
   no Secret Service provider. The weaker file fallback is labelled in `asli status` only, not in the
   window.
2. Whether `x-kde-passwordManagerHint` survives Mutter's XWayland selection bridge, which determines
   whether sensitive content filtering works at all on GNOME Wayland.
3. Whether 1Password and Bitwarden set any of the documented exclusion markers on any platform.
4. A libsodium interop check. Planned, not built.
5. A manual USPTO and EUIPO check is unrelated to security but is tracked separately.
