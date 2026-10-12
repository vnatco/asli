# Security policy

Asli syncs clipboard content between your own machines. Clipboard content routinely contains
passwords, tokens and private data, so security reports are taken seriously and handled before
features.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Older | No |

Only the latest minor release receives security fixes. Reports against `main` are welcome too.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Preferred: open a private security advisory through GitHub, using the "Report a vulnerability"
button under the repository's Security tab. That creates a private thread visible only to the
maintainers.

Alternative contact: **contact@vnat.dev**, if you cannot or would rather not use GitHub. Mail to
that address is read by the maintainer. There is no PGP key; if you need one to send a report,
say so in a first message with no details in it and one will be published.

Please include: what you found, how to reproduce it, the affected component (client, relay, protocol
or documentation), the platform and version, and what you think the impact is. A proof of concept is
welcome but not required.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 72 hours |
| Initial assessment, including whether we agree it is a vulnerability | 7 days |
| Fix or a documented mitigation for a confirmed high severity issue | 30 days |
| Public disclosure | Coordinated with you, after a fix is available |

If a report is disputed, the reasoning is given in writing rather than the report being closed
silently.

## In scope

- The relay protocol and its implementation: authentication, replay, rollback, room isolation,
  resource exhaustion, anything that lets one room affect another.
- The client crypto: key derivation, sealing, AAD binding, join code parsing, nonce handling,
  device keys and the signatures on device cards, file offers and answers.
- Handling of the account secret: keychain storage, memory hygiene, the join code, approval and
  grant flow, and the rekey that removes a device.
- File transfer: offers, the direct path on the local network, and writing received files to disk.
- Clipboard handling that leaks data, for example syncing or recording content marked sensitive.
- The public relay's operational controls (quotas, caps, logging that exposes more than documented).

## Out of scope

These are documented properties of the design, not bugs. They are explained in
`docs/THREAT_MODEL.md`, and reports about them will be closed as known and accepted:

- **No forward secrecy.** A leaked account secret decrypts archived traffic sent under it.
- **Removal does not reach back.** Removing a device (`asli remove`, or Remove on Home) moves the
  others to a new account key, so it reads nothing sent after; what it already received, it keeps.
- **Metadata visible to the relay**: IP addresses, connection times, message timing, padded sizes.
- **A compromised or malware infected device.** Any local process can read the clipboard on every
  desktop OS.
- **A relay denying service.** Availability is always the forwarder's to deny.
- **Passwords that a password manager does not mark as sensitive.** We honour the documented
  platform markers and deliberately do not guess beyond them.

Also out of scope: findings from automated scanners with no demonstrated impact, missing hardening
headers on the relay's health endpoint, and social engineering of maintainers or users.

## Recognition

There is no bug bounty and no money. Reporters are credited by name or handle in `CHANGELOG.md` and
in the advisory, unless you prefer to stay anonymous.

## The security model in three lines

Devices share one 32 byte account secret, which reaches a new device only after a device already
on the account approves it, sealed to the new device's own key. Clipboard content is sealed on the
device with XChaCha20-Poly1305, so the relay forwards ciphertext and holds no key that can decrypt
it. The relay authenticates devices with an Ed25519 signature over a fresh challenge and checks the
room id as a hash of the public key, holding no credential of its own, so compromising the relay
yields ciphertext and metadata, not access.

Full detail, including what this design deliberately does not protect against, is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
