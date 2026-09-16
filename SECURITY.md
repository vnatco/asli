# Security policy

Asli syncs clipboard content between your own machines. Clipboard content routinely contains
passwords, tokens and private data, so security reports are taken seriously and handled before
features.

## Supported versions

| Version | Supported |
|---|---|
| Unreleased (`main`) | Yes |

There is no tagged release yet, so `main` is the only thing to report against. This table is
updated when the first version is tagged, and the policy from that point is that only the latest
minor release receives security fixes.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Preferred: open a private security advisory through GitHub, using the "Report a vulnerability"
button under the repository's Security tab. That creates a private thread visible only to the
maintainers.

Alternative contact: **TODO, add a dedicated security contact address and, if one is offered, a PGP
key fingerprint, before the first public release.** This placeholder must not survive into a tagged
version.

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
- The client crypto: key derivation, sealing, AAD binding, join token parsing, nonce handling.
- Handling of the root secret: keychain storage, memory hygiene, the join token and QR flows.
- Clipboard handling that leaks data, for example syncing content marked sensitive, or writing the
  join token somewhere it persists.
- The public relay's operational controls (quotas, caps, logging that exposes more than documented).

## Out of scope

These are documented properties of the design, not bugs. They are explained in
`docs/THREAT_MODEL.md`, and reports about them will be closed as known and accepted:

- **No forward secrecy.** A leaked root secret decrypts archived traffic.
- **No device revocation in v1.** The answer to a leaked token is resetting the account.
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

Devices share one 32 byte secret obtained by pasting one token or scanning a QR code. Clipboard
content is sealed on the device with XChaCha20-Poly1305, so the relay forwards ciphertext and holds
no key that can decrypt it. The relay authenticates devices with an Ed25519 signature over a fresh
challenge and stores only a public key, so compromising the relay yields ciphertext and metadata,
not access.

Full detail, including what this design deliberately does not protect against, is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
