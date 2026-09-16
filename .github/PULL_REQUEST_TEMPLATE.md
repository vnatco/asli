## What changed and why

<!-- One or two sentences. Link the issue if there is one. -->

## Tested on

<!-- Tick what you actually ran this on. "Not tested" is useful information, not a confession. -->

- [ ] Windows
- [ ] macOS
- [ ] Linux, X11
- [ ] Linux, Wayland (say which compositor: )
- [ ] Not tested on any platform

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Docs updated in this same pull request, if this change made any of them wrong
- [ ] No clipboard content, secrets or key material can reach a log line
- [ ] No em dashes or en dashes in code, comments, docs or commit messages

<!-- Crypto or wire format changes also need a test vector, and a protocol version bump if the
     bytes on the wire changed. See CONTRIBUTING.md. -->
