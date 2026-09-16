//! The Asli window, compiled from markup.
//!
//! # Why this is a crate of its own
//!
//! Slint generates the Rust behind `ui/app.slint` at build time, and that generated code expands
//! macros containing `unsafe` guarded by `#[allow(unsafe_code)]`. A crate root cannot both
//! `forbid(unsafe_code)` and contain an inner `allow`: `forbid` overrules it and the build fails.
//!
//! Rather than weaken that to `deny` across a crate full of hand written code, the generated code
//! lives here on its own. Every other crate in the project keeps `#![forbid(unsafe_code)]`, and
//! the only `unsafe` anywhere is inside the toolkit's own generated bindings, which is where it
//! would have been regardless of which crate held them.
//!
//! # What is in here
//!
//! Markup and nothing else. There is no logic in this crate: `ui/design.slint` holds the controls,
//! built from primitives rather than a widget library, and `ui/app.slint` holds the six screens.
//! Everything they do is a callback the application implements in `asli-app`.

// The generated code is not ours to document or lint, and the toolkit already sets most of these
// internally. They are repeated here because the include happens in this crate's root.
#![allow(missing_docs)]
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

slint::include_modules!();
