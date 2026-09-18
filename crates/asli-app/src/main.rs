//! The `asli` command. Everything lives in [`asli_app::cli`], shared with the windowed binary.

#![forbid(unsafe_code)]

fn main() {
    asli_app::cli::main();
}
