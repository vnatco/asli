//! Compiles the window markup into Rust at build time.
//!
//! The markup is compiled, not interpreted: there is no `.slint` file next to the binary at run
//! time, nothing to load from disk, and a mistake in the markup is a build failure rather than a
//! blank window on somebody's machine.

fn main() {
    // The style is pinned rather than left to the platform. Slint would otherwise pick a native
    // looking theme per desktop, and every control in this application is drawn by hand precisely
    // so that it looks the same on all of them. Only the About attribution comes from the widget
    // set, and it has no style of its own to disagree about.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".to_owned());

    slint_build::compile_with_config("ui/app.slint", config).expect("the window markup compiles");
}
