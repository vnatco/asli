//! Stamps the build number, and gives the Windows executables the Asli icon.
//!
//! The build number is how many commits the source had, which only goes up on `main`, so devices
//! can tell which of them runs the newest Asli even while every build says 0.1.0. A build from a
//! source tree without git is number 0, which reads as unknown rather than old.
//!
//! Explorer, the Start menu and the taskbar take a program's icon from a resource compiled into
//! the executable. Without one, both `asli.exe` and `asliw.exe` wore the generic Windows program
//! icon. Nothing happens for other targets: they carry their icon elsewhere, in the desktop entry
//! on Linux and the bundle on macOS.

fn main() {
    stamp_build();
    let icon =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows/asli.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // Written with an absolute path, because resource compilers disagree about what a relative
    // one is relative to.
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let rc = out.join("asli.rc");
    let icon = icon
        .canonicalize()
        .expect("packaging/windows/asli.ico exists");
    let escaped = icon.display().to_string().replace('\\', "\\\\");
    std::fs::write(&rc, format!("1 ICON \"{escaped}\"\n")).expect("writes the resource script");

    embed_resource::compile(&rc, embed_resource::NONE)
        .manifest_optional()
        .expect("compiles the icon resource");
}

/// Sets `ASLI_BUILD` (the commit count) and `ASLI_COMMIT` (the short hash) for the code to read.
fn stamp_build() {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let count = git(&["rev-list", "--count", "HEAD"]).unwrap_or_else(|| "0".to_owned());
    let commit = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=ASLI_BUILD={count}");
    println!("cargo:rustc-env=ASLI_COMMIT={commit}");
    // A new commit moves HEAD, or the branch it names, so either changing restamps.
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/refs/heads");
        println!("cargo:rerun-if-changed={dir}/packed-refs");
    }
}
