//! Gives the Windows executables the Asli icon.
//!
//! Explorer, the Start menu and the taskbar take a program's icon from a resource compiled into
//! the executable. Without one, both `asli.exe` and `asliw.exe` wore the generic Windows program
//! icon. Nothing happens for other targets: they carry their icon elsewhere, in the desktop entry
//! on Linux and the bundle on macOS.

fn main() {
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
