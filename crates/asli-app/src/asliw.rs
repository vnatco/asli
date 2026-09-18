//! `asliw.exe`: the same program as `asli.exe`, linked as a Windows GUI application.
//!
//! A console program started at login opens a console window, and closing that window ends the
//! program. This one has no console at all, which is what a tray application needs. Anything it
//! prints goes nowhere, so run `asli.exe tray` from a terminal to watch the log.
//!
//! Built only with the `windowed` feature, which `setup.ps1` turns on, so other platforms do not
//! link the program twice.

#![forbid(unsafe_code)]
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    asli_app::cli::main();
}
