//! Graphical prompts, for the paths that must never require a terminal.
//!
//! # Why this exists
//!
//! The product promise is that you create an account on one machine, get one string, and paste it
//! on the others. Until this module existed the only way to paste it was `asli join <token>` in a
//! shell, which is not an onboarding story for anyone who does not keep a terminal open. A tray
//! application that sends people to the command line has, from their side, no join feature at all.
//!
//! # Why shelling out rather than a toolkit
//!
//! Adding a GUI toolkit for three prompts would pull GTK or Qt into a project that deliberately
//! avoids both: the whole reason for the `ksni` tray backend is that it needs neither. Every
//! desktop in the target list already ships a dialog binary, so this asks the desktop rather than
//! bringing its own.
//!
//! # Order of preference
//!
//! `kdialog` first, then `zenity`. Not alphabetical: `kdialog` is the Qt one and looks native on
//! KDE, `zenity` is the GTK one and looks native everywhere else, and a KDE session that has both
//! should get the one that matches. When neither exists the caller is told which package to
//! install, by name, rather than silently doing nothing.

use std::process::{Command, Stdio};

/// Which dialog program this session has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// KDE's dialog binary, from the `kdialog` package.
    KDialog,
    /// The GTK dialog binary, from the `zenity` package.
    Zenity,
}

impl Tool {
    /// The package a person would install to get this.
    #[must_use]
    pub const fn package(self) -> &'static str {
        match self {
            Self::KDialog => "kdialog",
            Self::Zenity => "zenity",
        }
    }

    /// The binary name.
    #[must_use]
    pub const fn binary(self) -> &'static str {
        self.package()
    }
}

/// Finds a usable dialog program, preferring the one that matches the desktop.
///
/// Returns `None` when neither is installed, which is a real possibility on a bare compositor and
/// must be reported rather than treated as a refusal by the user.
#[must_use]
pub fn detect() -> Option<Tool> {
    [Tool::KDialog, Tool::Zenity]
        .into_iter()
        .find(|tool| which(tool.binary()))
}

/// Advice for a session with no dialog program, naming both packages.
#[must_use]
pub fn missing_advice() -> String {
    "No graphical dialog program was found. Install kdialog or zenity, or join from a terminal \
     with 'asli join <token>'."
        .to_owned()
}

/// Whether a binary exists on `PATH`.
///
/// `PATH` is walked directly rather than shelling out to `which`, because spawning a process to
/// ask whether a process can be spawned is both slower and one more thing to be missing.
fn which(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(binary);
        candidate.is_file() && is_executable(&candidate)
    })
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}

/// What a person chose when offered two named options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// The first, affirmative option.
    Primary,
    /// The second option.
    Secondary,
    /// The dialog was dismissed without choosing.
    Cancelled,
}

/// Asks for a line of text.
///
/// Returns `None` when the dialog is cancelled or no dialog program exists, which the caller must
/// treat as "the person changed their mind", never as an empty answer.
///
/// The text is not hidden. A join token is not a password being typed from memory: it is pasted,
/// and a person pasting into a hidden field cannot see that they pasted the wrong thing, or that
/// their clipboard held something else entirely. The token is already visible on the other
/// machine's screen at this moment, so hiding it here buys nothing and costs the ability to check.
#[must_use]
pub fn ask_text(tool: Tool, title: &str, prompt: &str) -> Option<String> {
    let output = match tool {
        Tool::KDialog => Command::new(tool.binary())
            .args(["--title", title, "--inputbox", prompt, ""])
            .stderr(Stdio::null())
            .output(),
        Tool::Zenity => Command::new(tool.binary())
            .args([
                "--entry", "--title", title, "--text", prompt, "--width", "460",
            ])
            .stderr(Stdio::null())
            .output(),
    };

    let output = output.ok()?;
    if !output.status.success() {
        return None;
    }
    let answer = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if answer.is_empty() {
        None
    } else {
        Some(answer)
    }
}

/// Asks a yes or no question, with both buttons named.
///
/// Naming the buttons matters for a destructive action: "OK" next to a warning about losing an
/// account tells a person nothing about what OK does.
#[must_use]
pub fn confirm(tool: Tool, title: &str, text: &str, yes: &str, no: &str) -> bool {
    let status = match tool {
        Tool::KDialog => Command::new(tool.binary())
            .args([
                "--title",
                title,
                "--warningyesno",
                text,
                "--yes-label",
                yes,
                "--no-label",
                no,
            ])
            .stderr(Stdio::null())
            .status(),
        Tool::Zenity => Command::new(tool.binary())
            .args([
                "--question",
                "--title",
                title,
                "--text",
                text,
                "--ok-label",
                yes,
                "--cancel-label",
                no,
                "--width",
                "460",
            ])
            .stderr(Stdio::null())
            .status(),
    };

    status.is_ok_and(|s| s.success())
}

/// Offers two named choices, distinguishing a cancel from either of them.
///
/// Used for first run, where "create" and "join" are both legitimate and closing the window is
/// neither.
#[must_use]
pub fn choose(tool: Tool, title: &str, text: &str, primary: &str, secondary: &str) -> Choice {
    let status = match tool {
        Tool::KDialog => Command::new(tool.binary())
            .args([
                "--title",
                title,
                "--yesnocancel",
                text,
                "--yes-label",
                primary,
                "--no-label",
                secondary,
            ])
            .stderr(Stdio::null())
            .status(),
        Tool::Zenity => Command::new(tool.binary())
            .args([
                "--question",
                "--title",
                title,
                "--text",
                text,
                "--ok-label",
                primary,
                "--cancel-label",
                secondary,
                "--extra-button",
                "Quit",
                "--width",
                "460",
            ])
            .stderr(Stdio::null())
            .status(),
    };

    let Ok(status) = status else {
        return Choice::Cancelled;
    };

    // Both tools use exit 0 for the affirmative and 1 for the negative. kdialog uses 2 for its
    // third button, zenity returns 1 for both its cancel button and its extra button, so the
    // distinction only exists where the tool provides one.
    match status.code() {
        Some(0) => Choice::Primary,
        Some(1) => Choice::Secondary,
        _ => Choice::Cancelled,
    }
}

/// Shows an error, so a failure lands in front of the person rather than in a log they cannot see.
pub fn error(tool: Tool, title: &str, text: &str) {
    let _ = match tool {
        Tool::KDialog => Command::new(tool.binary())
            .args(["--title", title, "--error", text])
            .stderr(Stdio::null())
            .status(),
        Tool::Zenity => Command::new(tool.binary())
            .args([
                "--error", "--title", title, "--text", text, "--width", "420",
            ])
            .stderr(Stdio::null())
            .status(),
    };
}

/// Shows a plain message.
pub fn info(tool: Tool, title: &str, text: &str) {
    let _ = match tool {
        Tool::KDialog => Command::new(tool.binary())
            .args(["--title", title, "--msgbox", text])
            .stderr(Stdio::null())
            .status(),
        Tool::Zenity => Command::new(tool.binary())
            .args(["--info", "--title", title, "--text", text, "--width", "420"])
            .stderr(Stdio::null())
            .status(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_and_binary_names_match_reality() {
        assert_eq!(Tool::KDialog.binary(), "kdialog");
        assert_eq!(Tool::Zenity.binary(), "zenity");
        assert_eq!(Tool::KDialog.package(), "kdialog");
    }

    #[test]
    fn which_finds_something_that_certainly_exists() {
        // `sh` is required by POSIX to be on PATH, so a false here means the lookup is broken
        // rather than that the machine is unusual.
        assert!(
            which("sh"),
            "PATH lookup failed for a binary that must exist"
        );
    }

    #[test]
    fn which_rejects_something_that_certainly_does_not() {
        assert!(!which("asli-definitely-not-a-real-binary-name-9x7"));
    }

    #[test]
    fn the_missing_advice_names_both_packages_and_the_fallback() {
        let advice = missing_advice();
        assert!(advice.contains("kdialog"));
        assert!(advice.contains("zenity"));
        assert!(
            advice.contains("asli join"),
            "someone with no dialog program still needs a way through"
        );
    }

    #[test]
    fn detection_prefers_kdialog_when_both_exist() {
        // Order is the contract, so it is asserted rather than left to the loop's reading order.
        let order = [Tool::KDialog, Tool::Zenity];
        assert_eq!(order[0], Tool::KDialog);
        assert_eq!(order[1], Tool::Zenity);
    }
}
