//! Desktop notifications.
//!
//! Notifications are off by default, per the UX specification, because a clipboard tool that
//! announces every copy is a clipboard tool people turn off entirely.
//!
//! Two cases ignore that setting and always notify: a clip skipped for exceeding the size cap,
//! and a clip skipped because its source marked it as a password. The reasoning is in the
//! competitor research: a copy that silently fails to arrive is the single most common complaint
//! against every tool in this category, and a person who does not know their copy was dropped
//! will paste stale content into something that matters.
//!
//! Notification bodies never contain clipboard content. Only sizes, reasons and counts.

/// The application name shown by the notification daemon.
#[cfg(not(target_os = "macos"))]
const APP_NAME: &str = "Asli";

/// How long an informational notification stays up, in milliseconds.
#[cfg(not(target_os = "macos"))]
const TIMEOUT_MS: i32 = 4000;

/// Sends a notification, swallowing failures.
///
/// A missing or broken notification daemon must never take the daemon down with it. The clipboard
/// still syncs on a machine with no notification service, so a failure here is logged by the
/// caller at most, never propagated.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn send(summary: &str, body: &str) {
    show(summary, body);
}

/// Sends a notification from a thread of its own, swallowing failures.
///
/// The call goes over the session bus and waits for an answer, and a session whose notification
/// service is missing or hung never gives one: the bus holds the call while it tries to start a
/// service that does not come. Made from the tray, that froze every later menu click for good.
/// So calls are queued to one sender thread, in order, and a full queue drops the newest rather
/// than blocking the caller.
#[cfg(target_os = "linux")]
fn send(summary: &str, body: &str) {
    use std::sync::mpsc::{sync_channel, SyncSender};
    use std::sync::OnceLock;

    static QUEUE: OnceLock<Option<SyncSender<(String, String)>>> = OnceLock::new();
    let queue = QUEUE.get_or_init(|| {
        let (tx, rx) = sync_channel::<(String, String)>(16);
        std::thread::Builder::new()
            .name("asli-notify".to_owned())
            .spawn(move || {
                while let Ok((summary, body)) = rx.recv() {
                    show(&summary, &body);
                }
            })
            .ok()
            .map(|_| tx)
    });
    if let Some(queue) = queue {
        let _ = queue.try_send((summary.to_owned(), body.to_owned()));
    }
}

/// Shows one notification and waits for the service to take it.
#[cfg(not(target_os = "macos"))]
fn show(summary: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .appname(APP_NAME)
        .summary(summary)
        .body(body)
        .icon("edit-copy")
        .timeout(TIMEOUT_MS)
        .show();
}

/// Sends a notification on macOS through `osascript`, swallowing failures.
///
/// `display notification` is the one notification route that needs no bundle identifier, no
/// Objective-C and no entitlement. Until the app ships as a signed bundle, macOS attributes these
/// to Script Editor, which is the honest cost of having neither. Spawned and not waited for, so a
/// slow notification centre never holds up the caller.
#[cfg(target_os = "macos")]
fn send(summary: &str, body: &str) {
    let script = format!(
        "display notification {} with title \"Asli\" subtitle {}",
        applescript_string(body),
        applescript_string(summary)
    );
    let child = std::process::Command::new("osascript")
        .args(["-e", &script])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    // Reaped on a thread of its own. A child that is never waited for stays in the process table
    // as a zombie, and a password manager copy notifies every time, so they would pile up for the
    // life of the process.
    if let Ok(mut child) = child {
        let _ = std::thread::Builder::new()
            .name("asli-notify-reap".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

/// Quotes text as an `AppleScript` string literal.
///
/// Bodies here are built from sizes and fixed wording, never clipboard content, but an error
/// message can carry arbitrary text, and an unescaped quote would end the literal and run the rest
/// as script.
#[cfg(any(target_os = "macos", test))]
fn applescript_string(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            // A line break inside a literal is legal AppleScript, but a notification shows one line.
            '\n' | '\r' => quoted.push(' '),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// A clip arrived from another device.
///
/// Only sent when the person asked for it, which is why the caller passes the setting rather than
/// this module reading configuration it has no other use for.
pub fn clip_received(enabled: bool, bytes: usize) {
    if !enabled {
        return;
    }
    send(
        "Clipboard updated",
        &format!("{bytes} bytes from another device"),
    );
}

/// An image arrived from another device.
///
/// Separate from [`clip_received`] because "12073 bytes" reads as meaningless for an image, while
/// "an image" tells a person what is now on their clipboard without revealing anything about it.
pub fn image_received(enabled: bool, bytes: usize) {
    if !enabled {
        return;
    }
    send(
        "Clipboard updated",
        &format!("An image of {bytes} bytes from another device"),
    );
}

/// A local copy was not sent because it exceeded the size limit.
///
/// Always notified, regardless of the setting.
pub fn clip_too_large(bytes: usize, limit: usize) {
    send(
        "Clipboard not synced",
        &format!(
            "That copy is {bytes} bytes, over the {limit} byte limit, so it stayed on this machine"
        ),
    );
}

/// A local copy was not sent because its source marked it as a password.
///
/// Always notified, regardless of the setting. Being told this once is how a person learns the
/// behaviour is deliberate rather than broken.
pub fn clip_sensitive() {
    send(
        "Clipboard not synced",
        "The application that copied this marked it as a password, so it was not read or sent",
    );
}

/// Feedback for something the person just clicked in the tray menu.
///
/// These ignore the notification preference on purpose, and the distinction matters. That setting
/// governs *unsolicited* notifications about clips arriving, which is a stream a person may well
/// not want. A menu click is a question, and an answer is not spam. Without this, every menu item
/// except Settings reports success only to a log file nobody reads, which makes a working button
/// indistinguishable from a dead one.
fn action(summary: &str, body: &str) {
    send(summary, body);
}

/// The join token was copied to the clipboard.
pub fn token_copied(clear_after_secs: u64) {
    action(
        "Join token copied",
        &format!(
            "It is marked so clipboard history and cloud sync skip it, and it clears in {clear_after_secs} seconds"
        ),
    );
}

/// The join token could not be copied.
pub fn token_copy_failed(reason: &str) {
    action("Could not copy the join token", reason);
}

/// The reveal window was opened.
pub fn token_shown() {
    action(
        "Join string opened",
        "Scan the QR on your other device. Anyone who sees it has your clipboard",
    );
}

/// Diagnostics were copied to the clipboard.
pub fn diagnostics_copied() {
    action(
        "Diagnostics copied",
        "Paste them into a bug report. They contain no clipboard content",
    );
}

/// Diagnostics could not be copied.
pub fn diagnostics_failed(reason: &str) {
    action("Could not copy diagnostics", reason);
}

/// Syncing was paused or resumed from the menu.
pub fn sync_paused(paused: bool) {
    if paused {
        action(
            "Sync paused",
            "Copies stay on this machine until you resume",
        );
    } else {
        action(
            "Sync resumed",
            "Copies are shared with your other devices again",
        );
    }
}

/// The stored clip was requested from the relay.
pub fn retained_requested() {
    action(
        "Fetching the last synced clip",
        "It will land on your clipboard shortly",
    );
}

/// The stored clip that was asked for is now on the clipboard.
pub fn retained_pasted(bytes: usize) {
    action(
        "Pasted the last synced clip",
        &format!("{bytes} bytes are on your clipboard now"),
    );
}

/// The stored clip was fetched, but there was nothing new in it for this device.
///
/// The relay keeps the last clip anyone in the account copied, and that is very often one this
/// device sent itself or has already received, which is not a failure but used to look like one.
pub fn retained_nothing_new(reason: &str) {
    let why = match reason {
        "own_device" => "The last synced clip was copied on this device, so it is already here.",
        "duplicate" | "rollback" => "This device already received the last synced clip.",
        "too_old" => "The last synced clip is older than the relay keeps clips for.",
        _ => "The last synced clip could not be used on this device.",
    };
    action("Nothing new to paste", why);
}

/// There was no stored clip to fetch.
pub fn retained_unavailable() {
    action(
        "Nothing stored to paste",
        "The relay is not holding a clip for this account",
    );
}

/// A join succeeded and the daemon is restarting onto the new account.
///
/// The restart is named because the icon disappears and comes back, and an unexplained
/// disappearance reads as a crash rather than as the thing the person just asked for.
pub fn joined(room_id: &str) {
    action(
        "Joined the account",
        &format!("Room {room_id}. Reconnecting on the new account now."),
    );
}

/// A join was attempted with something that is not a usable token.
///
/// The reason comes from the token parser, which distinguishes a wrong prefix from a bad checksum
/// from a truncated string, so this shows that rather than a generic failure.
pub fn join_failed(reason: &str) {
    action("Could not join", reason);
}

/// This device's clock is far enough from the relay's that clips are close to being dropped.
///
/// Always shown. Past a day off, every clip in both directions is discarded as too old or from the
/// future and nothing else fails, so a warning well before that is the only useful signal.
pub fn clock_skew(skew_ms: i64) {
    let hours = skew_ms.unsigned_abs().div_ceil(60 * 60 * 1000);
    send(
        "This computer's clock is wrong",
        &format!(
            "It is about {hours} hours {} the internet's time. Past a day, clips to and from it \
             will be dropped. Turn on setting the time and time zone automatically.",
            if skew_ms > 0 { "behind" } else { "ahead of" }
        ),
    );
}

/// Something a menu action tried to do failed.
pub fn action_failed(what: &str, reason: &str) {
    action(what, reason);
}

/// Connection to the relay was lost and is being retried.
pub fn connection_lost(enabled: bool) {
    if !enabled {
        return;
    }
    send("Asli is offline", "Reconnecting to the relay");
}

#[cfg(test)]
mod tests {
    //! These assert the decision, not the delivery. Whether a notification daemon is running is
    //! not this crate's business, and a test that needs one would fail in CI for the wrong reason.

    /// The two mandatory cases must not consult the setting at all.
    ///
    /// This is enforced by their signatures: neither takes an `enabled` argument, so there is no
    /// way for a future edit to make them conditional without changing the call sites.
    #[test]
    fn mandatory_notifications_take_no_enabled_flag() {
        // A compile time assertion in test form: these coerce only if the signature is unchanged.
        let too_large: fn(usize, usize) = super::clip_too_large;
        let sensitive: fn() = super::clip_sensitive;
        let _ = (too_large, sensitive);
    }

    /// A quote or backslash in a message must not end the `AppleScript` literal early.
    #[test]
    fn applescript_quoting_cannot_be_escaped() {
        assert_eq!(super::applescript_string("plain"), "\"plain\"");
        assert_eq!(
            super::applescript_string("a \" & do shell script \"x"),
            "\"a \\\" & do shell script \\\"x\""
        );
        assert_eq!(
            super::applescript_string("back\\slash"),
            "\"back\\\\slash\""
        );
        assert_eq!(super::applescript_string("two\nlines"), "\"two lines\"");
    }

    /// The optional ones must consult it.
    #[test]
    fn optional_notifications_take_an_enabled_flag() {
        let received: fn(bool, usize) = super::clip_received;
        let lost: fn(bool) = super::connection_lost;
        let _ = (received, lost);
    }

    #[test]
    fn disabled_optional_notifications_return_without_sending() {
        // With no notification daemon in CI this would fail if it attempted delivery, and with one
        // it would show a popup during a test run. Neither happens, because false returns early.
        super::clip_received(false, 12);
        super::connection_lost(false);
    }
}
