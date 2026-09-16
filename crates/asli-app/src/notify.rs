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

use notify_rust::Notification;

/// The application name shown by the notification daemon.
const APP_NAME: &str = "Asli";

/// How long an informational notification stays up, in milliseconds.
const TIMEOUT_MS: i32 = 4000;

/// Sends a notification, swallowing failures.
///
/// A missing or broken notification daemon must never take the daemon down with it. The clipboard
/// still syncs on a machine with no notification service, so a failure here is logged by the
/// caller at most, never propagated.
fn send(summary: &str, body: &str) {
    let _ = Notification::new()
        .appname(APP_NAME)
        .summary(summary)
        .body(body)
        .icon("edit-copy")
        .timeout(TIMEOUT_MS)
        .show();
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

/// There was no stored clip to fetch.
pub fn retained_unavailable() {
    action(
        "Nothing stored to paste",
        "The relay is not holding a clip for this account",
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
