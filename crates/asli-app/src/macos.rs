//! The one piece of `AppKit` the application itself needs, as opposed to the pasteboard.

use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

/// Makes this process a menu bar accessory: no Dock icon, no application switcher entry.
///
/// Does nothing off the main thread, where `AppKit` may not be touched at all.
pub fn become_accessory() {
    let Some(main_thread) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(main_thread);
    let _ = app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
}
