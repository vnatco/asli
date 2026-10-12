//! Where on the screen Asli's small corner window goes, worked out before it is shown.
//!
//! A window positioned only after it is shown is positioned too late on Windows and macOS: the
//! native window does not exist yet at that moment, so the position is dropped and the system's
//! default, the top left corner, is where it appears. Asking the system for its usable area first
//! lets the position be given to the window before it is made.
//!
//! # The unsafe calls
//!
//! On Windows the work area comes from two Win32 functions, which Rust can only call as foreign
//! code. They live here, in a crate of their own, so the application keeps
//! `#![forbid(unsafe_code)]`, and each call carries its safety argument where it is made.

#![deny(unsafe_code)]

/// A top left corner for a window, in the units the window system places windows in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Corner {
    /// Physical pixels, as on Windows.
    Physical {
        /// From the left of the desktop.
        x: i32,
        /// From the top of the desktop.
        y: i32,
    },
    /// Logical pixels, points on macOS.
    Logical {
        /// From the left of the desktop.
        x: f32,
        /// From the top of the desktop.
        y: f32,
    },
}

/// The top left corner, in the window system's own units, at which a window of `width` by
/// `height` logical pixels sits `margin` logical pixels in from the bottom right of the usable
/// area of the main screen: the taskbar, the dock and the menu bar left clear, wherever they are.
///
/// Physical pixels on Windows, points on macOS. `None` where the system cannot say, or anywhere
/// else, where the caller places the window once it exists.
#[must_use]
pub fn bottom_right(width: f32, height: f32, margin: f32) -> Option<Corner> {
    imp::bottom_right(width, height, margin)
}

#[cfg(target_os = "windows")]
mod imp {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;
    use windows_sys::Win32::UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETWORKAREA};

    pub fn bottom_right(width: f32, height: f32, margin: f32) -> Option<crate::Corner> {
        let mut area = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: SPI_GETWORKAREA writes one RECT through the pointer, which points at a RECT that
        // lives for the whole call. The other arguments are unused for this action.
        #[allow(unsafe_code)]
        let got = unsafe {
            SystemParametersInfoW(SPI_GETWORKAREA, 0, std::ptr::from_mut(&mut area).cast(), 0)
        };
        if got == 0 {
            return None;
        }
        // The process is per monitor DPI aware, so the work area is in physical pixels, and the
        // window's logical size is scaled by the primary monitor's DPI to match.
        // SAFETY: takes no arguments and only reads the system setting.
        #[allow(unsafe_code)]
        let dpi = unsafe { GetDpiForSystem() };
        #[allow(clippy::cast_precision_loss)]
        let scale = if dpi == 0 { 1.0 } else { dpi as f32 / 96.0 };
        #[allow(clippy::cast_possible_truncation)]
        let px = |logical: f32| (logical * scale).round() as i32;
        Some(crate::Corner::Physical {
            x: area.right - px(width) - px(margin),
            y: area.bottom - px(height) - px(margin),
        })
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSScreen;

    pub fn bottom_right(width: f32, height: f32, margin: f32) -> Option<crate::Corner> {
        let main_thread = MainThreadMarker::new()?;
        // The visible frame leaves out the menu bar and the dock. Cocoa measures from the bottom
        // left of the first screen, with y going up; windows are placed from the top left, with y
        // going down, so the first screen's height turns one into the other.
        let screen = NSScreen::mainScreen(main_thread)?;
        let visible = screen.visibleFrame();
        let first = NSScreen::screens(main_thread).firstObject()?.frame();
        #[allow(clippy::cast_possible_truncation)]
        let (x, top) = (
            (visible.origin.x + visible.size.width) as f32 - width - margin,
            (first.size.height - visible.origin.y) as f32 - height - margin,
        );
        Some(crate::Corner::Logical { x, y: top })
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod imp {
    pub const fn bottom_right(_width: f32, _height: f32, _margin: f32) -> Option<crate::Corner> {
        None
    }
}
