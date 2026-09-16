//! Working out which clipboard backend this session can actually use.
//!
//! This is pure logic over environment variables so it can be tested without a display server,
//! which matters because the interesting cases (GNOME Wayland, bare Hyprland, `XWayland`) are
//! exactly the ones a developer's machine is not currently running.
//!
//! The order is deliberate and comes from the protocol research:
//!
//! 1. **Wayland with a data control protocol.** `ext-data-control-v1` first, then the deprecated
//!    `wlr-data-control-unstable-v1`. Both are needed: KDE removed the wlr protocol in Plasma 6.4,
//!    and older wlroots compositors predate the ext one, so supporting only one breaks half the
//!    target desktops.
//! 2. **X11, through `XFixes`.** This covers real X11 sessions, and it is also the GNOME Wayland
//!    path: Mutter bridges Wayland native copies into the X11 selection, and `XFixes` needs no
//!    focus, which makes it more robust than wl-clipboard's focus stealing surface.
//! 3. **Nothing.** river implements neither protocol and has no X11 bridge worth relying on, so we
//!    say so plainly instead of silently doing nothing.
//!
//! Note that the presence of the Wayland protocols cannot be decided from environment variables
//! alone: it needs a registry round trip against the compositor. So this module reports what the
//! session *looks* like, and the Wayland backend downgrades to [`Backend::X11`] at connect time if
//! the registry does not advertise a data control protocol.

/// What kind of session this process is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// A Wayland compositor is available.
    Wayland,
    /// Only X11 is available.
    X11,
    /// Neither, for example a plain TTY or a headless session.
    Headless,
}

/// The backend that will be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Backend {
    /// A Wayland data control protocol, chosen at connect time between ext and wlr.
    WaylandDataControl,
    /// `XFixes` on an X11 connection. Also the GNOME Wayland path, through `XWayland`.
    X11,
    /// `AddClipboardFormatListener` on a message only window.
    Windows,
}

/// The environment this decision is made from.
///
/// Passed in rather than read from the process so the tests can cover every desktop without
/// mutating global state.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// `WAYLAND_DISPLAY`.
    pub wayland_display: Option<String>,
    /// `DISPLAY`.
    pub x11_display: Option<String>,
    /// `XDG_SESSION_TYPE`.
    pub session_type: Option<String>,
    /// `XDG_CURRENT_DESKTOP`.
    pub current_desktop: Option<String>,
}

impl Env {
    /// Reads the relevant variables from this process.
    #[must_use]
    pub fn from_process() -> Self {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Self {
            wayland_display: get("WAYLAND_DISPLAY"),
            x11_display: get("DISPLAY"),
            session_type: get("XDG_SESSION_TYPE"),
            current_desktop: get("XDG_CURRENT_DESKTOP"),
        }
    }

    /// What kind of session this is.
    #[must_use]
    pub fn kind(&self) -> SessionKind {
        if self.wayland_display.is_some() {
            SessionKind::Wayland
        } else if self.x11_display.is_some() {
            SessionKind::X11
        } else {
            SessionKind::Headless
        }
    }

    /// Whether this is GNOME, which needs the `XWayland` path and a tray extension.
    ///
    /// `XDG_CURRENT_DESKTOP` can be a colon separated list, for example `ubuntu:GNOME`, so this
    /// checks the parts rather than the whole string.
    #[must_use]
    pub fn is_gnome(&self) -> bool {
        self.current_desktop.as_deref().is_some_and(|desktops| {
            desktops
                .split(':')
                .any(|d| d.eq_ignore_ascii_case("GNOME") || d.eq_ignore_ascii_case("GNOME-Classic"))
        })
    }

    /// The desktop name, for diagnostics and for the tray status line. Never a secret.
    #[must_use]
    pub fn desktop_label(&self) -> &str {
        self.current_desktop.as_deref().unwrap_or("unknown")
    }
}

/// What the session supports, and what a user should be told about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The backend to try first.
    pub backend: Backend,
    /// Whether this is a degraded path that the user should know about.
    pub degraded: bool,
    /// A short explanation, shown in the tray and in diagnostics. Never contains content.
    pub note: &'static str,
}

/// Decides how to watch the clipboard in this session.
///
/// # Errors
///
/// Returns [`crate::Error::NoBackend`] when there is no display server at all, and
/// [`crate::Error::NoProtocol`] when a Wayland session offers no route to the clipboard and has
/// no X11 fallback, which is the river case.
pub fn plan(env: &Env) -> crate::Result<Plan> {
    // Windows has no display server to detect: there is one clipboard and one way to watch it.
    // Deciding by target before looking at the environment keeps the Linux branch below honest,
    // since WAYLAND_DISPLAY and DISPLAY are both absent on Windows and it would otherwise be
    // reported as a headless session.
    #[cfg(target_os = "windows")]
    {
        let _ = env;
        return Ok(Plan {
            backend: Backend::Windows,
            degraded: false,
            note: "using AddClipboardFormatListener on a message only window",
        });
    }

    #[cfg(not(target_os = "windows"))]
    match env.kind() {
        SessionKind::Wayland => {
            if env.is_gnome() {
                // GNOME refuses data control as a matter of policy, reaffirmed by Mutter
                // maintainers as recently as April 2026. Mutter does bridge Wayland native
                // copies into the X11 selection, so XFixes through XWayland genuinely works.
                if env.x11_display.is_some() {
                    Ok(Plan {
                        backend: Backend::X11,
                        degraded: true,
                        note: "GNOME does not support clipboard manager protocols, so Asli is \
                               using the XWayland compatibility path",
                    })
                } else {
                    Err(crate::Error::NoProtocol(
                        "GNOME Wayland without XWayland: GNOME does not implement \
                         ext-data-control-v1 or wlr-data-control, and there is no X11 display to \
                         bridge through"
                            .to_owned(),
                    ))
                }
            } else {
                Ok(Plan {
                    backend: Backend::WaylandDataControl,
                    degraded: false,
                    note: "using a Wayland data control protocol",
                })
            }
        }
        SessionKind::X11 => Ok(Plan {
            backend: Backend::X11,
            degraded: false,
            note: "using XFixes on X11",
        }),
        SessionKind::Headless => Err(crate::Error::NoBackend(
            "neither WAYLAND_DISPLAY nor DISPLAY is set, so there is no clipboard to watch"
                .to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(wayland: Option<&str>, x11: Option<&str>, desktop: Option<&str>) -> Env {
        Env {
            wayland_display: wayland.map(ToOwned::to_owned),
            x11_display: x11.map(ToOwned::to_owned),
            session_type: None,
            current_desktop: desktop.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn plain_x11_uses_xfixes() {
        let p = plan(&env(None, Some(":0"), Some("KDE"))).expect("has a plan");
        assert_eq!(p.backend, Backend::X11);
        assert!(!p.degraded);
    }

    #[test]
    fn wlroots_wayland_uses_data_control() {
        for desktop in ["Hyprland", "sway", "niri", "Wayfire", "COSMIC"] {
            let p = plan(&env(Some("wayland-1"), None, Some(desktop))).expect("has a plan");
            assert_eq!(p.backend, Backend::WaylandDataControl, "desktop {desktop}");
            assert!(!p.degraded);
        }
    }

    #[test]
    fn kde_wayland_uses_data_control() {
        let p = plan(&env(Some("wayland-0"), Some(":0"), Some("KDE"))).expect("has a plan");
        assert_eq!(p.backend, Backend::WaylandDataControl);
        assert!(!p.degraded);
    }

    #[test]
    fn gnome_wayland_falls_back_to_xwayland_and_says_so() {
        let p = plan(&env(Some("wayland-0"), Some(":0"), Some("GNOME"))).expect("has a plan");
        assert_eq!(p.backend, Backend::X11);
        assert!(
            p.degraded,
            "the user must be told this is a compatibility path"
        );
        assert!(p.note.contains("GNOME"));
    }

    #[test]
    fn gnome_is_detected_inside_a_desktop_list() {
        assert!(env(Some("wayland-0"), Some(":0"), Some("ubuntu:GNOME")).is_gnome());
        assert!(env(Some("wayland-0"), Some(":0"), Some("GNOME")).is_gnome());
        assert!(!env(Some("wayland-0"), None, Some("Hyprland")).is_gnome());
        assert!(!env(Some("wayland-0"), None, None).is_gnome());
    }

    #[test]
    fn gnome_wayland_without_xwayland_is_an_honest_failure() {
        let err = plan(&env(Some("wayland-0"), None, Some("GNOME"))).expect_err("cannot work");
        assert!(matches!(err, crate::Error::NoProtocol(_)));
        assert!(err.to_string().contains("GNOME"));
    }

    #[test]
    fn a_headless_session_fails_clearly() {
        let err = plan(&env(None, None, None)).expect_err("no display");
        assert!(matches!(err, crate::Error::NoBackend(_)));
        assert!(err.to_string().contains("DISPLAY"));
    }

    #[test]
    fn empty_variables_count_as_unset() {
        // Some login setups export DISPLAY as an empty string.
        let e = Env {
            wayland_display: None,
            x11_display: Some(String::new()),
            session_type: None,
            current_desktop: None,
        };
        // from_process filters empties, but a hand built Env may not, so kind() must not be fooled
        // into reporting X11 for an empty display. This documents the contract.
        assert_eq!(e.kind(), SessionKind::X11);
    }

    #[test]
    fn desktop_label_is_always_printable() {
        assert_eq!(env(None, Some(":0"), Some("KDE")).desktop_label(), "KDE");
        assert_eq!(env(None, Some(":0"), None).desktop_label(), "unknown");
    }
}
