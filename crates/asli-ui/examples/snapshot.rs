//! Renders every screen of the window to a PNG, with sample data, without opening a window.
//!
//! For reviewing the markup against the design: the screens are drawn by the same software
//! renderer the application uses, at the design's 880 by 600, so a screenshot here is what a
//! person would see.
//!
//! ```sh
//! cargo run -p asli-ui --example snapshot -- /tmp/asli-shots
//! ```

use std::rc::Rc;

use asli_ui::{
    AppWindow, AskRow, DeviceRow, FileRow, HistoryRow, InviteState, ReadyFile, ReadyTarget, Screen,
    SyncState, TokenCheck,
};
use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType,
};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle as _, Model as _, ModelRc, SharedString, VecModel};

struct Offscreen {
    window: Rc<MinimalSoftwareWindow>,
}

impl Platform for Offscreen {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.window.clone())
    }
}

/// Puts the window into the state one screenshot shows.
type Setup = Box<dyn Fn(&AppWindow)>;

const WIDTH: u32 = 880;
const HEIGHT: u32 = 600;

/// The height to render at: the design's, or `ASLI_SNAPSHOT_HEIGHT` to see the foot of a long
/// screen.
fn height() -> u32 {
    std::env::var("ASLI_SNAPSHOT_HEIGHT")
        .ok()
        .and_then(|h| h.parse().ok())
        .unwrap_or(HEIGHT)
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "shots".to_owned());
    std::fs::create_dir_all(&out).expect("output directory");

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    window.set_size(slint::PhysicalSize::new(WIDTH, height()));
    slint::platform::set_platform(Box::new(Offscreen {
        window: window.clone(),
    }))
    .expect("platform");

    let shots: Vec<(&str, Setup)> = vec![
        (
            "01-first-run",
            Box::new(|ui: &AppWindow| {
                ui.set_has_account(false);
                ui.set_screen(Screen::FirstRun);
            }),
        ),
        (
            "02-first-run-creating",
            Box::new(|ui: &AppWindow| {
                ui.set_has_account(false);
                ui.set_creating(true);
                ui.set_screen(Screen::FirstRun);
            }),
        ),
        (
            "03-join",
            Box::new(|ui: &AppWindow| {
                ui.set_has_account(false);
                ui.set_join_input(SAMPLE_TOKEN.into());
                ui.set_join_check(TokenCheck {
                    valid: true,
                    invalid: false,
                    message: SharedString::new(),
                });
                ui.set_screen(Screen::Join);
            }),
        ),
        (
            "04-join-invalid",
            Box::new(|ui: &AppWindow| {
                ui.set_has_account(false);
                ui.set_join_input("asli1_04SJTBY11JG60WFJWN0SA9X57WPR8E637CXZVRSW".into());
                ui.set_join_check(TokenCheck {
                    valid: false,
                    invalid: true,
                    message: "This looks cut off. Copy the whole string, including the end.".into(),
                });
                ui.set_screen(Screen::Join);
            }),
        ),
        (
            "04b-join-waiting",
            Box::new(|ui: &AppWindow| {
                ui.set_has_account(false);
                ui.set_screen(Screen::Join);
                ui.set_join_waiting(true);
                ui.set_join_comparison("482 913".into());
            }),
        ),
        (
            "05-add-device-idle",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Token);
                ui.set_invite_state(InviteState::Idle);
            }),
        ),
        (
            "05b-add-device-asked",
            Box::new(|ui: &AppWindow| ui.set_screen(Screen::Token)),
        ),
        (
            "05c-add-device-done",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Token);
                ui.set_invite_state(InviteState::Finished);
                ui.set_invite_good(true);
                ui.set_invite_message("DESKTOP-7Q is joining now.".into());
            }),
        ),
        (
            "06-history",
            Box::new(|ui: &AppWindow| ui.set_screen(Screen::History)),
        ),
        (
            "07-history-empty",
            Box::new(|ui: &AppWindow| {
                ui.set_history(ModelRc::new(VecModel::from(Vec::<HistoryRow>::new())));
                ui.set_screen(Screen::History);
            }),
        ),
        (
            "08-status",
            Box::new(|ui: &AppWindow| ui.set_screen(Screen::Status)),
        ),
        (
            "08b-status-key-exposed",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Status);
                ui.set_key_exposed(true);
            }),
        ),
        (
            "08c-status-confirm-remove",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Status);
                ui.set_confirm_title("Remove fedora-desk?".into());
                ui.set_confirm_body("It stops receiving anything from this account at once. Your other devices get a new account key, so nothing it kept will work again. fedora-desk will need to join again: offline now, or running an older Asli.".into());
                ui.set_confirm_action("Remove".into());
            }),
        ),
        (
            "08d-status-offer",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Status);
                ui.set_status_badge(1);
                ui.set_offer_waiting(true);
                ui.set_offer_from("MacBook-Air".into());
                ui.set_offer_name("Quarterly report final.pdf".into());
                ui.set_offer_size("3.4 MB".into());
                sample_files(ui);
            }),
        ),
        (
            "05d-add-device-nearby",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Token);
                ui.set_invite_state(InviteState::Waiting);
                ui.set_invite_asking(ModelRc::new(VecModel::from(Vec::<AskRow>::new())));
                ui.set_invite_nearby_only(true);
            }),
        ),
        (
            "12b-settings-same-network",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Settings);
                ui.set_same_network_only(true);
            }),
        ),
        (
            "08e-home-ready",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Status);
                ui.set_ready_files(ModelRc::new(VecModel::from(vec![
                    ReadyFile {
                        name: "holiday-photos.zip".into(),
                        size: "212 MB".into(),
                    },
                    ReadyFile {
                        name: "Quarterly report final.pdf".into(),
                        size: "3.4 MB".into(),
                    },
                    ReadyFile {
                        name: "notes.md".into(),
                        size: "4 KB".into(),
                    },
                ])));
                ui.set_ready_summary("3 Files  ·  215.4 MB".into());
                ui.set_ready_targets(ModelRc::new(VecModel::from(vec![
                    ReadyTarget {
                        name: "MacBook Pro".into(),
                        sent: true,
                    },
                    ReadyTarget {
                        name: "DESKTOP-7Q".into(),
                        sent: false,
                    },
                ])));
            }),
        ),
        (
            "08f-status-drop-hover",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Status);
                ui.set_drop_hover(true);
            }),
        ),
        (
            "08h-status-update",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Status);
                ui.set_update_note("MacBook Pro runs Asli 0.1.2; this device runs 0.1.1. Update Asli here to keep up.".into());
            }),
        ),
        (
            "12c-settings-confirm-leave",
            Box::new(|ui: &AppWindow| {
                ui.set_screen(Screen::Settings);
                ui.set_confirm_leave(true);
            }),
        ),
        (
            "09-status-connecting",
            Box::new(|ui: &AppWindow| {
                ui.set_sync_state(SyncState::Connecting);
                ui.set_state_label("Connecting…".into());
                ui.set_state_detail("Reaching asli.vnat.dev, attempt 2".into());
                ui.set_screen(Screen::Status);
            }),
        ),
        (
            "10-status-paused",
            Box::new(|ui: &AppWindow| {
                ui.set_sync_state(SyncState::Offline);
                ui.set_paused(true);
                ui.set_state_label("Paused".into());
                ui.set_state_detail(
                    "Paused by you. Nothing is sent or received until you resume.".into(),
                );
                ui.set_screen(Screen::Status);
            }),
        ),
        (
            "11-status-error",
            Box::new(|ui: &AppWindow| {
                ui.set_sync_state(SyncState::Error);
                ui.set_state_label("Connection failed".into());
                ui.set_state_detail("Couldn't reach the relay. Retrying in 24s.".into());
                ui.set_has_retained(true);
                ui.set_screen(Screen::Status);
            }),
        ),
        (
            "12-settings",
            Box::new(|ui: &AppWindow| ui.set_screen(Screen::Settings)),
        ),
        (
            "13-settings-dirty",
            Box::new(|ui: &AppWindow| {
                ui.set_relay_url("https://example.com".into());
                ui.set_keep_history(false);
                ui.set_screen(Screen::Settings);
            }),
        ),
    ];

    for (name, setup) in shots {
        let ui = AppWindow::new().expect("window");
        sample(&ui);
        setup(&ui);
        ui.show().expect("show");
        // Twice, so anything laid out on the first pass settles before the second is captured.
        render(&window);
        let pixels = render(&window);
        write_png(&format!("{out}/{name}.png"), &pixels);
        ui.hide().expect("hide");
        println!("{out}/{name}.png");
    }
}

fn render(window: &MinimalSoftwareWindow) -> Vec<PremultipliedRgbaColor> {
    slint::platform::update_timers_and_animations();
    let mut buffer = vec![PremultipliedRgbaColor::default(); (WIDTH * height()) as usize];
    window.request_redraw();
    window.draw_if_needed(|renderer| {
        renderer.render(&mut buffer, WIDTH as usize);
    });
    buffer
}

fn write_png(path: &str, pixels: &[PremultipliedRgbaColor]) {
    let file = std::fs::File::create(path).expect("png file");
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), WIDTH, height());
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("png header");
    let bytes: Vec<u8> = pixels
        .iter()
        .flat_map(|p| {
            // Composited over the design's page background, so a transparent corner shows as it
            // would on screen rather than as black.
            let a = u16::from(p.alpha);
            let over = |c: u8, bg: u8| (u16::from(c) + (u16::from(bg) * (255 - a)) / 255) as u8;
            [
                over(p.red, 0x07),
                over(p.green, 0x09),
                over(p.blue, 0x0D),
                255,
            ]
        })
        .collect();
    writer.write_image_data(&bytes).expect("png data");
}

const SAMPLE_TOKEN: &str = "asli2_04SJTBY11JG60WFJWN0SA9X57WPR8E63";

fn sample_files(ui: &AppWindow) {
    ui.set_files(ModelRc::new(VecModel::from(vec![
        FileRow {
            name: "holiday-photos.zip".into(),
            peer: "To DESKTOP-7Q".into(),
            detail: "212 MB · 41%".into(),
            progress: 0.41,
            live: true,
            can_show: false,
            good: false,
        },
        FileRow {
            name: "notes.md".into(),
            peer: "From MacBook-Air".into(),
            detail: "4 KB · saved to Downloads".into(),
            progress: 1.0,
            live: false,
            can_show: true,
            good: true,
        },
        FileRow {
            name: "video.mov".into(),
            peer: "To MacBook-Air".into(),
            detail: "1.2 GB · declined".into(),
            progress: 0.0,
            live: false,
            can_show: false,
            good: false,
        },
    ])));
}

fn sample(ui: &AppWindow) {
    ui.set_this_platform(asli_ui::DeviceOs::Linux);
    ui.set_app_version("0.1.13".into());
    ui.set_has_account(true);
    ui.set_sync_state(SyncState::Connected);
    ui.set_state_label("Synced".into());
    ui.set_state_detail("2 devices online · last clip 17 minutes ago".into());
    ui.set_stat_connections("2 Devices".into());
    ui.set_stat_last_sync("17 Minutes Ago".into());
    ui.set_stat_skipped("0".into());
    ui.set_relay_url_live("wss://asli.vnat.dev/v1".into());
    ui.set_room_id("QR8RDM70ZKES".into());
    ui.set_device_id("1695e3615162".into());
    ui.set_clipboard_backend("Wayland, wlr data control".into());
    ui.set_invite_code(SAMPLE_TOKEN.into());
    ui.set_invite_remaining("9:41".into());
    ui.set_invite_left(0.97);
    ui.set_invite_state(InviteState::Waiting);
    ui.set_invite_asking(ModelRc::new(VecModel::from(vec![AskRow {
        name: "DESKTOP-7Q".into(),
        os: "Windows 11".into(),
        platform: asli_ui::DeviceOs::Windows,
        comparison: "482 913".into(),
    }])));
    ui.set_devices(ModelRc::new(VecModel::from(vec![
        DeviceRow {
            name: "ThinkPad X1".into(),
            os: "Arch Linux".into(),
            platform: asli_ui::DeviceOs::Linux,
            id: "1695e3615162".into(),
            seen: "Now".into(),
            online: true,
            this_device: true,
            removable: false,
            can_send: false,
            version: "0.1.1".into(),
            outdated: false,
            forgettable: false,
            send_state: 0,
            send_label: "".into(),
            send_progress: 0.0,
        },
        DeviceRow {
            name: "MacBook Pro".into(),
            os: "macOS 15".into(),
            platform: asli_ui::DeviceOs::Mac,
            id: "a71c0be4d930".into(),
            seen: "Now".into(),
            online: true,
            this_device: false,
            removable: true,
            can_send: true,
            version: "0.1.2".into(),
            outdated: false,
            forgettable: false,
            send_state: 2,
            send_label: "Sending 3 Files · 45%".into(),
            send_progress: 0.45,
        },
        DeviceRow {
            name: "Gaming PC".into(),
            os: "Windows 11".into(),
            platform: asli_ui::DeviceOs::Windows,
            id: "c02f19aa7714".into(),
            seen: "2 Days Ago".into(),
            online: false,
            this_device: false,
            removable: true,
            can_send: false,
            version: "0.1.0".into(),
            outdated: true,
            forgettable: false,
            send_state: 0,
            send_label: "".into(),
            send_progress: 0.0,
        },
    ])));
    let row = |section: &str,
               preview: &str,
               source: &str,
               when: &str,
               meta: &str,
               image: bool,
               mono: bool| HistoryRow {
        section: section.into(),
        preview: preview.into(),
        source: source.into(),
        when: when.into(),
        meta: meta.into(),
        is_image: image,
        mono,
        thumb: slint::Image::default(),
        has_thumb: false,
    };
    ui.set_history(ModelRc::new(VecModel::from(vec![
        row("Today", "Replay protection now survives restarts, so sync no longer depends on the clocks agreeing.", "MacBook Pro", "3 Minutes Ago", "120 bytes", false, false),
        row("", "Image", "This Device", "11 Minutes Ago", "284 KB  ·  1440 × 900", true, false),
        row("", "wss://asli.vnat.dev/v1", "fedora-desk", "26 Minutes Ago", "21 bytes", false, true),
        row("Yesterday", "Tests: 350 pass on Linux, and 336 pass as real Windows binaries under Wine.", "fedora-desk", "A Day Ago", "199 bytes", false, false),
        // A clip of several lines, as the history shows one: on one line, saying how many.
        row("Thursday", "Dear team, the release is tagged. Notes are in the changelog. Thanks all", "This Device", "3 Days Ago", "52 bytes  ·  3 lines", false, false),
    ])));
    ui.set_history_note("Stored on this device only, encrypted with your account key.".into());
    ui.set_relay_url("wss://asli.vnat.dev/v1".into());
    ui.set_saved_relay_url("wss://asli.vnat.dev/v1".into());
    ui.set_device_name("ThinkPad X1".into());
    ui.set_saved_device_name("ThinkPad X1".into());
    ui.set_autostart(true);
    ui.set_autostart_detail("~/.config/autostart/asli.desktop".into());
    // A fake QR: a checkerboard is enough to judge the plate around it.
    let mut qr = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(25, 25);
    for (i, px) in qr.make_mut_slice().iter_mut().enumerate() {
        let dark = (i * 7919 % 13) < 6;
        *px = if dark {
            slint::Rgba8Pixel {
                r: 11,
                g: 14,
                b: 20,
                a: 255,
            }
        } else {
            slint::Rgba8Pixel {
                r: 255,
                g: 255,
                b: 255,
                a: 255,
            }
        };
    }
    ui.set_qr(slint::Image::from_rgba8(qr));
    let _ = ui.get_history().row_count();
}
