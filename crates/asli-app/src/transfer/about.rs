//! Telling the other devices which Asli this one runs, and hearing which they run. Also saying
//! goodbye when this device leaves the account, and hearing others do it.

use asli_crypto::about::{About, Leave};
use asli_net::client::{LocalEvent, MsgKind};

use super::{send_msg, State};

/// Says which Asli this is: to the room, asking everyone back, or to one connection in reply.
pub(super) fn announce(state: &State, ask: bool, to: Option<&str>) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Some(reply_to) = link.conn_id.clone() else {
        return;
    };
    let about = About {
        from_device_id: link.device_id,
        ask,
        reply_to,
        build: 0,
        version: crate::VERSION.to_owned(),
    };
    let Ok(body) = about.encode(&link.keys(), &link.room) else {
        return;
    };
    let _ = match to {
        Some(to) => send_msg(link, MsgKind::About, body, to),
        None => link
            .tx
            .try_send(LocalEvent::Message {
                kind: MsgKind::About,
                body,
                to: None,
                token: None,
            })
            .map_err(|_| String::new()),
    };
}

/// Another device said which Asli it runs. Answers with this one's when it asks.
pub(super) fn on_about(state: &State, body: &[u8]) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Ok(from) = About::claimed_sender(body) else {
        return;
    };
    if from == link.device_id {
        return;
    }
    let Some(pinned) = state
        .devices
        .pinned()
        .into_iter()
        .find(|device| device.device_id == from)
    else {
        return;
    };
    let Ok(about) = About::decode(body, &link.room, &pinned.sign_pub) else {
        return;
    };
    state
        .devices
        .heard_version(&about.from_device_id, &about.version, about.build);
    if about.ask {
        announce(state, false, Some(&about.reply_to));
    }
}

/// Token of the goodbye, to know when the relay has read it.
pub(super) const LEAVE_TOKEN: u64 = u64::MAX - 8;

/// Tells the room this device is leaving. Returns whether it went into the queue.
pub(super) fn say_leaving(state: &State) -> bool {
    let Some(link) = state.link.as_ref() else {
        return false;
    };
    if link.conn_id.is_none() {
        return false;
    }
    let body = Leave {
        from_device_id: link.device_id,
        ts_ms: asli_net::client::now_ms(),
    }
    .encode(&link.keys(), &link.room);
    link.tx
        .try_send(LocalEvent::Message {
            kind: MsgKind::Leave,
            body,
            to: None,
            token: Some(LEAVE_TOKEN),
        })
        .is_ok()
}

/// Another device left the account: it comes off the list.
pub(super) fn on_leave(state: &mut State, body: &[u8]) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Ok(from) = About::claimed_sender(body) else {
        return;
    };
    let Some(pinned) = state
        .devices
        .pinned()
        .into_iter()
        .find(|device| device.device_id == from)
    else {
        return;
    };
    if Leave::decode(body, &link.room, &pinned.sign_pub).is_err() {
        return;
    }
    eprintln!(
        "{}",
        crate::clipboard_io::log_line("device_left", &pinned.name)
    );
    state.devices.forget(&from);
}
