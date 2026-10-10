//! Telling the other devices which Asli this one runs, and hearing which they run.

use asli_crypto::about::About;
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
        build: crate::build_number(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
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
