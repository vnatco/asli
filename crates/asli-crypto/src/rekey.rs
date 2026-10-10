//! Replacing the account key: how a device is removed, and how an account retires a key that
//! once travelled in an old style join token.
//!
//! Every device holds the account key, so taking one device out means making a new key and giving
//! it to everyone else. One device makes it, seals it to each remaining device's box key, signs the
//! bundle, and sends it in the old room. Each remaining device opens its own entry and moves to the
//! new room the new key names. The removed device, and anyone holding the old key by any route,
//! is left in a room nobody uses any more.
//!
//! ```text
//! body = u8(1) || from_device_id[16] || u64be(ts_ms) || u8(count)
//!        || count * ( to_device_id[16] || u32be(len) || box(to_box_pub, "asli/v2/rekey",
//!                                                           u8(1) || new_secret[32]) )
//!        || signature over "asli/v2/rekey" || old_room_id || everything above
//! ```
//!
//! A receiver accepts a bundle only from a device it already knows, checked against the signing
//! key that device's card pinned, so neither the relay nor a stranger can move an account.

use zeroize::Zeroizing;

use crate::clip::DEVICE_ID_LEN;
use crate::device::{seal_box, DeviceKeys, BOX_PUB_LEN};
use crate::error::{Error, Result};
use crate::identity::{verify_signature, PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN};
use crate::kdf::KEY_LEN;
use crate::msg::{Reader, Writer};

/// Signature label, and the purpose of each box.
pub const LABEL_REKEY: &[u8] = b"asli/v2/rekey";
/// Most devices one bundle can carry.
pub const MAX_RECIPIENTS: usize = 64;

/// One device to hand the new key to.
pub struct Recipient {
    /// Its id.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The key its card named for sealing.
    pub box_pub: [u8; BOX_PUB_LEN],
}

/// Builds and signs a bundle handing `new_secret` to each recipient.
///
/// # Errors
///
/// Returns [`Error::InnerMalformed`] for more than [`MAX_RECIPIENTS`], and a sealing error if one
/// box cannot be made.
pub fn bundle(
    from: &DeviceKeys,
    from_device_id: &[u8; DEVICE_ID_LEN],
    old_room: &[u8; ROOM_ID_LEN],
    ts_ms: u64,
    recipients: &[Recipient],
    new_secret: &[u8; KEY_LEN],
) -> Result<Vec<u8>> {
    let count = u8::try_from(recipients.len()).map_err(|_| Error::InnerMalformed)?;
    if recipients.len() > MAX_RECIPIENTS {
        return Err(Error::InnerMalformed);
    }
    let mut inner = Zeroizing::new(Vec::with_capacity(1 + KEY_LEN));
    inner.push(1);
    inner.extend_from_slice(new_secret);

    let mut body = Writer::default();
    body.u8(1).bytes(from_device_id).u64(ts_ms).u8(count);
    for recipient in recipients {
        body.bytes(&recipient.device_id);
        body.blob(&seal_box(&recipient.box_pub, LABEL_REKEY, &inner)?)?;
    }
    let mut covered = Vec::new();
    covered.extend_from_slice(LABEL_REKEY);
    covered.extend_from_slice(old_room);
    covered.extend_from_slice(body.as_slice());
    let sig = from.sign(&covered);
    body.bytes(&sig);
    Ok(body.finish())
}

/// Who sent a bundle, read before anything is checked, so the receiver can look up the key that
/// device pinned.
///
/// # Errors
///
/// Returns [`Error::InnerMalformed`] for a body too short to name a sender.
pub fn sender(body: &[u8]) -> Result<[u8; DEVICE_ID_LEN]> {
    let mut r = Reader::new(body);
    match r.u8()? {
        1 => r.array(),
        other => Err(Error::InnerVersion(other)),
    }
}

/// What a bundle held for this device.
pub struct Rekeyed {
    /// The device that made the new key.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// When, by its clock.
    pub ts_ms: u64,
    /// The new account key.
    pub secret: Zeroizing<[u8; KEY_LEN]>,
    /// Every device the new key went to, this one included.
    pub recipients: Vec<[u8; DEVICE_ID_LEN]>,
}

/// Opens this device's entry in a bundle, after checking it was signed by `from_sign_pub`, the
/// key pinned for the sender.
///
/// Returns `Ok(None)` for a genuine bundle with no entry for this device: the one being removed.
///
/// # Errors
///
/// Returns [`Error::BadSignature`] for a bundle not signed by that key, [`Error::Open`] if this
/// device's entry does not open, and a malformed error for anything out of shape.
pub fn open(
    keys: &DeviceKeys,
    device_id: &[u8; DEVICE_ID_LEN],
    old_room: &[u8; ROOM_ID_LEN],
    from_sign_pub: &[u8; PUB_KEY_LEN],
    body: &[u8],
) -> Result<Option<Rekeyed>> {
    let split = body
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InnerMalformed)?;
    let mut covered = Vec::with_capacity(LABEL_REKEY.len() + ROOM_ID_LEN + split);
    covered.extend_from_slice(LABEL_REKEY);
    covered.extend_from_slice(old_room);
    covered.extend_from_slice(&body[..split]);
    let sig: [u8; SIGNATURE_LEN] = body[split..]
        .try_into()
        .map_err(|_| Error::InnerMalformed)?;
    verify_signature(from_sign_pub, &covered, &sig)?;

    let mut r = Reader::new(&body[..split]);
    if r.u8()? != 1 {
        return Err(Error::InnerVersion(body[0]));
    }
    let from_device_id = r.array()?;
    let ts_ms = r.u64()?;
    let count = usize::from(r.u8()?);
    let mut recipients = Vec::with_capacity(count);
    let mut mine = None;
    for _ in 0..count {
        let to: [u8; DEVICE_ID_LEN] = r.array()?;
        let sealed = r.blob()?;
        if to == *device_id {
            mine = Some(sealed);
        }
        recipients.push(to);
    }
    r.done()?;

    let Some(sealed) = mine else {
        return Ok(None);
    };
    let inner = keys.open_box(LABEL_REKEY, sealed)?;
    if inner.len() != 1 + KEY_LEN || inner[0] != 1 {
        return Err(Error::InnerMalformed);
    }
    let mut secret = Zeroizing::new([0u8; KEY_LEN]);
    secret.copy_from_slice(&inner[1..]);
    Ok(Some(Rekeyed {
        from_device_id,
        ts_ms,
        secret,
        recipients,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];

    #[test]
    fn each_remaining_device_opens_the_new_key_and_the_removed_one_gets_nothing() {
        let a = DeviceKeys::from_secret(&[1u8; 32]);
        let b = DeviceKeys::from_secret(&[2u8; 32]);
        let c = DeviceKeys::from_secret(&[3u8; 32]);
        let removed = DeviceKeys::from_secret(&[4u8; 32]);
        let new_secret = [77u8; KEY_LEN];
        let body = bundle(
            &a,
            &[1u8; 16],
            &ROOM,
            5,
            &[
                Recipient {
                    device_id: [2u8; 16],
                    box_pub: b.box_pub(),
                },
                Recipient {
                    device_id: [3u8; 16],
                    box_pub: c.box_pub(),
                },
            ],
            &new_secret,
        )
        .expect("bundles");

        assert_eq!(sender(&body).expect("names a sender"), [1u8; 16]);
        for (keys, id) in [(&b, [2u8; 16]), (&c, [3u8; 16])] {
            let got = open(keys, &id, &ROOM, &a.sign_pub(), &body)
                .expect("checks")
                .expect("has an entry");
            assert_eq!(*got.secret, new_secret);
            assert_eq!(got.from_device_id, [1u8; 16]);
            assert_eq!(got.recipients, vec![[2u8; 16], [3u8; 16]]);
        }
        assert!(open(&removed, &[4u8; 16], &ROOM, &a.sign_pub(), &body)
            .expect("checks")
            .is_none());
    }

    #[test]
    fn a_bundle_counts_only_from_the_key_its_sender_pinned_and_for_its_room() {
        let a = DeviceKeys::from_secret(&[1u8; 32]);
        let b = DeviceKeys::from_secret(&[2u8; 32]);
        let stranger = DeviceKeys::from_secret(&[9u8; 32]);
        let to_b = [Recipient {
            device_id: [2u8; 16],
            box_pub: b.box_pub(),
        }];
        let forged = bundle(&stranger, &[1u8; 16], &ROOM, 5, &to_b, &[1u8; 32]).expect("bundles");
        assert!(matches!(
            open(&b, &[2u8; 16], &ROOM, &a.sign_pub(), &forged),
            Err(Error::BadSignature)
        ));
        let genuine = bundle(&a, &[1u8; 16], &ROOM, 5, &to_b, &[1u8; 32]).expect("bundles");
        assert!(open(&b, &[2u8; 16], &[8u8; ROOM_ID_LEN], &a.sign_pub(), &genuine).is_err());
    }
}
