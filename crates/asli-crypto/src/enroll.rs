//! Joining a device to an account: a short, single use join code, and the three messages that
//! follow it.
//!
//! The old join token carried the account key itself, so anyone who ever saw it, in a screenshot
//! from a year ago, held the account for good. A join code carries no key. It names a meeting
//! place on the relay that exists for ten minutes, and the account key crosses only after a person
//! approves the new device on one that is already in, sealed to that new device alone.
//!
//! ```text
//! E          12 bytes, OS CSPRNG, made by the approving device for one join
//! fp         = SHA-256("asli/v2/approver" || approver_sign_pub)[0..6]
//! payload    = u8(2) || E || fp                                              (19 bytes)
//! checksum   = SHA-256("asli/v2/join-check" || payload)[0..3]
//! code       = "asli2_" || Crockford-Base32(payload || checksum)             (6 + 36 characters)
//!
//! meeting    = Identity::from_secret(HKDF(salt = "asli/v2/enroll-salt", IKM = E,
//!                                         info = "asli/v2/enroll", 32))
//! ```
//!
//! Both devices connect to the meeting identity's room, which to the relay is a room like any
//! other. The new device sends a [`JoinRequest`]. The approving device shows its name, its
//! operating system and a six digit [`comparison_code`], which the new device shows as well, and
//! the person checks they match before approving. That is what stops someone who saw the join code
//! from slipping their own request in first. The approval, a [`JoinGrant`], carries the account
//! key sealed to the new device and is signed by the approving device, whose key the join code
//! fingerprints. That is what stops the same someone from answering the request themselves and
//! enrolling the new device into an account of their own.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::base32;
use crate::clip::DEVICE_ID_LEN;
use crate::device::{seal_box, DeviceKeys, BOX_PUB_LEN};
use crate::error::{Error, Result};
use crate::identity::{Identity, PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN};
use crate::kdf::KEY_LEN;
use crate::msg::{Reader, Writer};
use crate::random;

/// Prefix of a join code. The digit is its format version.
pub const CODE_PREFIX: &str = "asli2_";
/// Join code format version.
pub const CODE_VERSION: u8 = 2;
/// Length of the meeting secret.
pub const MEETING_SECRET_LEN: usize = 12;
/// Length of the approver fingerprint.
pub const FINGERPRINT_LEN: usize = 6;
/// Length of the checksum.
pub const CHECKSUM_LEN: usize = 3;
/// Characters after the prefix.
pub const CODE_BODY_CHARS: usize = 36;
/// How long a join code is offered for, in milliseconds.
pub const CODE_LIFETIME_MS: u64 = 10 * 60 * 1000;
/// Length of a request id.
pub const REQUEST_ID_LEN: usize = 16;

const LABEL_FINGERPRINT: &[u8] = b"asli/v2/approver";
const LABEL_CHECK: &[u8] = b"asli/v2/join-check";
const LABEL_ENROLL_SALT: &[u8] = b"asli/v2/enroll-salt";
const LABEL_ENROLL: &[u8] = b"asli/v2/enroll";
const LABEL_COMPARE: &[u8] = b"asli/v2/compare";
const LABEL_JOIN_DIRECT: &[u8] = b"asli/v2/join-direct";
/// Most local addresses a `where` message names.
pub const MAX_WHERE_ADDRS: usize = 4;
/// Signature label for a join request.
pub const LABEL_REQUEST: &[u8] = b"asli/v2/join-request";
/// Signature label for a join grant, and the purpose of the box inside it.
pub const LABEL_GRANT: &[u8] = b"asli/v2/join-grant";
/// Signature label for a join decline.
pub const LABEL_DECLINE: &[u8] = b"asli/v2/join-decline";

/// What a join code holds.
pub struct JoinCode {
    meeting_secret: Zeroizing<[u8; MEETING_SECRET_LEN]>,
    fingerprint: [u8; FINGERPRINT_LEN],
}

/// The fingerprint a join code carries for the device that made it.
#[must_use]
pub fn fingerprint(sign_pub: &[u8; PUB_KEY_LEN]) -> [u8; FINGERPRINT_LEN] {
    let digest = Sha256::new()
        .chain_update(LABEL_FINGERPRINT)
        .chain_update(sign_pub)
        .finalize();
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(&digest[..FINGERPRINT_LEN]);
    out
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::new()
        .chain_update(LABEL_CHECK)
        .chain_update(payload)
        .finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

impl JoinCode {
    /// A fresh code for one join, made by the device that will approve it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if randomness fails.
    pub fn generate(approver: &DeviceKeys) -> Result<Self> {
        Ok(Self {
            meeting_secret: Zeroizing::new(random::bytes()?),
            fingerprint: fingerprint(&approver.sign_pub()),
        })
    }

    /// The code as typed: `asli2_` and 36 characters.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(1 + MEETING_SECRET_LEN + 9));
        payload.push(CODE_VERSION);
        payload.extend_from_slice(self.meeting_secret.as_ref());
        payload.extend_from_slice(&self.fingerprint);
        let sum = checksum(&payload);
        payload.extend_from_slice(&sum);
        Zeroizing::new(format!("{CODE_PREFIX}{}", base32::encode(&payload)))
    }

    /// Reads a typed or pasted code. Spaces, line breaks and dashes anywhere are ignored, and so
    /// is case, so a code read aloud or broken across lines still works.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenPrefix`], [`Error::TokenAlphabet`], [`Error::TokenLength`],
    /// [`Error::TokenVersion`] or [`Error::TokenChecksum`], each for its own fault.
    pub fn parse(input: &str) -> Result<Self> {
        let compact: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect(),
        );
        if compact.len() < CODE_PREFIX.len()
            || !compact.is_char_boundary(CODE_PREFIX.len())
            || !compact[..CODE_PREFIX.len()].eq_ignore_ascii_case(CODE_PREFIX)
        {
            return Err(Error::TokenPrefix);
        }
        let body = &compact[CODE_PREFIX.len()..];
        if body.len() != CODE_BODY_CHARS {
            return Err(Error::TokenLength);
        }
        let decoded = Zeroizing::new(base32::decode(body).map_err(|_| Error::TokenAlphabet)?);
        if decoded.len() != 1 + MEETING_SECRET_LEN + FINGERPRINT_LEN + CHECKSUM_LEN {
            return Err(Error::TokenLength);
        }
        if decoded[0] != CODE_VERSION {
            return Err(Error::TokenVersion(decoded[0]));
        }
        let split = decoded.len() - CHECKSUM_LEN;
        if checksum(&decoded[..split]) != decoded[split..] {
            return Err(Error::TokenChecksum);
        }
        let mut meeting_secret = Zeroizing::new([0u8; MEETING_SECRET_LEN]);
        meeting_secret.copy_from_slice(&decoded[1..=MEETING_SECRET_LEN]);
        let mut fp = [0u8; FINGERPRINT_LEN];
        fp.copy_from_slice(&decoded[1 + MEETING_SECRET_LEN..split]);
        Ok(Self {
            meeting_secret,
            fingerprint: fp,
        })
    }

    /// The identity both devices use to meet on the relay.
    ///
    /// # Panics
    ///
    /// Never: 32 bytes is far inside the HKDF output limit.
    #[must_use]
    pub fn meeting(&self) -> Identity {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(LABEL_ENROLL_SALT), self.meeting_secret.as_ref());
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(LABEL_ENROLL, secret.as_mut())
            .expect("32 bytes is well within the HKDF output limit");
        Identity::from_secret(&secret)
    }

    /// The key both devices seal their frames with when the new one reaches the approving one on
    /// the local network (see [`crate::direct`]). Only someone holding the code can make it.
    ///
    /// # Panics
    ///
    /// Never: 32 bytes is well within what HKDF can produce.
    #[must_use]
    pub fn direct_key(&self) -> Zeroizing<[u8; KEY_LEN]> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(LABEL_ENROLL_SALT), self.meeting_secret.as_ref());
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(LABEL_JOIN_DIRECT, key.as_mut())
            .expect("32 bytes is well within the HKDF output limit");
        key
    }

    /// Whether `sign_pub` is the key of the device that made this code.
    #[must_use]
    pub fn made_by(&self, sign_pub: &[u8; PUB_KEY_LEN]) -> bool {
        fingerprint(sign_pub) == self.fingerprint
    }

    /// The six digit code both devices show for one request, for a person to compare.
    #[must_use]
    pub fn comparison_code(&self, request: &JoinRequest) -> String {
        let digest = Sha256::new()
            .chain_update(LABEL_COMPARE)
            .chain_update(self.meeting_secret.as_ref())
            .chain_update(request.request_id)
            .chain_update(request.sign_pub)
            .chain_update(request.box_pub)
            .finalize();
        let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
        let digits = format!("{value:06}");
        format!("{} {}", &digits[..3], &digits[3..])
    }
}

/// A new device asking to join, sent in the meeting room and signed by the new device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// Chosen by the new device for this request, so the answer can name it.
    pub request_id: [u8; REQUEST_ID_LEN],
    /// The id the new device will use on the account.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The new device's signing key.
    pub sign_pub: [u8; PUB_KEY_LEN],
    /// The key the account key is sealed to.
    pub box_pub: [u8; BOX_PUB_LEN],
    /// When it asked, by its own clock.
    pub ts_ms: u64,
    /// What the person calls it.
    pub name: String,
    /// Its operating system.
    pub os: String,
}

impl JoinRequest {
    /// Encodes and signs the request for the meeting room.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadPublicKey`] if the keys are not the signer's, or
    /// [`Error::AnnounceField`] for an over long name or system.
    pub fn encode(&self, keys: &DeviceKeys, meeting_room: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        if keys.sign_pub() != self.sign_pub || keys.box_pub() != self.box_pub {
            return Err(Error::BadPublicKey);
        }
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.request_id)
            .bytes(&self.device_id)
            .bytes(&self.sign_pub)
            .bytes(&self.box_pub)
            .u64(self.ts_ms);
        body.text(&self.name)?.text(&self.os)?;
        Ok(sign(keys, LABEL_REQUEST, meeting_room, body))
    }

    /// Decodes a request and checks the new device signed it.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed request or a signature that does not verify.
    pub fn decode(body: &[u8], meeting_room: &[u8; ROOM_ID_LEN]) -> Result<Self> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        let request = Self {
            request_id: r.array()?,
            device_id: r.array()?,
            sign_pub: r.array()?,
            box_pub: r.array()?,
            ts_ms: r.u64()?,
            name: r.text()?,
            os: r.text()?,
        };
        signature_ends(&mut r)?;
        verify(LABEL_REQUEST, meeting_room, body, &request.sign_pub)?;
        Ok(request)
    }
}

/// What a grant hands over, once opened by the new device.
pub struct Granted {
    /// The account key.
    pub secret: Zeroizing<[u8; KEY_LEN]>,
    /// Whether this key has never been shown in an old style join token, which carried the key
    /// itself. A key that has been can still be in a screenshot somewhere, so the account offers
    /// to replace it.
    pub never_exported: bool,
}

/// Approves a request: seals the account key to the new device and signs the result.
///
/// # Errors
///
/// Returns [`Error::Rng`] or [`Error::Seal`] if sealing fails, and [`Error::BadPublicKey`] for a
/// request whose box key cannot be sealed to.
pub fn grant(
    approver: &DeviceKeys,
    meeting_room: &[u8; ROOM_ID_LEN],
    request: &JoinRequest,
    account_secret: &[u8; KEY_LEN],
    never_exported: bool,
) -> Result<Vec<u8>> {
    let mut inner = Zeroizing::new(Vec::with_capacity(2 + KEY_LEN));
    inner.push(1);
    inner.extend_from_slice(account_secret);
    inner.push(u8::from(never_exported));
    let sealed = seal_box(&request.box_pub, LABEL_GRANT, &inner)?;

    let mut body = Writer::default();
    body.u8(1)
        .bytes(&request.request_id)
        .bytes(&request.sign_pub)
        .bytes(&approver.sign_pub());
    body.blob(&sealed)?;
    Ok(sign(approver, LABEL_GRANT, meeting_room, body))
}

/// Opens a grant on the new device, accepting it only from the device the join code names and
/// only for this device's own request.
///
/// # Errors
///
/// Returns [`Error::BadSignature`] for a grant not from the code's maker, not for this request,
/// or not signed; [`Error::Open`] if the key inside does not open; and [`Error::InnerMalformed`]
/// for anything else out of shape.
pub fn open_grant(
    code: &JoinCode,
    meeting_room: &[u8; ROOM_ID_LEN],
    keys: &DeviceKeys,
    request_id: &[u8; REQUEST_ID_LEN],
    body: &[u8],
) -> Result<Granted> {
    let mut r = Reader::new(body);
    version(&mut r)?;
    let for_request: [u8; REQUEST_ID_LEN] = r.array()?;
    let for_key: [u8; PUB_KEY_LEN] = r.array()?;
    let approver: [u8; PUB_KEY_LEN] = r.array()?;
    let sealed = r.blob()?;
    signature_ends(&mut r)?;

    if !code.made_by(&approver) || for_request != *request_id || for_key != keys.sign_pub() {
        return Err(Error::BadSignature);
    }
    verify(LABEL_GRANT, meeting_room, body, &approver)?;

    let inner = keys.open_box(LABEL_GRANT, sealed)?;
    if inner.len() != 2 + KEY_LEN || inner[0] != 1 || inner[1 + KEY_LEN] > 1 {
        return Err(Error::InnerMalformed);
    }
    let mut secret = Zeroizing::new([0u8; KEY_LEN]);
    secret.copy_from_slice(&inner[1..=KEY_LEN]);
    Ok(Granted {
        secret,
        never_exported: inner[1 + KEY_LEN] == 1,
    })
}

/// Turns a request down, signed by the approving device so only it can.
///
/// # Errors
///
/// Never in practice; the signature step cannot fail.
pub fn decline(
    approver: &DeviceKeys,
    meeting_room: &[u8; ROOM_ID_LEN],
    request_id: &[u8; REQUEST_ID_LEN],
) -> Result<Vec<u8>> {
    let mut body = Writer::default();
    body.u8(1).bytes(request_id).bytes(&approver.sign_pub());
    Ok(sign(approver, LABEL_DECLINE, meeting_room, body))
}

/// Whether a decline is genuine: from the code's maker, for this request.
#[must_use]
pub fn is_decline_for(
    code: &JoinCode,
    meeting_room: &[u8; ROOM_ID_LEN],
    request_id: &[u8; REQUEST_ID_LEN],
    body: &[u8],
) -> bool {
    let check = || -> Result<bool> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        let for_request: [u8; REQUEST_ID_LEN] = r.array()?;
        let approver: [u8; PUB_KEY_LEN] = r.array()?;
        signature_ends(&mut r)?;
        verify(LABEL_DECLINE, meeting_room, body, &approver)?;
        Ok(code.made_by(&approver) && for_request == *request_id)
    };
    check().unwrap_or(false)
}

fn version(r: &mut Reader<'_>) -> Result<()> {
    match r.u8()? {
        1 => Ok(()),
        other => Err(Error::InnerVersion(other)),
    }
}

fn signature_ends(r: &mut Reader<'_>) -> Result<()> {
    r.bytes(SIGNATURE_LEN)?;
    r.done()
}

fn sign(keys: &DeviceKeys, label: &[u8], room: &[u8; ROOM_ID_LEN], mut body: Writer) -> Vec<u8> {
    let mut covered = Vec::with_capacity(label.len() + ROOM_ID_LEN + body.as_slice().len());
    covered.extend_from_slice(label);
    covered.extend_from_slice(room);
    covered.extend_from_slice(body.as_slice());
    let sig = keys.sign(&covered);
    body.bytes(&sig);
    body.finish()
}

fn verify(
    label: &[u8],
    room: &[u8; ROOM_ID_LEN],
    body: &[u8],
    sign_pub: &[u8; PUB_KEY_LEN],
) -> Result<()> {
    let split = body
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InnerMalformed)?;
    let mut covered = Vec::with_capacity(label.len() + ROOM_ID_LEN + split);
    covered.extend_from_slice(label);
    covered.extend_from_slice(room);
    covered.extend_from_slice(&body[..split]);
    let sig: [u8; SIGNATURE_LEN] = body[split..]
        .try_into()
        .map_err(|_| Error::InnerMalformed)?;
    crate::identity::verify_signature(sign_pub, &covered, &sig)
}

/// Where the approving device listens on its local network, for an invitation that accepts a new
/// device only from there: `u8(1) || u8(count) || count * text(addr)`.
///
/// # Errors
///
/// Returns [`Error::AnnounceField`] for no addresses, too many, or one too long.
pub fn where_body(addrs: &[String]) -> Result<Vec<u8>> {
    if addrs.is_empty() || addrs.len() > MAX_WHERE_ADDRS {
        return Err(Error::AnnounceField);
    }
    let mut body = Writer::default();
    body.u8(1)
        .u8(u8::try_from(addrs.len()).map_err(|_| Error::AnnounceField)?);
    for addr in addrs {
        body.text(addr)?;
    }
    Ok(body.finish())
}

/// Reads the addresses out of a `where` message.
///
/// # Errors
///
/// Returns an error for a malformed message.
pub fn read_where(body: &[u8]) -> Result<Vec<String>> {
    let mut r = Reader::new(body);
    match r.u8()? {
        1 => {}
        other => return Err(Error::InnerVersion(other)),
    }
    let count = usize::from(r.u8()?);
    if count == 0 || count > MAX_WHERE_ADDRS {
        return Err(Error::AnnounceField);
    }
    let addrs = (0..count).map(|_| r.text()).collect::<Result<Vec<_>>>()?;
    r.done()?;
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(keys: &DeviceKeys) -> JoinRequest {
        JoinRequest {
            request_id: [4u8; REQUEST_ID_LEN],
            device_id: [5u8; DEVICE_ID_LEN],
            sign_pub: keys.sign_pub(),
            box_pub: keys.box_pub(),
            ts_ms: 1_767_225_600_000,
            name: "DESKTOP-7Q".to_owned(),
            os: "Windows 11".to_owned(),
        }
    }

    #[test]
    fn a_code_round_trips_and_forgives_how_it_was_typed() {
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let code = JoinCode::generate(&approver).expect("generates");
        let text = code.encode();
        assert!(text.starts_with(CODE_PREFIX));
        assert_eq!(text.len(), CODE_PREFIX.len() + CODE_BODY_CHARS);

        let messy = format!(
            "  {}-{}\n{} ",
            text[..10].to_uppercase(),
            &text[10..20],
            text[20..].to_lowercase()
        );
        let back = JoinCode::parse(&messy).expect("parses");
        assert_eq!(back.meeting().room_id(), code.meeting().room_id());
        assert!(back.made_by(&approver.sign_pub()));
    }

    #[test]
    fn each_kind_of_bad_code_says_what_is_wrong() {
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let text = JoinCode::generate(&approver).expect("generates").encode();
        assert!(matches!(
            JoinCode::parse("asli1_ABC"),
            Err(Error::TokenPrefix)
        ));
        assert!(matches!(
            JoinCode::parse(&text[..text.len() - 1]),
            Err(Error::TokenLength)
        ));
        // A character in the middle: the last one is mostly padding bits.
        let mut typo = text.to_string();
        let at = CODE_PREFIX.len() + 10;
        let was = typo.as_bytes()[at];
        typo.replace_range(at..=at, if was == b'A' { "B" } else { "A" });
        assert!(matches!(JoinCode::parse(&typo), Err(Error::TokenChecksum)));
        let mut bad = text.to_string();
        bad.replace_range(10..11, "U");
        assert!(matches!(JoinCode::parse(&bad), Err(Error::TokenAlphabet)));
    }

    #[test]
    fn two_codes_meet_in_different_rooms() {
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let a = JoinCode::generate(&approver).expect("a");
        let b = JoinCode::generate(&approver).expect("b");
        assert_ne!(a.meeting().room_id(), b.meeting().room_id());
    }

    #[test]
    fn the_whole_join_hands_the_key_to_the_requester_and_nobody_else() {
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let newcomer = DeviceKeys::from_secret(&[2u8; 32]);
        let code = JoinCode::generate(&approver).expect("generates");
        let room = code.meeting().room_id_bytes();
        let account = [42u8; KEY_LEN];

        // The new device asks; the approving device reads the request and sees who asked.
        let asked = request(&newcomer)
            .encode(&newcomer, &room)
            .expect("encodes");
        let seen = JoinRequest::decode(&asked, &room).expect("decodes");
        assert_eq!(seen, request(&newcomer));

        // Both show the same comparison code.
        let typed = JoinCode::parse(&code.encode()).expect("parses");
        assert_eq!(
            code.comparison_code(&seen),
            typed.comparison_code(&request(&newcomer))
        );

        // Approved: only the requester opens the key, and only with the right request id.
        let granted = grant(&approver, &room, &seen, &account, true).expect("grants");
        let opened =
            open_grant(&typed, &room, &newcomer, &seen.request_id, &granted).expect("opens");
        assert_eq!(*opened.secret, account);
        assert!(opened.never_exported);

        let bystander = DeviceKeys::from_secret(&[3u8; 32]);
        assert!(open_grant(&typed, &room, &bystander, &seen.request_id, &granted).is_err());
        assert!(open_grant(&typed, &room, &newcomer, &[0u8; REQUEST_ID_LEN], &granted).is_err());
    }

    #[test]
    fn a_grant_from_anyone_but_the_codes_maker_is_refused() {
        // Someone who saw the code answers the request first, offering an account of their own.
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let newcomer = DeviceKeys::from_secret(&[2u8; 32]);
        let intruder = DeviceKeys::from_secret(&[9u8; 32]);
        let code = JoinCode::generate(&approver).expect("generates");
        let room = code.meeting().room_id_bytes();
        let seen = request(&newcomer);

        let forged = grant(&intruder, &room, &seen, &[66u8; KEY_LEN], true).expect("grants");
        assert!(matches!(
            open_grant(&code, &room, &newcomer, &seen.request_id, &forged),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn a_request_from_someone_else_shows_a_different_comparison_code() {
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let code = JoinCode::generate(&approver).expect("generates");
        let mine = request(&DeviceKeys::from_secret(&[2u8; 32]));
        let theirs = request(&DeviceKeys::from_secret(&[9u8; 32]));
        assert_ne!(code.comparison_code(&mine), code.comparison_code(&theirs));
        assert_eq!(
            code.comparison_code(&mine).len(),
            7,
            "three digits, a space, three digits"
        );
    }

    #[test]
    fn a_request_must_be_signed_by_the_keys_it_names() {
        let newcomer = DeviceKeys::from_secret(&[2u8; 32]);
        let other = DeviceKeys::from_secret(&[3u8; 32]);
        let room = [7u8; ROOM_ID_LEN];
        assert!(matches!(
            request(&other).encode(&newcomer, &room),
            Err(Error::BadPublicKey)
        ));

        let mut asked = request(&newcomer)
            .encode(&newcomer, &room)
            .expect("encodes");
        asked[20] ^= 0x01;
        assert!(JoinRequest::decode(&asked, &room).is_err());
    }

    #[test]
    fn where_round_trips_and_the_direct_key_follows_the_code() {
        let addrs = vec!["192.168.1.20:40000".to_owned()];
        assert_eq!(
            read_where(&where_body(&addrs).expect("encodes")).expect("reads"),
            addrs
        );
        assert!(where_body(&[]).is_err());
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let one = JoinCode::generate(&approver).expect("makes");
        let again = JoinCode::parse(&one.encode()).expect("parses");
        let other = JoinCode::generate(&approver).expect("makes");
        assert_eq!(*one.direct_key(), *again.direct_key());
        assert_ne!(*one.direct_key(), *other.direct_key());
        assert_ne!(*one.direct_key(), *one.meeting().secret());
    }

    #[test]
    fn a_decline_counts_only_from_the_codes_maker() {
        let approver = DeviceKeys::from_secret(&[1u8; 32]);
        let intruder = DeviceKeys::from_secret(&[9u8; 32]);
        let code = JoinCode::generate(&approver).expect("generates");
        let room = code.meeting().room_id_bytes();
        let id = [4u8; REQUEST_ID_LEN];
        assert!(is_decline_for(
            &code,
            &room,
            &id,
            &decline(&approver, &room, &id).expect("d")
        ));
        assert!(!is_decline_for(
            &code,
            &room,
            &id,
            &decline(&intruder, &room, &id).expect("d")
        ));
        assert!(!is_decline_for(
            &code,
            &room,
            &[0u8; 16],
            &decline(&approver, &room, &id).expect("d")
        ));
    }
}
