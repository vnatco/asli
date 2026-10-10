//! Sending a file straight to a device on the same network, when it can be reached.
//!
//! The sender listens on a port of its own for as long as an offer is waiting, and names its local
//! addresses in the offer. The receiver, once a person accepts, tries them for a moment. If one
//! answers, the file goes over that connection, sealed under a key made for this transfer alone
//! (see [`asli_crypto::direct`]); if none does, it goes through the relay as before. Nothing
//! listens when no offer is waiting.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use asli_crypto::direct::{hello, is_hello, Side, Stream, FRAME_OVERHEAD, SALT_LEN};
use asli_crypto::file::{AckState, CHUNK_BYTES};
use zeroize::Zeroizing;

use crate::clipboard_io::log_line;
use crate::transfer::{OfferId, Transfers};

/// How long the receiver tries the sender's addresses before falling back to the relay.
const REACH: Duration = Duration::from_millis(1500);
/// How long either side waits on the other once connected.
const PATIENCE: Duration = Duration::from_secs(30);
/// How long a sender listens for an offer nobody answers.
const LISTEN_FOR: Duration = Duration::from_mins(15);
/// Connections that fail to prove they hold the key before the sender stops listening.
const MAX_STRANGERS: u32 = 16;
/// Largest frame other than a piece.
const SMALL_FRAME: usize = 64;

/// This machine's addresses on its local networks: private, carrier grade and link local IPv4.
/// Found by asking the system which address it would use to reach the internet, which sends
/// nothing.
#[must_use]
pub fn local_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        if socket.connect(("192.0.2.1", 9)).is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if is_local(addr.ip()) {
                    out.push(addr.ip());
                }
            }
        }
    }
    out
}

/// Whether an address can only be on a local network.
#[must_use]
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(_) => false,
    }
}

/// Starts listening for the receiver of `offer_id`. Returns the addresses to name in the offer,
/// or nothing when this machine has no local address or cannot listen.
pub(crate) fn listen(
    transfers: &Transfers,
    offer_id: OfferId,
    key: Zeroizing<[u8; 32]>,
) -> Vec<String> {
    let ips = local_addrs();
    if ips.is_empty() {
        return Vec::new();
    }
    let Ok(listener) = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return Vec::new();
    };
    let Ok(port) = listener.local_addr().map(|a| a.port()) else {
        return Vec::new();
    };
    if listener.set_nonblocking(true).is_err() {
        return Vec::new();
    }
    let transfers = transfers.clone();
    let spawned = std::thread::Builder::new()
        .name("asli-direct-send".to_owned())
        .spawn(move || serve(&transfers, &listener, offer_id, &key));
    if spawned.is_err() {
        return Vec::new();
    }
    ips.into_iter()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .collect()
}

/// Waits for the receiver, then sends it the file.
fn serve(transfers: &Transfers, listener: &TcpListener, offer_id: OfferId, key: &[u8; 32]) {
    let started = Instant::now();
    let mut strangers = 0;
    loop {
        if !transfers.direct_waiting(&offer_id) || started.elapsed() > LISTEN_FOR {
            return;
        }
        let (socket, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(_) => return,
        };
        if let Some((socket, stream)) = greet(socket, offer_id, key) {
            send_file(transfers, socket, stream, offer_id);
            return;
        }
        strangers += 1;
        if strangers >= MAX_STRANGERS {
            return;
        }
    }
}

/// Reads the receiver's salt and hello. Anyone can connect; only the receiver can say hello.
fn greet(mut socket: TcpStream, offer_id: OfferId, key: &[u8; 32]) -> Option<(TcpStream, Stream)> {
    socket.set_nonblocking(false).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    socket.set_write_timeout(Some(PATIENCE)).ok()?;
    let mut salt = [0u8; SALT_LEN];
    socket.read_exact(&mut salt).ok()?;
    let mut stream = Stream::new(key, &salt, &offer_id, Side::Sender);
    let first = read_frame(&mut socket, SMALL_FRAME)?;
    let opened = stream.open(&first).ok()?;
    if !is_hello(&opened, &offer_id) {
        return None;
    }
    socket.set_read_timeout(Some(PATIENCE)).ok()?;
    Some((socket, stream))
}

fn send_file(transfers: &Transfers, mut socket: TcpStream, mut stream: Stream, offer_id: OfferId) {
    let Some((path, offer)) = transfers.direct_begin(&offer_id) else {
        return;
    };
    eprintln!(
        "{}",
        log_line("file_direct", "sending on the local network")
    );
    let count = u32::try_from(offer.chunk_count()).unwrap_or(u32::MAX);
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            transfers.direct_failed(&offer_id, &format!("couldn't read the file: {err}"));
            return;
        }
    };
    let mut piece = vec![0u8; offer.chunk_bytes as usize];
    for index in 0..count {
        let len = crate::transfer::piece_len(&offer, index);
        if let Err(err) = file.read_exact(&mut piece[..len]) {
            transfers.direct_failed(&offer_id, &format!("couldn't read the file: {err}"));
            return;
        }
        let sent = stream
            .seal(&piece[..len])
            .is_ok_and(|frame| write_frame(&mut socket, &frame).is_ok());
        if !sent {
            transfers.direct_failed(&offer_id, "the other device stopped receiving.");
            return;
        }
        if !transfers.direct_progress(&offer_id, index + 1) {
            // Called off.
            return;
        }
    }
    let _ = socket.set_read_timeout(Some(Duration::from_secs(120)));
    let state = read_frame(&mut socket, SMALL_FRAME)
        .and_then(|frame| stream.open(&frame).ok())
        .and_then(|opened| match opened.as_slice() {
            [1] => Some(AckState::Done),
            [2] => Some(AckState::Corrupt),
            _ => None,
        });
    match state {
        Some(state) => transfers.direct_finished(&offer_id, state),
        None => transfers.direct_failed(&offer_id, "the other device did not confirm it."),
    }
}

/// Tries to fetch an accepted file directly. Returns false if no address answered in time, so
/// the caller can fall back to the relay; once a piece has arrived the transfer is this
/// connection's, whatever happens.
pub(crate) fn fetch(
    transfers: &Transfers,
    offer_id: OfferId,
    key: &[u8; 32],
    addrs: &[String],
) -> bool {
    let Some(mut socket) = reach(addrs) else {
        return false;
    };
    let Ok(salt) = asli_crypto::random::bytes::<SALT_LEN>() else {
        return false;
    };
    let mut stream = Stream::new(key, &salt, &offer_id, Side::Receiver);
    let said_hello = socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_ok()
        && socket.set_write_timeout(Some(PATIENCE)).is_ok()
        && socket.write_all(&salt).is_ok()
        && stream
            .seal(&hello(&offer_id))
            .is_ok_and(|frame| write_frame(&mut socket, &frame).is_ok());
    if !said_hello {
        return false;
    }
    let max = CHUNK_BYTES as usize + FRAME_OVERHEAD;
    let Some(first) = read_frame(&mut socket, max) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(PATIENCE));
    eprintln!(
        "{}",
        log_line("file_direct", "receiving on the local network")
    );
    transfers.direct_receiving(&offer_id);
    let mut frame = first;
    loop {
        let Ok(piece) = stream.open(&frame) else {
            transfers.direct_receive_failed(&offer_id, "a piece arrived damaged.");
            return true;
        };
        match transfers.direct_piece(&offer_id, &piece) {
            Err(()) => return true,
            Ok(None) => {}
            Ok(Some(state)) => {
                let code = if state == AckState::Done { 1 } else { 2 };
                if let Ok(frame) = stream.seal(&[code]) {
                    let _ = write_frame(&mut socket, &frame);
                }
                return true;
            }
        }
        let Some(next) = read_frame(&mut socket, max) else {
            transfers.direct_receive_failed(&offer_id, "the other device stopped sending.");
            return true;
        };
        frame = next;
    }
}

/// Connects to whichever address answers first.
fn reach(addrs: &[String]) -> Option<TcpStream> {
    let (tx, rx) = mpsc::channel();
    for addr in addrs {
        let Ok(addr) = addr.parse::<SocketAddr>() else {
            continue;
        };
        // Only ever a local address: an offer cannot send this device to the internet.
        if !is_local(addr.ip()) {
            continue;
        }
        let tx = tx.clone();
        let _ = std::thread::Builder::new()
            .name("asli-direct-reach".to_owned())
            .spawn(move || {
                if let Ok(socket) = TcpStream::connect_timeout(&addr, REACH) {
                    let _ = tx.send(socket);
                }
            });
    }
    drop(tx);
    rx.recv_timeout(REACH + Duration::from_millis(200)).ok()
}

fn write_frame(socket: &mut TcpStream, frame: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(frame.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    socket.write_all(&len.to_be_bytes())?;
    socket.write_all(frame)
}

/// Reads one frame, refusing anything longer than `max` before allocating for it.
fn read_frame(socket: &mut TcpStream, max: usize) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    socket.read_exact(&mut len).ok()?;
    let len = usize::try_from(u32::from_be_bytes(len)).ok()?;
    if len > max {
        return None;
    }
    let mut frame = vec![0u8; len];
    socket.read_exact(&mut frame).ok()?;
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_addresses_count() {
        for (ip, local) in [
            ("192.168.1.20", true),
            ("10.1.2.3", true),
            ("172.16.0.9", true),
            ("169.254.10.1", true),
            ("100.101.102.103", true),
            ("8.8.8.8", false),
            ("100.128.0.1", false),
            ("127.0.0.1", false),
            ("::1", false),
        ] {
            assert_eq!(is_local(ip.parse().expect("parses")), local, "{ip}");
        }
    }

    #[test]
    fn an_offer_cannot_point_this_device_anywhere_but_the_local_network() {
        // Loopback and public addresses are not tried at all, so fetching falls back to the relay
        // at once, and an offer cannot make a device connect out to the internet or to itself.
        let started = Instant::now();
        assert!(reach(&[
            "127.0.0.1:9".to_owned(),
            "8.8.8.8:53".to_owned(),
            "not an address".to_owned(),
        ])
        .is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
