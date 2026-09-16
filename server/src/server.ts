/**
 * The relay itself.
 *
 * It forwards ciphertext between the connections in a room and can read none of it. It holds no
 * per room secret, writes nothing to disk, and keeps at most one recent message per room so a
 * device that was switched off can catch up.
 *
 * The parts worth reading carefully are the handshake state machine (a connection that has not
 * authenticated is the cheapest thing an attacker can create, so it is on a short timer) and the
 * backpressure handling (the clipboard is last write wins, so a slow consumer gets one pending
 * slot rather than a queue).
 */

import { createServer } from 'node:http';
import type { IncomingMessage, Server as HttpServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { Buffer as NodeBuffer } from 'node:buffer';
import { WebSocketServer } from 'ws';
import type { RawData, WebSocket } from 'ws';

import type { Config } from './config.ts';
import { log, roomLogId } from './log.ts';
import { AUTH_FAIL_CLOSE, verifyAuth } from './auth.ts';
import type { AuthFailCode, NonceState } from './auth.ts';
import { parseFrame, validateAuth, validateClip, validateHello } from './validate.ts';
import { IpLimiter, RollingQuota, TokenBucket, rateLimitKey, resolveClientAddress } from './limits.ts';
import { RoomRegistry } from './rooms.ts';
import type { Connection } from './rooms.ts';

const SUITE = 'asli-v1';
const ENCODING = 'json';

type ConnState = 'connected' | 'challenged' | 'ready';

type Session = {
  ws: WebSocket;
  conn: Connection;
  state: ConnState;
  nonce: NonceState;
  ipKey: string;
  authTimer: NodeJS.Timeout | null;
  missedPongs: number;
  msgBucket: TokenBucket;
  byteBucket: TokenBucket;
  rateStrikes: number;
  pendingClip: string | null;
  backpressureSinceMs: number | null;
  joined: boolean;
};

/**
 * Whether a frame must be parked in the pending slot rather than sent now.
 *
 * Exported so the backpressure rule can be tested directly. Simulating a peer that never drains a
 * socket is flaky; the decision itself is the part that has to be right.
 */
export function shouldPark(bufferedAmount: number, softLimitBytes: number): boolean {
  return bufferedAmount > softLimitBytes;
}

export type Relay = {
  httpServer: HttpServer;
  wss: WebSocketServer;
  port: () => number;
  close: () => Promise<void>;
};

export function createRelay(config: Config): Relay {
  const registry = new RoomRegistry({
    retainMaxBytes: config.retainMaxBytes,
    retainGlobalBudgetBytes: config.retainGlobalBudgetBytes,
    retainTtlMs: config.retainTtlMs,
    maxRooms: config.maxRooms,
    maxConnsPerRoom: config.maxConnsPerRoom,
    dedupWindow: config.dedupWindow,
    presenceDebounceMs: config.presenceDebounceMs,
  });

  const ipLimiter = new IpLimiter(config.maxConnsPerIp, config.newConnBurst, config.newConnRefillMs);
  const roomQuotas = new Map<string, RollingQuota>();
  const sessions = new Set<Session>();

  const httpServer = createServer((req, res) => {
    // Deliberately minimal: no counts, because room and connection numbers on a public endpoint
    // are free intelligence about the user base.
    if (req.method === 'GET' && (req.url === '/healthz' || req.url === '/healthz/')) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok\n');
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
  });

  const wss = new WebSocketServer({
    server: httpServer,
    path: '/v1',
    maxPayload: config.maxFrameBytes,
    // Compressing ciphertext buys nothing and costs a zlib context per connection, which is a
    // documented memory amplifier.
    perMessageDeflate: false,
    // The peers of a public relay are untrusted by definition, so validation stays on.
    skipUTF8Validation: false,
  });

  const metricsServer =
    config.metricsPort === 0
      ? null
      : createServer((req, res) => {
          if (req.method !== 'GET' || req.url !== '/metrics') {
            res.writeHead(404);
            res.end();
            return;
          }
          const body = [
            `asli_rooms ${registry.roomCount}`,
            `asli_connections ${registry.connectionCount}`,
            `asli_retained_bytes ${registry.retainedByteCount}`,
            `asli_ip_entries ${ipLimiter.size}`,
          ].join('\n');
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end(`${body}\n`);
        });

  function sendJson(session: Session, payload: Record<string, unknown>): void {
    if (session.ws.readyState !== session.ws.OPEN) return;
    session.ws.send(JSON.stringify(payload));
  }

  function sendError(
    session: Session,
    code: string,
    message?: string,
    retryAfterMs?: number,
  ): void {
    const payload: Record<string, unknown> = { v: 1, type: 'error', code };
    if (message !== undefined) payload['message'] = message;
    if (retryAfterMs !== undefined) payload['retry_after_ms'] = retryAfterMs;
    sendJson(session, payload);
  }

  function failAuth(session: Session, code: AuthFailCode, message?: string): void {
    const payload: Record<string, unknown> = { v: 1, type: 'auth_fail', code };
    if (message !== undefined) payload['message'] = message;
    sendJson(session, payload);
    log.warn('auth_fail', { conn: session.conn.id, code });
    session.ws.close(AUTH_FAIL_CLOSE[code], code);
  }

  function broadcastPresence(roomId: string): void {
    registry.schedulePresence(roomId, (peers) => {
      const payload = { v: 1, type: 'presence', peers };
      for (const session of sessions) {
        if (session.state === 'ready' && session.conn.roomId === roomId) {
          sendJson(session, payload);
        }
      }
    });
  }

  function handleHello(session: Session, message: ReturnType<typeof parseFrame>): void {
    if (!message.ok) return;
    const hello = validateHello(message.message);
    if (hello === null) {
      failAuth(session, 'MALFORMED_AUTH', 'hello failed validation');
      return;
    }
    if (!hello.suites.includes(SUITE) || !hello.enc.includes(ENCODING)) {
      failAuth(session, 'UNSUPPORTED_VERSION', 'no shared suite or encoding');
      return;
    }

    const nonceS = randomBytes(32);
    session.nonce.issued = nonceS;
    session.state = 'challenged';

    sendJson(session, {
      v: 1,
      type: 'challenge',
      suite: SUITE,
      enc: ENCODING,
      nonce_s: nonceS.toString('base64'),
      server_time_ms: Date.now(),
      limits: {
        max_frame_bytes: config.maxFrameBytes,
        max_content_bytes: config.maxContentBytes,
        retain_max_bytes: config.retainMaxBytes,
        msgs_per_sec: config.msgsPerSec,
        room_bytes_per_day: config.roomBytesPerDay,
      },
    });
  }

  function handleAuth(session: Session, message: ReturnType<typeof parseFrame>): void {
    if (!message.ok) return;
    const fields = validateAuth(message.message);
    if (fields === null) {
      // The nonce is consumed even on a malformed attempt: one challenge per connection.
      session.nonce.issued = null;
      failAuth(session, 'MALFORMED_AUTH', 'auth failed validation');
      return;
    }

    const result = verifyAuth(fields, session.nonce, false);
    if (!result.ok) {
      failAuth(session, result.code);
      return;
    }

    session.conn.roomId = result.roomId;
    const joined = registry.join(session.conn, Date.now());
    if (!joined.ok) {
      log.warn('conn_rejected', { conn: session.conn.id, code: joined.reason });
      session.ws.close(4009, joined.reason);
      return;
    }
    session.joined = true;
    session.state = 'ready';
    if (session.authTimer !== null) {
      clearTimeout(session.authTimer);
      session.authTimer = null;
    }

    const retained = registry.retainedFor(result.roomId, Date.now());
    const payload: Record<string, unknown> = {
      v: 1,
      type: 'auth_ok',
      conn_id: session.conn.id,
      peers: joined.peers,
      has_retained: retained !== null,
    };
    if (retained !== null) payload['stored_at'] = retained.storedAtMs;
    sendJson(session, payload);

    log.info('auth_ok', {
      conn: session.conn.id,
      room: roomLogId(result.roomId),
      count: joined.peers,
    });
    broadcastPresence(result.roomId);
  }

  function deliver(session: Session, frame: string): void {
    if (session.ws.readyState !== session.ws.OPEN) return;

    if (shouldPark(session.ws.bufferedAmount, config.backpressureSoftBytes)) {
      // Last write wins, so the newest clip simply replaces whatever was waiting. This bounds
      // per connection memory to one message regardless of how slow the peer is.
      session.pendingClip = frame;
      if (session.backpressureSinceMs === null) session.backpressureSinceMs = Date.now();
      log.debug('backpressure', { conn: session.conn.id, bytes: session.ws.bufferedAmount });
      return;
    }
    session.ws.send(frame);
  }

  function handleClip(session: Session, raw: NodeBuffer, message: ReturnType<typeof parseFrame>): void {
    if (!message.ok) return;
    const clip = validateClip(message.message, config.maxFrameBytes);
    if (clip === null) {
      sendError(session, 'MALFORMED', 'clip failed validation');
      session.ws.close(4005, 'MALFORMED');
      return;
    }
    if (clip.roomText.toUpperCase() !== session.conn.roomId) {
      session.ws.close(4005, 'ROOM_MISMATCH');
      return;
    }

    const now = Date.now();
    let quota = roomQuotas.get(session.conn.roomId);
    if (quota === undefined) {
      quota = new RollingQuota(config.roomBytesPerDay, 24 * 60 * 60 * 1000, now);
      roomQuotas.set(session.conn.roomId, quota);
    }
    if (!quota.charge(raw.length, now)) {
      log.warn('quota_exceeded', { conn: session.conn.id, room: roomLogId(session.conn.roomId) });
      sendError(session, 'QUOTA_EXCEEDED', 'room daily quota exhausted', quota.retryAfterMs(now));
      session.ws.close(4008, 'QUOTA_EXCEEDED');
      return;
    }

    if (registry.isDuplicate(session.conn.roomId, clip.msgIdText)) {
      log.debug('clip_dropped', { conn: session.conn.id, msg: clip.msgIdText, code: 'duplicate' });
      return;
    }

    const frame = raw.toString('utf8');
    let delivered = 0;
    for (const peer of sessions) {
      if (peer === session) continue;
      if (peer.state !== 'ready' || peer.conn.roomId !== session.conn.roomId) continue;
      deliver(peer, frame);
      delivered += 1;
    }

    // Stored as raw bytes, decoded once, never kept as a parsed object.
    registry.retain(session.conn.roomId, Buffer.from(raw), clip.msgIdText, now);

    log.debug('clip_forward', {
      conn: session.conn.id,
      room: roomLogId(session.conn.roomId),
      bytes: raw.length,
      count: delivered,
    });
  }

  function handleFetchLast(session: Session): void {
    const retained = registry.retainedFor(session.conn.roomId, Date.now());
    if (retained === null) {
      sendError(session, 'NO_RETAINED', 'no clip is currently retained for this room');
      return;
    }

    // The two delivery markers are added here rather than at storage time, so the stored bytes stay
    // exactly what the sender produced. This is the only place the relay parses a clip, and it
    // still never touches the ciphertext.
    const parsed = JSON.parse(retained.frame.toString('utf8')) as Record<string, unknown>;
    parsed['retained'] = true;
    parsed['stored_at'] = retained.storedAtMs;
    sendJson(session, parsed);
    log.debug('fetch_last', { conn: session.conn.id, room: roomLogId(session.conn.roomId) });
  }

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    const now = Date.now();
    const socketAddress = req.socket.remoteAddress ?? '';
    const clientAddress = resolveClientAddress(
      socketAddress,
      req.headers['x-forwarded-for'] as string | undefined,
      config.trustedProxyCidrs,
    );
    const ipKey = rateLimitKey(clientAddress);

    if (wss.clients.size > config.maxConnsGlobal) {
      log.warn('conn_rejected', { code: 'global_cap' });
      ws.close(4009, 'too many connections');
      return;
    }

    const admission = ipLimiter.admit(ipKey, now);
    if (admission !== 'ok') {
      log.warn('conn_rejected', { code: admission });
      ws.close(4009, admission);
      return;
    }

    const session: Session = {
      ws,
      conn: {
        id: `c_${randomBytes(4).toString('hex')}`,
        roomId: '',
        send: (data: string) => ws.send(data),
        close: (code: number, reason?: string) => ws.close(code, reason),
      },
      state: 'connected',
      nonce: { issued: null },
      ipKey,
      authTimer: null,
      missedPongs: 0,
      msgBucket: new TokenBucket(config.msgBurst, config.msgsPerSec, now),
      byteBucket: new TokenBucket(config.byteBurst, config.bytesPerSec, now),
      rateStrikes: 0,
      pendingClip: null,
      backpressureSinceMs: null,
      joined: false,
    };
    sessions.add(session);
    log.debug('conn_open', { conn: session.conn.id });

    session.authTimer = setTimeout(() => {
      if (session.state !== 'ready') failAuth(session, 'AUTH_TIMEOUT');
    }, config.authTimeoutMs);
    session.authTimer.unref?.();

    ws.on('pong', () => {
      session.missedPongs = 0;
    });

    ws.on('message', (data: RawData, isBinary: boolean) => {
      // v1 is text frames only. A binary frame is either a bug or a probe.
      if (isBinary) {
        session.ws.close(4005, 'binary frames are not used in v1');
        return;
      }
      const raw = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
      const nowMs = Date.now();

      if (!session.msgBucket.take(1, nowMs) || !session.byteBucket.take(raw.length, nowMs)) {
        session.rateStrikes += 1;
        const retryAfter = session.msgBucket.retryAfterMs(1, nowMs);
        log.warn('rate_limited', { conn: session.conn.id, count: session.rateStrikes });
        if (session.rateStrikes > 3) {
          session.ws.close(4007, 'RATE_LIMITED');
          return;
        }
        sendError(session, 'RATE_LIMITED', 'slow down', retryAfter);
        return;
      }

      const parsed = parseFrame(raw, config.maxFrameBytes);
      if (!parsed.ok) {
        if (parsed.code === 'UNKNOWN_TYPE') {
          sendError(session, 'UNKNOWN_TYPE', 'unknown message type');
          return;
        }
        log.warn('protocol_error', { conn: session.conn.id, code: parsed.code });
        sendError(session, parsed.code, 'message rejected');
        session.ws.close(parsed.close, parsed.code);
        return;
      }

      const type = parsed.message.type;

      if (session.state === 'connected') {
        if (type !== 'hello') {
          session.ws.close(4005, 'hello must be first');
          return;
        }
        handleHello(session, parsed);
        return;
      }

      if (session.state === 'challenged') {
        if (type !== 'auth') {
          session.ws.close(4005, 'auth must follow challenge');
          return;
        }
        handleAuth(session, parsed);
        return;
      }

      switch (type) {
        case 'clip':
          handleClip(session, raw, parsed);
          return;
        case 'fetch_last':
          handleFetchLast(session);
          return;
        case 'ping': {
          const payload: Record<string, unknown> = { v: 1, type: 'pong' };
          const t = parsed.message['t'];
          if (typeof t === 'number') payload['t'] = t;
          sendJson(session, payload);
          return;
        }
        case 'pong':
          return;
        default:
          // hello or auth arriving again on an authenticated connection is a client bug.
          session.ws.close(4005, 'unexpected message for this state');
      }
    });

    ws.on('close', (code: number) => {
      if (session.authTimer !== null) clearTimeout(session.authTimer);
      sessions.delete(session);
      ipLimiter.release(session.ipKey, Date.now());
      if (session.joined) {
        const roomId = session.conn.roomId;
        registry.leave(session.conn, Date.now());
        broadcastPresence(roomId);
      }
      log.debug('conn_close', { conn: session.conn.id, close: code });
    });

    ws.on('error', () => {
      // A socket level error is not worth a log line with any detail: it is almost always a peer
      // that vanished. The close handler does the cleanup.
      session.ws.terminate();
    });
  });

  const heartbeat = setInterval(() => {
    for (const session of sessions) {
      if (session.missedPongs >= 2) {
        // A half open socket never completes a graceful close, so terminate rather than close.
        session.ws.terminate();
        continue;
      }
      session.missedPongs += 1;
      session.ws.ping();
    }
  }, config.heartbeatIntervalMs);
  heartbeat.unref?.();

  const flusher = setInterval(() => {
    const now = Date.now();
    for (const session of sessions) {
      if (session.pendingClip !== null && session.ws.bufferedAmount === 0) {
        const frame = session.pendingClip;
        session.pendingClip = null;
        session.backpressureSinceMs = null;
        session.ws.send(frame);
        continue;
      }
      if (
        session.backpressureSinceMs !== null &&
        session.ws.bufferedAmount > config.backpressureHardBytes &&
        now - session.backpressureSinceMs > config.backpressureGraceMs
      ) {
        log.warn('backpressure', { conn: session.conn.id, bytes: session.ws.bufferedAmount });
        session.ws.close(1009, 'send buffer stalled');
      }
    }
  }, 250);
  flusher.unref?.();

  const sweeper = setInterval(() => {
    const now = Date.now();
    registry.sweep(now);
    ipLimiter.sweep(now, 10 * 60 * 1000);
    for (const [roomId, quota] of roomQuotas) {
      if (quota.retryAfterMs(now) === 0 && registry.peers(roomId) === 0) roomQuotas.delete(roomId);
    }
  }, 60_000);
  sweeper.unref?.();

  return {
    httpServer,
    wss,
    port: () => {
      const address = httpServer.address();
      return typeof address === 'object' && address !== null ? address.port : config.port;
    },
    close: async () => {
      clearInterval(heartbeat);
      clearInterval(flusher);
      clearInterval(sweeper);
      registry.clearTimers();

      // 1001 tells clients this is a restart, so they reconnect with backoff and jitter rather
      // than treating it as a fatal error.
      for (const session of sessions) session.ws.close(1001, 'server going away');

      await new Promise<void>((resolve) => {
        wss.close(() => resolve());
      });
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      });
      if (metricsServer !== null) {
        await new Promise<void>((resolve) => {
          metricsServer.close(() => resolve());
        });
      }
      log.info('shutdown');
    },
  };
}
