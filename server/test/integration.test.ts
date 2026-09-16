/**
 * End to end tests against a real relay over real sockets.
 *
 * The clients here perform the genuine handshake with the frozen key material from
 * testdata/vectors.json, so this exercises the same path a desktop client takes: hello, challenge,
 * a signature over the server nonce, then clip traffic.
 */

import assert from 'node:assert/strict';
import { createPrivateKey, randomBytes, sign as edSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { WebSocket } from 'ws';

import { buildSigInput } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { createRelay, shouldPark } from '../src/server.ts';
import type { Relay } from '../src/server.ts';

type Vectors = {
  sign_seed: string;
  pub_key: string;
  room_id: string;
  room_id_bytes: string;
};

const vectors = JSON.parse(
  readFileSync(new URL('../../testdata/vectors.json', import.meta.url), 'utf8'),
) as Vectors;

const pubKey = Buffer.from(vectors.pub_key, 'hex');
const roomIdBytes = Buffer.from(vectors.room_id_bytes, 'hex');
const ROOM = vectors.room_id;

// Ed25519 private keys are the 32 byte seed. JWK is the least awkward way into a KeyObject.
const privateKey = createPrivateKey({
  key: {
    kty: 'OKP',
    crv: 'Ed25519',
    x: pubKey.toString('base64url'),
    d: Buffer.from(vectors.sign_seed, 'hex').toString('base64url'),
  },
  format: 'jwk',
});

type Json = Record<string, unknown>;

/** A tiny client that queues inbound messages so tests can await them in order. */
class TestClient {
  private readonly queue: Json[] = [];
  private waiter: ((message: Json) => void) | null = null;

  readonly ws: WebSocket;

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.on('message', (data) => {
      const message = JSON.parse(data.toString()) as Json;
      if (this.waiter !== null) {
        const resolve = this.waiter;
        this.waiter = null;
        resolve(message);
        return;
      }
      this.queue.push(message);
    });
  }

  static async open(port: number): Promise<TestClient> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1`);
    const client = new TestClient(ws);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });
    return client;
  }

  next(timeoutMs = 3000): Promise<Json> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise<Json>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new Error('timed out waiting for a message'));
      }, timeoutMs);
      this.waiter = (message) => {
        clearTimeout(timer);
        resolve(message);
      };
    });
  }

  /** Waits for a message of a given type, skipping presence chatter. */
  async nextOfType(type: string, timeoutMs = 3000): Promise<Json> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const remaining = Math.max(1, deadline - Date.now());
      const message = await this.next(remaining);
      if (message['type'] === type) return message;
    }
  }

  /**
   * Asserts that no clip arrives within the window.
   *
   * Presence frames are expected and are not what these assertions are about: a peer joining or
   * leaving legitimately produces one. What must never arrive is a clip, which is what proves
   * sender exclusion and proves that a retained clip is never pushed without being asked for.
   */
  async expectNoClip(windowMs = 400): Promise<void> {
    const deadline = Date.now() + windowMs;
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) return;
      let message: Json;
      try {
        message = await this.next(remaining);
      } catch {
        return; // Timed out, which is the silence being asserted.
      }
      assert.notEqual(message['type'], 'clip', 'no clip should have been delivered here');
    }
  }

  send(message: Json): void {
    this.ws.send(JSON.stringify(message));
  }

  async handshake(): Promise<Json> {
    this.send({ v: 1, type: 'hello', suites: ['asli-v1'], enc: ['json'] });
    const challenge = await this.next();
    assert.equal(challenge['type'], 'challenge');

    const nonceS = Buffer.from(challenge['nonce_s'] as string, 'base64');
    const nonceC = randomBytes(16);
    const clientTimeMs = Date.now();
    const sigInput = buildSigInput({
      version: 1,
      roomIdBytes,
      pubKey,
      nonceS,
      nonceC,
      clientTimeMs,
    });
    const sig = edSign(null, sigInput, privateKey);

    this.send({
      v: 1,
      type: 'auth',
      room: ROOM,
      pub_key: pubKey.toString('base64'),
      nonce_c: nonceC.toString('base64'),
      client_time_ms: clientTimeMs,
      sig: sig.toString('base64'),
    });
    return this.nextOfType('auth_ok');
  }

  close(): void {
    this.ws.close();
  }
}

function clipFrame(msgId: Buffer, ciphertextByte: number): Json {
  return {
    v: 1,
    type: 'clip',
    room: ROOM,
    epoch: 0,
    msg_id: msgId.toString('base64'),
    n: Buffer.alloc(24, 0x41).toString('base64'),
    ct: Buffer.alloc(64, ciphertextByte).toString('base64'),
  };
}

async function withRelay(fn: (port: number) => Promise<void>): Promise<void> {
  // The relay is told to listen on an ephemeral port directly, so PORT is left alone: a port of
  // zero in a real deployment is almost always a typo, and config.ts is right to reject it.
  process.env['METRICS_PORT'] = '0';
  process.env['PRESENCE_DEBOUNCE_MS'] = '0';
  process.env['LOG_LEVEL'] = 'silent';
  process.env['MSG_BURST'] = '200';
  process.env['MSGS_PER_SEC'] = '200';

  const relay: Relay = createRelay(loadConfig());
  await new Promise<void>((resolve) => {
    relay.httpServer.listen(0, '127.0.0.1', () => resolve());
  });
  try {
    await fn(relay.port());
  } finally {
    await relay.close();
  }
}

test('two clients complete the handshake and a clip reaches the peer but not the sender', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    const b = await TestClient.open(port);

    const authA = await a.handshake();
    assert.equal(authA['has_retained'], false);
    assert.equal(typeof authA['conn_id'], 'string');

    const authB = await b.handshake();
    assert.equal(authB['peers'], 2, 'the second client sees both connections');

    const msgId = randomBytes(16);
    a.send(clipFrame(msgId, 0x11));

    const received = await b.nextOfType('clip');
    assert.equal(received['msg_id'], msgId.toString('base64'));
    assert.equal(received['room'], ROOM);
    assert.equal(received['ct'], Buffer.alloc(64, 0x11).toString('base64'));
    assert.equal(received['retained'], undefined, 'live delivery carries no retained marker');

    await a.expectNoClip();

    a.close();
    b.close();
  });
});

test('a duplicate message id is not forwarded twice', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    const b = await TestClient.open(port);
    await a.handshake();
    await b.handshake();

    const msgId = randomBytes(16);
    a.send(clipFrame(msgId, 0x22));
    const first = await b.nextOfType('clip');
    assert.equal(first['msg_id'], msgId.toString('base64'));

    a.send(clipFrame(msgId, 0x22));
    await b.expectNoClip();

    a.close();
    b.close();
  });
});

test('a late joiner fetches the retained clip explicitly and never automatically', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    await a.handshake();

    const msgId = randomBytes(16);
    a.send(clipFrame(msgId, 0x33));
    // Give the relay a moment to retain it.
    await new Promise((resolve) => setTimeout(resolve, 100));

    const late = await TestClient.open(port);
    const authLate = await late.handshake();
    assert.equal(authLate['has_retained'], true);
    assert.equal(typeof authLate['stored_at'], 'number');

    // Nothing is pushed: retrieval is explicit.
    await late.expectNoClip();

    late.send({ v: 1, type: 'fetch_last' });
    const retained = await late.nextOfType('clip');
    assert.equal(retained['retained'], true);
    assert.equal(retained['msg_id'], msgId.toString('base64'));
    assert.equal(typeof retained['stored_at'], 'number');

    a.close();
    late.close();
  });
});

test('fetch_last reports NO_RETAINED when the room holds nothing', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    await a.handshake();
    a.send({ v: 1, type: 'fetch_last' });
    const error = await a.nextOfType('error');
    assert.equal(error['code'], 'NO_RETAINED');
    a.close();
  });
});

test('an unknown message type is reported without dropping the connection', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    await a.handshake();

    a.send({ v: 1, type: 'nonsense' });
    const error = await a.nextOfType('error');
    assert.equal(error['code'], 'UNKNOWN_TYPE');

    // The connection still works afterwards.
    a.send({ v: 1, type: 'ping', t: 7 });
    const pong = await a.nextOfType('pong');
    assert.equal(pong['t'], 7);
    a.close();
  });
});

test('a message before the handshake is refused', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    const closed = new Promise<number>((resolve) => {
      a.ws.once('close', (code: number) => resolve(code));
    });
    a.send({ v: 1, type: 'fetch_last' });
    assert.equal(await closed, 4005);
  });
});

test('a clip for a room the connection did not authenticate is refused', async () => {
  await withRelay(async (port) => {
    const a = await TestClient.open(port);
    await a.handshake();

    const closed = new Promise<number>((resolve) => {
      a.ws.once('close', (code: number) => resolve(code));
    });
    a.send({ ...clipFrame(randomBytes(16), 0x44), room: 'C8V4B1KQ7M3ZRXPT9WNJ0GHA2E' });
    assert.equal(await closed, 4005);
  });
});

test('the health endpoint answers and reveals no counts', async () => {
  await withRelay(async (port) => {
    const response = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.equal(body.trim(), 'ok');
  });
});

test('backpressure parks a frame instead of queueing once the buffer is above the soft limit', () => {
  // The clipboard is last write wins, so a slow peer gets one pending slot, never a queue.
  assert.equal(shouldPark(0, 1024), false);
  assert.equal(shouldPark(1024, 1024), false);
  assert.equal(shouldPark(1025, 1024), true);
});
