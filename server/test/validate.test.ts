import assert from 'node:assert/strict';
import test from 'node:test';

import {
  decodeAtLeast,
  decodeExact,
  parseFrame,
  validateAuth,
  validateClip,
  validateHello,
} from '../src/validate.ts';
import type { Envelope } from '../src/validate.ts';

const MAX = 1024 * 1024;

function frame(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function envelope(value: Record<string, unknown>): Envelope {
  const parsed = parseFrame(frame(value), MAX);
  assert.equal(parsed.ok, true, 'fixture should parse');
  if (!parsed.ok) throw new Error('unreachable');
  return parsed.message;
}

test('rejects a frame larger than the cap before parsing it', () => {
  const huge = Buffer.alloc(MAX + 1, 0x20);
  const result = parseFrame(huge, MAX);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, 'MESSAGE_TOO_LARGE');
  assert.equal(result.close, 4006);
});

test('rejects malformed json without throwing', () => {
  for (const bad of ['{', 'not json', '', '[1,2,3]', 'null', '"string"', '42']) {
    const result = parseFrame(Buffer.from(bad, 'utf8'), MAX);
    assert.equal(result.ok, false, `expected rejection for ${JSON.stringify(bad)}`);
  }
});

test('rejects an unsupported protocol version', () => {
  const result = parseFrame(frame({ v: 2, type: 'hello' }), MAX);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.close, 4004);
});

test('rejects an unknown message type but keeps the connection open', () => {
  const result = parseFrame(frame({ v: 1, type: 'nonsense' }), MAX);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, 'UNKNOWN_TYPE');
});

test('rejects unknown fields inside a known type', () => {
  const result = parseFrame(frame({ v: 1, type: 'fetch_last', extra: true }), MAX);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, 'MALFORMED');
});

test('does not inherit prototype pollution from input keys', () => {
  const result = parseFrame(
    Buffer.from('{"v":1,"type":"fetch_last","__proto__":{"polluted":true}}', 'utf8'),
    MAX,
  );
  // Either it is rejected as an unknown field, or the object is null prototyped. Both are safe.
  if (result.ok) {
    assert.equal(Object.getPrototypeOf(result.message), null);
  }
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

test('base64 decoding is strict about alphabet, padding and length', () => {
  const sixteen = Buffer.alloc(16, 7).toString('base64');
  assert.notEqual(decodeExact(sixteen, 16), null);

  // base64url is deliberately not accepted in the JSON envelope.
  assert.equal(decodeExact(sixteen.replace(/\+/g, '-').replace(/\//g, '_') + 'x', 16), null);
  assert.equal(decodeExact(`${sixteen} `, 16), null);
  assert.equal(decodeExact(sixteen, 24), null);
  assert.equal(decodeExact('', 16), null);
  assert.equal(decodeExact(42, 16), null);
  assert.equal(decodeExact('*'.repeat(24), 16), null);
  // A long string in a fixed size field is rejected on length, before any decode work.
  assert.equal(decodeExact('A'.repeat(5000), 16), null);
});

test('ciphertext decoding enforces a minimum length', () => {
  const short = Buffer.alloc(8, 1).toString('base64');
  assert.equal(decodeAtLeast(short, 17, 5000), null);
  const ok = Buffer.alloc(40, 1).toString('base64');
  assert.notEqual(decodeAtLeast(ok, 17, 5000), null);
});

test('hello validation requires the suite and encoding arrays', () => {
  assert.notEqual(
    validateHello(envelope({ v: 1, type: 'hello', suites: ['asli-v1'], enc: ['json'] })),
    null,
  );
  assert.equal(validateHello(envelope({ v: 1, type: 'hello', suites: [], enc: ['json'] })), null);
  assert.equal(
    validateHello(envelope({ v: 1, type: 'hello', suites: ['asli-v1'], enc: 'json' })),
    null,
  );
  assert.equal(
    validateHello(
      envelope({ v: 1, type: 'hello', suites: ['asli-v1'], enc: ['json'], client: 'x'.repeat(65) }),
    ),
    null,
  );
});

test('auth validation enforces every field length', () => {
  const base = {
    v: 1,
    type: 'auth',
    room: 'E5V0APG0E0QQ5MEGA99JBPFDHM',
    pub_key: Buffer.alloc(32, 3).toString('base64'),
    nonce_c: Buffer.alloc(16, 4).toString('base64'),
    client_time_ms: 1_767_225_600_000,
    sig: Buffer.alloc(64, 5).toString('base64'),
  };
  assert.notEqual(validateAuth(envelope(base)), null);

  assert.equal(validateAuth(envelope({ ...base, room: 'TOOSHORT' })), null);
  assert.equal(validateAuth(envelope({ ...base, pub_key: Buffer.alloc(31, 3).toString('base64') })), null);
  assert.equal(validateAuth(envelope({ ...base, nonce_c: Buffer.alloc(15, 4).toString('base64') })), null);
  assert.equal(validateAuth(envelope({ ...base, sig: Buffer.alloc(63, 5).toString('base64') })), null);
  assert.equal(validateAuth(envelope({ ...base, client_time_ms: -1 })), null);
  assert.equal(validateAuth(envelope({ ...base, client_time_ms: 1.5 })), null);
});

test('clip validation enforces field sizes and the epoch range', () => {
  const base = {
    v: 1,
    type: 'clip',
    room: 'E5V0APG0E0QQ5MEGA99JBPFDHM',
    epoch: 0,
    msg_id: Buffer.alloc(16, 9).toString('base64'),
    n: Buffer.alloc(24, 8).toString('base64'),
    ct: Buffer.alloc(64, 7).toString('base64'),
  };
  assert.notEqual(validateClip(envelope(base), MAX), null);

  assert.equal(validateClip(envelope({ ...base, epoch: -1 }), MAX), null);
  assert.equal(validateClip(envelope({ ...base, epoch: 0x1_0000_0000 }), MAX), null);
  assert.equal(validateClip(envelope({ ...base, n: Buffer.alloc(23, 8).toString('base64') }), MAX), null);
  assert.equal(validateClip(envelope({ ...base, msg_id: Buffer.alloc(17, 9).toString('base64') }), MAX), null);
  // Ciphertext must carry at least one byte plus the sixteen byte tag.
  assert.equal(validateClip(envelope({ ...base, ct: Buffer.alloc(16, 7).toString('base64') }), MAX), null);
});
