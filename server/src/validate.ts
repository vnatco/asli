/**
 * Hand written validation for the only untrusted input surface this process has.
 *
 * A schema library would be more ergonomic, but this is six message types with fixed fields sitting
 * in the hottest path on a public relay, and the smallest possible dependency footprint is worth
 * more here than ergonomics. The order of operations below matters more than the implementation:
 * see docs/PROTOCOL.md
 */

import type { Buffer as NodeBuffer } from 'node:buffer';

/** Largest base64 string we will even attempt to decode for a fixed size field. */
const SHORT_FIELD_MAX_CHARS = 128;
/** Longest room id string. 16 bytes of Crockford base32 is 26 characters. */
const ROOM_CHARS = 26;

export type ParseFailure = {
  ok: false;
  /** Error code from the closed enum in docs/PROTOCOL.md section 12.2. */
  code: 'MALFORMED' | 'UNKNOWN_TYPE' | 'MESSAGE_TOO_LARGE';
  /** Close code to use if this failure is fatal. */
  close: number;
};

export type Envelope = {
  v: number;
  type: string;
  [key: string]: unknown;
};

export type ParseSuccess = { ok: true; message: Envelope };
export type ParseResult = ParseSuccess | ParseFailure;

const KNOWN_TYPES = new Set([
  'hello',
  'auth',
  'clip',
  'clip_begin',
  'clip_chunk',
  'clip_end',
  'fetch_last',
  'ping',
  'pong',
]);

/** The three chunk types carry identical fields and differ only in position. */
const CHUNK_FIELDS = new Set([
  'v',
  'type',
  'room',
  'epoch',
  'msg_id',
  'idx',
  'chunk_count',
  'n',
  'ct',
]);

const ALLOWED_FIELDS: Record<string, ReadonlySet<string>> = {
  hello: new Set(['v', 'type', 'suites', 'enc', 'client']),
  auth: new Set(['v', 'type', 'room', 'pub_key', 'nonce_c', 'client_time_ms', 'sig']),
  clip: new Set(['v', 'type', 'room', 'epoch', 'msg_id', 'n', 'ct']),
  clip_begin: CHUNK_FIELDS,
  clip_chunk: CHUNK_FIELDS,
  clip_end: CHUNK_FIELDS,
  fetch_last: new Set(['v', 'type']),
  ping: new Set(['v', 'type', 't']),
  pong: new Set(['v', 'type', 't']),
};

function fail(code: ParseFailure['code'], close: number): ParseFailure {
  return { ok: false, code, close };
}

/** Strict base64 decode with an exact expected length. */
export function decodeExact(value: unknown, expectedBytes: number): NodeBuffer | null {
  if (typeof value !== 'string') return null;
  // Length is checked before decoding, so a 1 MiB string in a 24 byte field costs nothing.
  if (value.length > SHORT_FIELD_MAX_CHARS) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  let decoded: NodeBuffer;
  try {
    decoded = Buffer.from(value, 'base64');
  } catch {
    return null;
  }
  // Buffer.from is lenient, so the round trip is what actually enforces strictness.
  if (decoded.length !== expectedBytes) return null;
  if (decoded.toString('base64') !== value) return null;
  return decoded;
}

/** Strict base64 decode with a minimum length, used for ciphertext. */
export function decodeAtLeast(value: unknown, minBytes: number, maxChars: number): NodeBuffer | null {
  if (typeof value !== 'string') return null;
  if (value.length > maxChars) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length < minBytes) return null;
  if (decoded.toString('base64') !== value) return null;
  return decoded;
}

/**
 * Parses one frame.
 *
 * Steps, in this order and for these reasons:
 * 1. Size before parse. Parsing a hostile 1 MiB document in order to reject it is the mistake.
 * 2. Parse inside try/catch. An uncaught parse throw on a public relay is a crash.
 * 3. Reject non objects, arrays and null before touching any field.
 * 4. Reject unknown top level fields, so protocol drift surfaces immediately.
 */
export function parseFrame(raw: NodeBuffer | string, maxFrameBytes: number): ParseResult {
  const size = typeof raw === 'string' ? Buffer.byteLength(raw) : raw.length;
  if (size > maxFrameBytes) return fail('MESSAGE_TOO_LARGE', 4006);

  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof raw === 'string' ? raw : raw.toString('utf8'));
  } catch {
    return fail('MALFORMED', 4005);
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return fail('MALFORMED', 4005);
  }

  const source = parsed as Record<string, unknown>;

  // Never build an object from untrusted keys without a null prototype, or __proto__ and
  // constructor become an attack on every later property access.
  const message = Object.assign(Object.create(null) as Envelope, source) as Envelope;

  if (message.v !== 1) return fail('MALFORMED', 4004);
  if (typeof message.type !== 'string') return fail('MALFORMED', 4005);
  if (!KNOWN_TYPES.has(message.type)) return fail('UNKNOWN_TYPE', 4005);

  const allowed = ALLOWED_FIELDS[message.type];
  if (allowed === undefined) return fail('UNKNOWN_TYPE', 4005);
  for (const key of Object.keys(source)) {
    if (!allowed.has(key)) return fail('MALFORMED', 4005);
  }

  return { ok: true, message };
}

export type HelloFields = { suites: string[]; enc: string[] };

/** Validates `hello`, which must be the first message on a connection. */
export function validateHello(message: Envelope): HelloFields | null {
  const suites = message['suites'];
  const enc = message['enc'];
  if (!Array.isArray(suites) || suites.length === 0 || suites.length > 8) return null;
  if (!Array.isArray(enc) || enc.length === 0 || enc.length > 8) return null;
  if (!suites.every((s) => typeof s === 'string' && s.length <= 32)) return null;
  if (!enc.every((e) => typeof e === 'string' && e.length <= 32)) return null;
  const client = message['client'];
  if (client !== undefined && (typeof client !== 'string' || client.length > 64)) return null;
  return { suites: suites as string[], enc: enc as string[] };
}

export type AuthFields = {
  roomText: string;
  pubKey: NodeBuffer;
  nonceC: NodeBuffer;
  clientTimeMs: number;
  sig: NodeBuffer;
};

/** Validates the shape of `auth`. Cryptographic checks happen in auth.ts, in the documented order. */
export function validateAuth(message: Envelope): AuthFields | null {
  const roomText = message['room'];
  if (typeof roomText !== 'string' || roomText.length !== ROOM_CHARS) return null;

  const pubKey = decodeExact(message['pub_key'], 32);
  if (pubKey === null) return null;

  const nonceC = decodeExact(message['nonce_c'], 16);
  if (nonceC === null) return null;

  const sig = decodeExact(message['sig'], 64);
  if (sig === null) return null;

  const clientTimeMs = message['client_time_ms'];
  if (typeof clientTimeMs !== 'number' || !Number.isSafeInteger(clientTimeMs) || clientTimeMs < 0) {
    return null;
  }

  return { roomText, pubKey, nonceC, clientTimeMs, sig };
}

export type ClipFields = {
  roomText: string;
  epoch: number;
  msgIdText: string;
  msgId: NodeBuffer;
  nonce: NodeBuffer;
  ciphertextBytes: number;
};

/** Validates the shape of `clip`. The relay never decodes the ciphertext beyond measuring it. */
export function validateClip(message: Envelope, maxFrameChars: number): ClipFields | null {
  const roomText = message['room'];
  if (typeof roomText !== 'string' || roomText.length !== ROOM_CHARS) return null;

  const epoch = message['epoch'];
  if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 0 || epoch > 0xffff_ffff) {
    return null;
  }

  const msgIdText = message['msg_id'];
  const msgId = decodeExact(msgIdText, 16);
  if (msgId === null || typeof msgIdText !== 'string') return null;

  const nonce = decodeExact(message['n'], 24);
  if (nonce === null) return null;

  // At least one byte of ciphertext plus the 16 byte Poly1305 tag.
  const ciphertext = decodeAtLeast(message['ct'], 17, maxFrameChars);
  if (ciphertext === null) return null;

  return { roomText, epoch, msgIdText, msgId, nonce, ciphertextBytes: ciphertext.length };
}

/** Upper bound on chunks per message, matching the crypto layer's cap. */
export const MAX_CHUNKS = 4096;

export type ChunkFields = {
  roomText: string;
  epoch: number;
  msgIdText: string;
  idx: number;
  chunkCount: number;
  ciphertextBytes: number;
};

/**
 * Validates the shape of a chunk message.
 *
 * The relay never opens a chunk, so this checks only what routing and accounting need: that the
 * position fields are plausible integers within the cap, and that the ciphertext is present. The
 * cryptographic binding of idx and chunk_count is the receiver's business, and it is what actually
 * prevents a reordered chunk from being accepted.
 */
export function validateChunk(message: Envelope, maxFrameChars: number): ChunkFields | null {
  const roomText = message['room'];
  if (typeof roomText !== 'string' || roomText.length !== ROOM_CHARS) return null;

  const epoch = message['epoch'];
  if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 0 || epoch > 0xffff_ffff) {
    return null;
  }

  const msgIdText = message['msg_id'];
  const msgId = decodeExact(msgIdText, 16);
  if (msgId === null || typeof msgIdText !== 'string') return null;

  const idx = message['idx'];
  const chunkCount = message['chunk_count'];
  if (typeof idx !== 'number' || !Number.isInteger(idx) || idx < 0) return null;
  if (typeof chunkCount !== 'number' || !Number.isInteger(chunkCount)) return null;
  if (chunkCount < 1 || chunkCount > MAX_CHUNKS) return null;
  // An index outside the declared run is nonsense that never needs forwarding.
  if (idx >= chunkCount) return null;

  const nonce = decodeExact(message['n'], 24);
  if (nonce === null) return null;

  const ciphertext = decodeAtLeast(message['ct'], 17, maxFrameChars);
  if (ciphertext === null) return null;

  return { roomText, epoch, msgIdText, idx, chunkCount, ciphertextBytes: ciphertext.length };
}
