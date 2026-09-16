/**
 * The Ed25519 challenge response handshake.
 *
 * The relay stores no per room secret and no first sight state. It verifies that the presented
 * room id really is the hash of the presented public key, and that the client can sign a nonce the
 * relay just generated. That is the whole of it, and it is why a compromised relay database grants
 * an attacker nothing: there is no stored credential to steal.
 *
 * Checks run in the order given in docs/PROTOCOL.md section 8.2 and fail closed at the first
 * failure.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { Buffer as NodeBuffer } from 'node:buffer';

import { decodeCrockford } from './base32.ts';
import type { AuthFields } from './validate.ts';

const LABEL_ROOM = Buffer.from('asli/v1/room', 'ascii');
const LABEL_AUTH = Buffer.from('asli/v1/auth', 'ascii');

/** Fixed length of the signature input. Any drift here is an interoperability break. */
export const SIG_INPUT_LEN = 121;

export type AuthFailCode =
  | 'MALFORMED_AUTH'
  | 'ROOM_MISMATCH'
  | 'STALE_NONCE'
  | 'BAD_SIGNATURE'
  | 'AUTH_TIMEOUT'
  | 'UNSUPPORTED_VERSION';

export type AuthResult =
  | { ok: true; roomId: string; roomIdBytes: NodeBuffer }
  | { ok: false; code: AuthFailCode; close: number };

/** Close code that accompanies each failure, per docs/PROTOCOL.md section 7.5. */
export const AUTH_FAIL_CLOSE: Record<AuthFailCode, number> = {
  UNSUPPORTED_VERSION: 4004,
  BAD_SIGNATURE: 4002,
  ROOM_MISMATCH: 4003,
  MALFORMED_AUTH: 4005,
  STALE_NONCE: 4005,
  AUTH_TIMEOUT: 4001,
};

function failure(code: AuthFailCode): AuthResult {
  return { ok: false, code, close: AUTH_FAIL_CLOSE[code] };
}

/** Computes the room id bytes that belong to a public key. */
export function roomIdForPublicKey(pubKey: NodeBuffer): NodeBuffer {
  return createHash('sha256').update(LABEL_ROOM).update(pubKey).digest().subarray(0, 16);
}

/**
 * Builds the exact 121 bytes that the client signed.
 *
 * Assembled from Buffers rather than by serializing JSON, because JSON key order, whitespace and
 * number formatting are not canonical and two implementations would eventually disagree about the
 * bytes they are signing.
 */
export function buildSigInput(params: {
  version: number;
  roomIdBytes: NodeBuffer;
  pubKey: NodeBuffer;
  nonceS: NodeBuffer;
  nonceC: NodeBuffer;
  clientTimeMs: number;
}): NodeBuffer {
  const time = Buffer.alloc(8);
  time.writeBigUInt64BE(BigInt(params.clientTimeMs));

  const input = Buffer.concat([
    LABEL_AUTH,
    Buffer.from([params.version]),
    Buffer.from([16]),
    params.roomIdBytes,
    Buffer.from([32]),
    params.pubKey,
    Buffer.from([32]),
    params.nonceS,
    Buffer.from([16]),
    params.nonceC,
    time,
  ]);

  if (input.length !== SIG_INPUT_LEN) {
    // Unreachable unless a length above changed, which would be a protocol break.
    throw new Error(`signature input must be ${SIG_INPUT_LEN} bytes, built ${input.length}`);
  }
  return input;
}

/** Wraps a raw 32 byte Ed25519 public key as a KeyObject, or returns null if it is not valid. */
function publicKeyFromRaw(pubKey: NodeBuffer): KeyObject | null {
  try {
    return createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: pubKey.toString('base64url'),
      },
      format: 'jwk',
    });
  } catch {
    return null;
  }
}

export type NonceState = {
  /** The nonce issued to this connection, or null once it has been consumed. */
  issued: NodeBuffer | null;
};

/**
 * Verifies an auth message.
 *
 * `nonceState` is mutated: the issued nonce is invalidated on first use whether or not the
 * remaining checks pass. A connection that fails auth is not given a second challenge, so a client
 * that wants another attempt reconnects, which is also what makes the 10 second timeout meaningful.
 */
export function verifyAuth(
  fields: AuthFields,
  nonceState: NonceState,
  timedOut: boolean,
): AuthResult {
  // Step 1: the room id must decode to exactly 16 bytes.
  const roomIdBytes = decodeCrockford(fields.roomText, 16);
  if (roomIdBytes === null) return failure('MALFORMED_AUTH');

  // Step 2: the public key must be a valid Ed25519 encoding. Steps 3 (lengths) already happened
  // during shape validation.
  const key = publicKeyFromRaw(fields.pubKey);
  if (key === null) return failure('MALFORMED_AUTH');

  // Step 4: the room id must be the hash of this public key. No trust on first use, no stored
  // state, no room squatting.
  const expected = roomIdForPublicKey(fields.pubKey);
  if (!expected.equals(roomIdBytes)) return failure('ROOM_MISMATCH');

  // Step 5: the challenge nonce must be the one issued to this connection, and is consumed now.
  const nonceS = nonceState.issued;
  nonceState.issued = null;
  if (nonceS === null) return failure('STALE_NONCE');

  // Step 6: the signature must verify over the reconstructed input.
  const sigInput = buildSigInput({
    version: 1,
    roomIdBytes,
    pubKey: fields.pubKey,
    nonceS,
    nonceC: fields.nonceC,
    clientTimeMs: fields.clientTimeMs,
  });

  let verified = false;
  try {
    verified = cryptoVerify(null, sigInput, key, fields.sig);
  } catch {
    verified = false;
  }
  if (!verified) return failure('BAD_SIGNATURE');

  // Step 7: the handshake must have completed inside the auth timeout.
  if (timedOut) return failure('AUTH_TIMEOUT');

  return { ok: true, roomId: fields.roomText.toUpperCase(), roomIdBytes };
}
