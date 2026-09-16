/**
 * Chunk validation and accounting.
 *
 * The relay never opens a chunk, so these cover the part it is actually responsible for: refusing
 * nonsense positions cheaply, and the field allowlist that keeps protocol drift visible.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseFrame, validateChunk, MAX_CHUNKS } from '../src/validate.ts';

const ROOM = 'PAJJVF67VX0M0RJKZ0FDAD8B2M';
const MSG_ID = Buffer.alloc(16, 0xb0).toString('base64');
const NONCE = Buffer.alloc(24, 0x10).toString('base64');
const CT = Buffer.alloc(64, 0x22).toString('base64');
const MAX_FRAME = 1024 * 1024;

function chunkFrame(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    type: 'clip_begin',
    room: ROOM,
    epoch: 0,
    msg_id: MSG_ID,
    idx: 0,
    chunk_count: 4,
    n: NONCE,
    ct: CT,
    ...overrides,
  });
}

function parsed(frame: string) {
  const result = parseFrame(frame, MAX_FRAME);
  assert.equal(result.ok, true, 'frame should parse');
  return result.ok ? result.message : null;
}

test('all three chunk types are known to the parser', () => {
  for (const type of ['clip_begin', 'clip_chunk', 'clip_end']) {
    const result = parseFrame(chunkFrame({ type }), MAX_FRAME);
    assert.equal(result.ok, true, `${type} should be accepted`);
  }
});

test('a valid chunk passes validation', () => {
  const fields = validateChunk(parsed(chunkFrame())!, MAX_FRAME);
  assert.notEqual(fields, null);
  assert.equal(fields?.idx, 0);
  assert.equal(fields?.chunkCount, 4);
  assert.equal(fields?.roomText, ROOM);
});

test('an index at or beyond the declared count is refused', () => {
  // idx is zero based, so idx 4 of 4 is outside the run and can never complete.
  assert.equal(validateChunk(parsed(chunkFrame({ idx: 4 }))!, MAX_FRAME), null);
  assert.equal(validateChunk(parsed(chunkFrame({ idx: 99 }))!, MAX_FRAME), null);
});

test('a chunk count beyond the cap is refused', () => {
  // The cap is what stops a hostile count from driving an allocation on the receiving side.
  assert.equal(
    validateChunk(parsed(chunkFrame({ chunk_count: MAX_CHUNKS + 1, idx: 0 }))!, MAX_FRAME),
    null,
  );
  assert.equal(validateChunk(parsed(chunkFrame({ chunk_count: 0 }))!, MAX_FRAME), null);
});

test('negative and non integer positions are refused', () => {
  assert.equal(validateChunk(parsed(chunkFrame({ idx: -1 }))!, MAX_FRAME), null);
  assert.equal(validateChunk(parsed(chunkFrame({ idx: 1.5 }))!, MAX_FRAME), null);
  assert.equal(validateChunk(parsed(chunkFrame({ chunk_count: 2.5 }))!, MAX_FRAME), null);
});

test('a wrong length nonce or message id is refused', () => {
  const shortNonce = Buffer.alloc(8, 1).toString('base64');
  assert.equal(validateChunk(parsed(chunkFrame({ n: shortNonce }))!, MAX_FRAME), null);
  const shortId = Buffer.alloc(4, 1).toString('base64');
  assert.equal(validateChunk(parsed(chunkFrame({ msg_id: shortId }))!, MAX_FRAME), null);
});

test('ciphertext shorter than a tag is refused', () => {
  const tiny = Buffer.alloc(4, 7).toString('base64');
  assert.equal(validateChunk(parsed(chunkFrame({ ct: tiny }))!, MAX_FRAME), null);
});

test('an unknown field on a chunk is rejected by the parser', () => {
  // Field drift has to surface immediately rather than be silently ignored.
  const result = parseFrame(chunkFrame({ surprise: 1 }), MAX_FRAME);
  assert.equal(result.ok, false);
});

test('a clip field set is not accepted on a chunk type', () => {
  // A clip carries no idx or chunk_count, so sending one as a chunk must fail the allowlist.
  const frame = JSON.stringify({
    v: 1,
    type: 'clip_begin',
    room: ROOM,
    epoch: 0,
    msg_id: MSG_ID,
    n: NONCE,
    ct: CT,
  });
  const message = parsed(frame);
  assert.equal(validateChunk(message!, MAX_FRAME), null);
});
