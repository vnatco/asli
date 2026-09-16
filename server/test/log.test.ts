/**
 * Tests for the logger.
 *
 * The guarantees worth protecting are not about formatting, they are about what can never reach a
 * log line: content, key material, or anything that was not explicitly named. A logger that leaks
 * a clipboard payload once has undone the point of the whole relay.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { log, roomLogId } from '../src/log.ts';

const logModuleUrl = pathToFileURL(fileURLToPath(new URL('../src/log.ts', import.meta.url))).href;

/** Captures whatever the logger writes to stdout while `body` runs. */
function capture(body: () => void): string[] {
  const written: string[] = [];
  const original = process.stdout.write.bind(process.stdout);
  // The logger writes straight to stdout by design, so the test intercepts the sink rather than
  // the module being given one, which keeps the exported interface free of test seams.
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  }) as typeof process.stdout.write;
  try {
    body();
  } finally {
    process.stdout.write = original;
  }
  return written
    .join('')
    .split('\n')
    .filter((line) => line.length > 0);
}

/** Runs a snippet in a fresh process, so module level state is built again. */
function inChildProcess(snippet: string, env: Record<string, string> = {}): string {
  const script = `const m = await import(${JSON.stringify(logModuleUrl)});\n${snippet}`;
  return execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
}

test('writes one valid JSON object per line', () => {
  const lines = capture(() => {
    log.info('listening', { port: 3006 });
    log.warn('rate_limited', { conn: 'c1', count: 3 });
  });

  assert.equal(lines.length, 2);
  for (const line of lines) {
    const record = JSON.parse(line) as Record<string, unknown>;
    assert.equal(typeof record['time'], 'string');
    assert.equal(typeof record['level'], 'string');
    assert.equal(typeof record['event'], 'string');
  }

  const first = JSON.parse(lines[0] as string) as Record<string, unknown>;
  assert.equal(first['event'], 'listening');
  assert.equal(first['level'], 'info');
  assert.equal(first['port'], 3006);
});

test('keeps a multiline string on a single line', () => {
  const lines = capture(() => {
    log.warn('protocol_error', { code: 'bad\nvalue' });
  });

  assert.equal(lines.length, 1);
  const record = JSON.parse(lines[0] as string) as Record<string, unknown>;
  assert.equal(record['code'], 'bad\nvalue');
});

test('drops field names that are not on the allowlist, including the denied ones', () => {
  const lines = capture(() => {
    // Cast because the type system already forbids these. The point is what happens when a future
    // call site bypasses the types, which is exactly when a leak would otherwise happen.
    log.info('clip_forward', {
      bytes: 42,
      ct: 'ciphertext-that-must-never-be-logged',
      secret: 'root-secret',
      pub_key: 'public-key',
      content: 'the actual clipboard text',
      unknown_field: 'whatever',
    } as unknown as Parameters<typeof log.info>[1]);
  });

  assert.equal(lines.length, 1);
  const line = lines[0] as string;
  const record = JSON.parse(line) as Record<string, unknown>;

  assert.equal(record['bytes'], 42);
  for (const banned of ['ct', 'secret', 'pub_key', 'content', 'unknown_field']) {
    assert.equal(banned in record, false, `${banned} must not appear in a log record`);
  }
  // Belt and braces: the values themselves must not appear anywhere in the raw line.
  assert.equal(line.includes('ciphertext-that-must-never'), false);
  assert.equal(line.includes('the actual clipboard text'), false);
});

test('drops a non scalar value for an allowed field', () => {
  const lines = capture(() => {
    log.info('conn_open', {
      conn: 'c1',
      code: { nested: 'object' },
      count: ['array'],
    } as unknown as Parameters<typeof log.info>[1]);
  });

  const record = JSON.parse(lines[0] as string) as Record<string, unknown>;
  assert.equal(record['conn'], 'c1');
  assert.equal('code' in record, false);
  assert.equal('count' in record, false);
});

test('respects the level threshold from LOG_LEVEL', () => {
  const out = inChildProcess(
    `m.log.debug('conn_open', { conn: 'c1' });
     m.log.info('listening', { port: 1 });
     m.log.warn('shutdown');
     m.log.error('protocol_error', { code: 'boom' });`,
    { LOG_LEVEL: 'warn' },
  );

  const events = out
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => (JSON.parse(line) as Record<string, unknown>)['event']);

  assert.deepEqual(events, ['shutdown', 'protocol_error']);
});

test('an unrecognised LOG_LEVEL falls back to info rather than silence', () => {
  const out = inChildProcess(`m.log.info('listening', { port: 1 });`, { LOG_LEVEL: 'nonsense' });
  assert.equal(out.includes('"event":"listening"'), true);
});

test('roomLogId is a stable 8 character hex digest within a process', () => {
  const first = roomLogId('C8V4B1KQ7M3ZRXPT9WNJ0GHA2E');
  const again = roomLogId('C8V4B1KQ7M3ZRXPT9WNJ0GHA2E');

  assert.equal(first, again);
  assert.equal(first.length, 8);
  assert.match(first, /^[0-9a-f]{8}$/);
  assert.notEqual(first, roomLogId('A DIFFERENT ROOM'));
});

test('roomLogId differs across processes, so logs cannot be correlated across restarts', () => {
  const snippet = `process.stdout.write(m.roomLogId('SAME ROOM EVERY TIME'));`;
  const first = inChildProcess(snippet).trim();
  const second = inChildProcess(snippet).trim();

  assert.match(first, /^[0-9a-f]{8}$/);
  assert.match(second, /^[0-9a-f]{8}$/);
  assert.notEqual(first, second);
});
