/**
 * Logging is an allowlist, not a redaction pass.
 *
 * Every record is assembled here from named, known safe fields. Raw message objects, request
 * objects and errors with attached context never reach the logger, because redaction that runs
 * after the fact only protects against the cases someone remembered.
 *
 * This writes JSON lines to stdout and nothing else. The relay runs as a systemd unit on a memory
 * constrained box, so journald is already collecting stdout and a logging library would only add a
 * dependency tree to a machine that forbids one. The deny list and the scalar check below are the
 * second gate behind the allowlist, for the day someone widens the field list carelessly.
 *
 * The room identifier is salted with a per process random value, so log lines cannot be correlated
 * across restarts and a leaked log does not reveal which rooms exist. Note that room_id is not a
 * credential in this design (see docs/PROTOCOL.md section 4.3), so this is a privacy measure.
 */

import { createHash, randomBytes } from 'node:crypto';

const salt = randomBytes(32);

/** Coarse outcome codes. Deliberately small and stable, so they are safe to aggregate on. */
export type EventName =
  | 'listening'
  | 'shutdown'
  | 'conn_open'
  | 'conn_close'
  | 'conn_rejected'
  | 'auth_ok'
  | 'auth_fail'
  | 'clip_forward'
  | 'chunk_complete'
  | 'announce_forward'
  | 'chunk_assembly_timeout'
  | 'clip_dropped'
  | 'clip_retained'
  | 'retain_evicted'
  | 'fetch_last'
  | 'rate_limited'
  | 'quota_exceeded'
  | 'backpressure'
  | 'protocol_error';

export type EventFields = {
  /** Salted, truncated room identifier. Never the raw room id. */
  room?: string;
  /** Server assigned connection id. Opaque and per connection. */
  conn?: string;
  /** Size of the payload in bytes. Never the payload. */
  bytes?: number;
  /** Public message id, which is already visible to the relay and carries no content. */
  msg?: string;
  /** Number of connections in a room, or globally. */
  count?: number;
  /** Coarse machine readable reason, from a closed set. */
  code?: string;
  /** WebSocket close code. */
  close?: number;
  /** Listening port, at startup only. */
  port?: number;
};

type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** The only field names that may ever be written. Everything else is dropped. */
const ALLOWED: readonly (keyof EventFields)[] = [
  'room',
  'conn',
  'bytes',
  'msg',
  'count',
  'code',
  'close',
  'port',
];

/**
 * Names that must never appear in a log line, checked even though the allowlist above already
 * excludes them. Cheap insurance against a future edit that adds a field without thinking.
 */
const DENIED = new Set([
  'ct',
  'n',
  'sig',
  'pub_key',
  'nonce_s',
  'nonce_c',
  'secret',
  'token',
  'content',
]);

function thresholdFrom(name: string | undefined): number {
  const key = (name ?? 'info').toLowerCase();
  // An unrecognised level falls back to info rather than silencing the relay.
  return key in LEVELS ? LEVELS[key as Level] : LEVELS.info;
}

const threshold = thresholdFrom(process.env['LOG_LEVEL']);

/** Derives the salted, truncated identifier used for a room in logs. */
export function roomLogId(roomId: string): string {
  return createHash('sha256').update(salt).update(roomId).digest('hex').slice(0, 8);
}

function isScalar(value: unknown): value is string | number {
  return typeof value === 'string' || typeof value === 'number';
}

function emit(level: Level, event: EventName, fields: EventFields): void {
  if (LEVELS[level] < threshold) return;

  // Built field by field on purpose: nothing reaches the output that was not named here.
  const record: Record<string, string | number> = {
    time: new Date().toISOString(),
    level,
    event,
  };

  const supplied = fields as Record<string, unknown>;
  for (const name of ALLOWED) {
    if (DENIED.has(name)) continue;
    const value = supplied[name];
    if (value === undefined) continue;
    // Objects and arrays are dropped rather than serialized, so a nested structure can never
    // smuggle content into a log line.
    if (!isScalar(value)) continue;
    record[name] = value;
  }

  // JSON.stringify escapes any newline inside a string, so one record is always one line.
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

export const log = {
  debug: (event: EventName, fields: EventFields = {}): void => emit('debug', event, fields),
  info: (event: EventName, fields: EventFields = {}): void => emit('info', event, fields),
  warn: (event: EventName, fields: EventFields = {}): void => emit('warn', event, fields),
  error: (event: EventName, fields: EventFields = {}): void => emit('error', event, fields),
};
