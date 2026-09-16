/**
 * Every operational limit lives here, is overridable by environment variable, and is validated at
 * startup. A relay that boots with a nonsense limit and discovers it under load is worse than one
 * that refuses to boot, so this module throws rather than clamping.
 *
 * The defaults are the public relay's values, documented in docs/PROTOCOL.md section 11.
 */

export type Config = {
  readonly port: number;
  readonly host: string;
  readonly metricsPort: number;
  readonly logLevel: string;

  readonly maxFrameBytes: number;
  readonly maxContentBytes: number;
  readonly retainMaxBytes: number;
  readonly retainGlobalBudgetBytes: number;
  readonly retainTtlMs: number;
  readonly maxRooms: number;

  readonly authTimeoutMs: number;
  readonly heartbeatIntervalMs: number;

  readonly msgBurst: number;
  readonly msgsPerSec: number;
  readonly byteBurst: number;
  readonly bytesPerSec: number;
  readonly roomBytesPerDay: number;

  readonly maxConnsPerIp: number;
  readonly newConnBurst: number;
  readonly newConnRefillMs: number;
  readonly maxConnsPerRoom: number;
  readonly maxConnsGlobal: number;

  readonly backpressureSoftBytes: number;
  readonly backpressureHardBytes: number;
  readonly backpressureGraceMs: number;

  readonly dedupWindow: number;
  readonly presenceDebounceMs: number;

  readonly trustedProxyCidrs: readonly string[];
};

const KIB = 1024;
const MIB = 1024 * 1024;

function readInt(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value)) {
    throw new Error(`${name} must be an integer, got ${JSON.stringify(raw)}`);
  }
  if (value < min || value > max) {
    throw new Error(`${name} must be between ${min} and ${max}, got ${value}`);
  }
  return value;
}

function readString(name: string, fallback: string): string {
  const raw = process.env[name];
  return raw === undefined || raw === '' ? fallback : raw;
}

function readList(name: string): readonly string[] {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export function loadConfig(): Config {
  const config: Config = {
    port: readInt('PORT', 8080, 1, 65535),
    host: readString('HOST', '0.0.0.0'),
    // Bound to loopback by the server, because room and connection counts are free intelligence
    // about the user base and do not belong on a public port.
    metricsPort: readInt('METRICS_PORT', 9090, 0, 65535),
    logLevel: readString('LOG_LEVEL', 'info'),

    maxFrameBytes: readInt('MAX_FRAME_BYTES', MIB, 4 * KIB, 64 * MIB),
    maxContentBytes: readInt('MAX_CONTENT_BYTES', 700 * KIB, KIB, 32 * MIB),
    retainMaxBytes: readInt('RETAIN_MAX_BYTES', 64 * KIB, 0, 16 * MIB),
    retainGlobalBudgetBytes: readInt('RETAIN_GLOBAL_BUDGET_BYTES', 256 * MIB, 0, 8192 * MIB),
    retainTtlMs: readInt('RETAIN_TTL_MS', 24 * 60 * 60 * 1000, 1000, 30 * 24 * 60 * 60 * 1000),
    maxRooms: readInt('MAX_ROOMS', 100_000, 1, 10_000_000),

    authTimeoutMs: readInt('AUTH_TIMEOUT_MS', 10_000, 500, 120_000),
    heartbeatIntervalMs: readInt('HEARTBEAT_INTERVAL_MS', 30_000, 1000, 300_000),

    msgBurst: readInt('MSG_BURST', 10, 1, 10_000),
    msgsPerSec: readInt('MSGS_PER_SEC', 2, 1, 10_000),
    byteBurst: readInt('BYTE_BURST', 2 * MIB, KIB, 512 * MIB),
    bytesPerSec: readInt('BYTES_PER_SEC', 256 * KIB, KIB, 512 * MIB),
    roomBytesPerDay: readInt('ROOM_BYTES_PER_DAY', 50 * MIB, 64 * KIB, 64 * 1024 * MIB),

    maxConnsPerIp: readInt('MAX_CONNS_PER_IP', 20, 1, 100_000),
    newConnBurst: readInt('NEW_CONN_BURST', 10, 1, 10_000),
    newConnRefillMs: readInt('NEW_CONN_REFILL_MS', 5000, 1, 3_600_000),
    maxConnsPerRoom: readInt('MAX_CONNS_PER_ROOM', 16, 2, 10_000),
    maxConnsGlobal: readInt('MAX_CONNS_GLOBAL', 10_000, 2, 1_000_000),

    backpressureSoftBytes: readInt('BACKPRESSURE_SOFT_BYTES', MIB, KIB, 64 * MIB),
    backpressureHardBytes: readInt('BACKPRESSURE_HARD_BYTES', 8 * MIB, KIB, 256 * MIB),
    backpressureGraceMs: readInt('BACKPRESSURE_GRACE_MS', 15_000, 100, 600_000),

    dedupWindow: readInt('DEDUP_WINDOW', 256, 16, 100_000),
    presenceDebounceMs: readInt('PRESENCE_DEBOUNCE_MS', 1500, 0, 60_000),

    trustedProxyCidrs: readList('TRUSTED_PROXY_CIDRS'),
  };

  // Cross field checks. Each of these would otherwise produce a confusing runtime failure rather
  // than an obvious startup failure.
  if (config.retainMaxBytes > config.maxFrameBytes) {
    throw new Error('RETAIN_MAX_BYTES must not exceed MAX_FRAME_BYTES');
  }
  if (config.backpressureHardBytes <= config.backpressureSoftBytes) {
    throw new Error('BACKPRESSURE_HARD_BYTES must be greater than BACKPRESSURE_SOFT_BYTES');
  }
  if (config.metricsPort !== 0 && config.metricsPort === config.port) {
    throw new Error('METRICS_PORT must differ from PORT');
  }
  // Base64 inflates by 4/3, so a content cap above three quarters of the frame cap cannot fit on
  // the wire once the envelope is added.
  if (config.maxContentBytes * (4 / 3) >= config.maxFrameBytes) {
    throw new Error('MAX_CONTENT_BYTES is too large for MAX_FRAME_BYTES once base64 expansion is applied');
  }

  return config;
}
