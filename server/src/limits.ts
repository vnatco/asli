/**
 * Rate limiting and client address resolution.
 *
 * Two things here are easy to get wrong and expensive to get wrong:
 *
 * 1. A Map that only ever grows is itself a memory exhaustion vector, so every map has a sweep.
 * 2. X-Forwarded-For is attacker controlled. Trusting the first entry lets anyone forge a client
 *    address, which turns per IP rate limiting into a tool for denying service to other people.
 */

/** A token bucket with lazy refill. Time is passed in so the tests are deterministic. */
export class TokenBucket {
  private tokens: number;
  private lastRefillMs: number;
  private readonly capacity: number;
  private readonly refillPerSec: number;

  constructor(capacity: number, refillPerSec: number, nowMs: number) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.tokens = capacity;
    this.lastRefillMs = nowMs;
  }

  /** Attempts to spend `cost` tokens. Returns false when the bucket is empty. */
  take(cost: number, nowMs: number): boolean {
    this.refill(nowMs);
    if (this.tokens < cost) return false;
    this.tokens -= cost;
    return true;
  }

  /** Milliseconds until `cost` tokens will be available, for the retry_after_ms hint. */
  retryAfterMs(cost: number, nowMs: number): number {
    this.refill(nowMs);
    if (this.tokens >= cost) return 0;
    const missing = cost - this.tokens;
    return Math.ceil((missing / this.refillPerSec) * 1000);
  }

  private refill(nowMs: number): void {
    // A clock that jumps backwards must not mint tokens or freeze the bucket forever.
    if (nowMs < this.lastRefillMs) {
      this.lastRefillMs = nowMs;
      return;
    }
    const elapsedSec = (nowMs - this.lastRefillMs) / 1000;
    if (elapsedSec <= 0) return;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.refillPerSec);
    this.lastRefillMs = nowMs;
  }

  /** Whether this bucket is full, meaning it carries no state worth keeping. */
  isIdle(nowMs: number): boolean {
    this.refill(nowMs);
    return this.tokens >= this.capacity;
  }
}

/** A rolling byte quota over a fixed window, used for the per room daily cap. */
export class RollingQuota {
  private used = 0;
  private windowStartMs: number;
  private readonly limit: number;
  private readonly windowMs: number;

  constructor(limit: number, windowMs: number, nowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.windowStartMs = nowMs;
  }

  /** Charges bytes against the quota. Returns false when the window is exhausted. */
  charge(bytes: number, nowMs: number): boolean {
    this.rollIfNeeded(nowMs);
    if (this.used + bytes > this.limit) return false;
    this.used += bytes;
    return true;
  }

  /** Milliseconds until the window resets. */
  retryAfterMs(nowMs: number): number {
    this.rollIfNeeded(nowMs);
    return Math.max(0, this.windowStartMs + this.windowMs - nowMs);
  }

  private rollIfNeeded(nowMs: number): void {
    if (nowMs < this.windowStartMs || nowMs - this.windowStartMs >= this.windowMs) {
      this.windowStartMs = nowMs;
      this.used = 0;
    }
  }
}

type IpEntry = {
  connections: number;
  newConns: TokenBucket;
  lastSeenMs: number;
};

/** Per IP connection accounting. */
export class IpLimiter {
  private readonly entries = new Map<string, IpEntry>();
  private readonly maxConcurrent: number;
  private readonly newConnBurst: number;
  private readonly newConnRefillMs: number;

  constructor(maxConcurrent: number, newConnBurst: number, newConnRefillMs: number) {
    this.maxConcurrent = maxConcurrent;
    this.newConnBurst = newConnBurst;
    this.newConnRefillMs = newConnRefillMs;
  }

  /** Records a connection attempt. Returns a reason string when it must be refused. */
  admit(key: string, nowMs: number): 'ok' | 'too_many' | 'too_fast' {
    let entry = this.entries.get(key);
    if (entry === undefined) {
      entry = {
        connections: 0,
        newConns: new TokenBucket(this.newConnBurst, 1000 / this.newConnRefillMs, nowMs),
        lastSeenMs: nowMs,
      };
      this.entries.set(key, entry);
    }
    entry.lastSeenMs = nowMs;

    if (entry.connections >= this.maxConcurrent) return 'too_many';
    if (!entry.newConns.take(1, nowMs)) return 'too_fast';

    entry.connections += 1;
    return 'ok';
  }

  release(key: string, nowMs: number): void {
    const entry = this.entries.get(key);
    if (entry === undefined) return;
    entry.connections = Math.max(0, entry.connections - 1);
    entry.lastSeenMs = nowMs;
  }

  /** Drops entries that hold no connections and have refilled, so the map cannot grow forever. */
  sweep(nowMs: number, idleMs: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.connections === 0 && nowMs - entry.lastSeenMs > idleMs && entry.newConns.isIdle(nowMs)) {
        this.entries.delete(key);
      }
    }
  }

  get size(): number {
    return this.entries.size;
  }
}

function ipv4ToInt(address: string): number | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

function expandIpv6(address: string): bigint | null {
  const stripped = address.startsWith('[') && address.endsWith(']') ? address.slice(1, -1) : address;
  if (!stripped.includes(':')) return null;
  const halves = stripped.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] === '' ? [] : (halves[0] ?? '').split(':').filter((p) => p !== '');
  const tail = halves.length === 2 ? (halves[1] === '' ? [] : (halves[1] ?? '').split(':').filter((p) => p !== '')) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && head.length !== 8) return null;
  if (missing < 0) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  return value;
}

/** Normalizes an address for rate limiting: IPv6 is grouped by /64, since one client owns a whole /64. */
export function rateLimitKey(address: string): string {
  const normalized = address.startsWith('::ffff:') ? address.slice(7) : address;
  if (ipv4ToInt(normalized) !== null) return normalized;
  const value = expandIpv6(normalized);
  if (value === null) return normalized;
  return `${(value >> 64n).toString(16)}::/64`;
}

/** Whether an address falls inside a CIDR block. Supports IPv4 and IPv6. */
export function inCidr(address: string, cidr: string): boolean {
  const slash = cidr.lastIndexOf('/');
  if (slash === -1) return address === cidr;
  const network = cidr.slice(0, slash);
  const bits = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0) return false;

  const addr4 = ipv4ToInt(address.startsWith('::ffff:') ? address.slice(7) : address);
  const net4 = ipv4ToInt(network);
  if (addr4 !== null && net4 !== null) {
    if (bits > 32) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : ~((1 << (32 - bits)) - 1) >>> 0;
    return (addr4 & mask) >>> 0 === (net4 & mask) >>> 0;
  }

  const addr6 = expandIpv6(address);
  const net6 = expandIpv6(network);
  if (addr6 === null || net6 === null || bits > 128) return false;
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return addr6 >> shift === net6 >> shift;
}

/**
 * Resolves the client address.
 *
 * Behind a reverse proxy every connection appears to come from the proxy, so per IP limiting
 * silently becomes global limiting unless the forwarded header is used. The header is also
 * attacker controlled, so it is used only when the peer is a configured trusted proxy, and then
 * the chain is walked right to left taking the last entry added by a trusted hop. Never the first
 * entry: that one is whatever the client wrote.
 */
export function resolveClientAddress(
  socketAddress: string,
  forwardedFor: string | undefined,
  trustedCidrs: readonly string[],
): string {
  if (trustedCidrs.length === 0) return socketAddress;
  if (!trustedCidrs.some((cidr) => inCidr(socketAddress, cidr))) return socketAddress;
  if (forwardedFor === undefined || forwardedFor.length === 0) return socketAddress;

  const chain = forwardedFor
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  for (let i = chain.length - 1; i >= 0; i -= 1) {
    const candidate = chain[i];
    if (candidate === undefined) continue;
    if (!trustedCidrs.some((cidr) => inCidr(candidate, cidr))) return candidate;
  }

  // Every hop in the chain is a trusted proxy, so the socket address is the best answer.
  return socketAddress;
}
