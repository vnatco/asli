import assert from 'node:assert/strict';
import test from 'node:test';

import {
  IpLimiter,
  RollingQuota,
  TokenBucket,
  inCidr,
  rateLimitKey,
  resolveClientAddress,
} from '../src/limits.ts';

test('a token bucket refills at the configured rate', () => {
  const bucket = new TokenBucket(10, 2, 0);
  for (let i = 0; i < 10; i += 1) assert.equal(bucket.take(1, 0), true);
  assert.equal(bucket.take(1, 0), false, 'burst is exhausted');

  assert.equal(bucket.take(1, 500), true, 'half a second yields one token');
  assert.equal(bucket.take(1, 500), false);

  assert.equal(bucket.take(2, 1500), true, 'a further second yields two');
});

test('a token bucket never exceeds its capacity', () => {
  const bucket = new TokenBucket(5, 100, 0);
  assert.equal(bucket.take(5, 0), true);
  // A long idle period must not accumulate more than the burst.
  assert.equal(bucket.take(5, 1_000_000), true);
  assert.equal(bucket.take(1, 1_000_000), false);
});

test('a backwards clock jump neither mints tokens nor freezes the bucket', () => {
  const bucket = new TokenBucket(4, 1, 10_000);
  assert.equal(bucket.take(4, 10_000), true);

  // The clock jumps back an hour. Nothing should be granted for free.
  assert.equal(bucket.take(1, 10_000 - 3_600_000), false);
  // And the bucket must still refill normally from the new reference point.
  assert.equal(bucket.take(1, 10_000 - 3_600_000 + 2000), true);
});

test('retryAfterMs reports when the next token arrives', () => {
  const bucket = new TokenBucket(1, 2, 0);
  assert.equal(bucket.take(1, 0), true);
  assert.equal(bucket.retryAfterMs(1, 0), 500);
});

test('a rolling quota resets after its window', () => {
  const quota = new RollingQuota(1000, 60_000, 0);
  assert.equal(quota.charge(600, 0), true);
  assert.equal(quota.charge(600, 1000), false, 'over the limit inside the window');
  assert.equal(quota.charge(600, 61_000), true, 'window rolled');
  assert.ok(quota.retryAfterMs(61_000) > 0);
});

test('per ip limiting counts concurrency and admission rate', () => {
  const limiter = new IpLimiter(2, 2, 1000);
  assert.equal(limiter.admit('a', 0), 'ok');
  assert.equal(limiter.admit('a', 0), 'ok');
  assert.equal(limiter.admit('a', 0), 'too_many', 'concurrency cap');

  limiter.release('a', 0);
  limiter.release('a', 0);
  // The admission bucket is now empty, so a burst of reconnects is refused even with no
  // connections held.
  assert.equal(limiter.admit('a', 0), 'too_fast');
});

test('the ip map is swept so it cannot grow without bound', () => {
  const limiter = new IpLimiter(2, 10, 10);
  limiter.admit('a', 0);
  limiter.release('a', 0);
  assert.equal(limiter.size, 1);
  limiter.sweep(60_000, 1000);
  assert.equal(limiter.size, 0);
});

test('ipv6 addresses are grouped by /64 and ipv4 is left alone', () => {
  assert.equal(rateLimitKey('203.0.113.5'), '203.0.113.5');
  assert.equal(rateLimitKey('::ffff:203.0.113.5'), '203.0.113.5');

  const a = rateLimitKey('2001:db8:1:2:aaaa::1');
  const b = rateLimitKey('2001:db8:1:2:bbbb::9');
  assert.equal(a, b, 'the same /64 must share a key');

  const other = rateLimitKey('2001:db8:1:3::1');
  assert.notEqual(a, other, 'a different /64 must not');
});

test('cidr matching works for both address families', () => {
  assert.equal(inCidr('10.0.0.5', '10.0.0.0/8'), true);
  assert.equal(inCidr('11.0.0.5', '10.0.0.0/8'), false);
  assert.equal(inCidr('192.168.1.7', '192.168.1.0/24'), true);
  assert.equal(inCidr('2001:db8::1', '2001:db8::/32'), true);
  assert.equal(inCidr('2001:db9::1', '2001:db8::/32'), false);
});

test('x-forwarded-for is ignored unless the peer is a trusted proxy', () => {
  // No trusted proxies configured: the header is untrusted input and must be ignored entirely.
  assert.equal(resolveClientAddress('203.0.113.9', '198.51.100.1', []), '203.0.113.9');
  // Peer is not in the trusted set.
  assert.equal(
    resolveClientAddress('203.0.113.9', '198.51.100.1', ['10.0.0.0/8']),
    '203.0.113.9',
  );
});

test('a trusted proxy chain is walked right to left, never taking the first entry', () => {
  const trusted = ['10.0.0.0/8'];
  // The client forged the leftmost entry. The rightmost untrusted hop is the real peer.
  const resolved = resolveClientAddress('10.0.0.1', '1.1.1.1, 198.51.100.7, 10.0.0.2', trusted);
  assert.equal(resolved, '198.51.100.7');
});

test('a chain of only trusted hops falls back to the socket address', () => {
  const resolved = resolveClientAddress('10.0.0.1', '10.0.0.2, 10.0.0.3', ['10.0.0.0/8']);
  assert.equal(resolved, '10.0.0.1');
});

test('a rolling quota is idle once nothing has been charged in its window', () => {
  const quota = new RollingQuota(1000, 60_000, 0);
  assert.equal(quota.isIdle(0), true, 'fresh');
  assert.equal(quota.charge(10, 1), true);
  assert.equal(quota.isIdle(30_000), false, 'charged in this window');
  assert.equal(quota.isIdle(60_001), true, 'the window has passed');
});
