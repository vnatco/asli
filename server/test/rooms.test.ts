import assert from 'node:assert/strict';
import test from 'node:test';

import { RoomRegistry } from '../src/rooms.ts';
import type { Connection } from '../src/rooms.ts';

const ROOM = 'E5V0APG0E0QQ5MEGA99JBPFDHM';
const OTHER_ROOM = 'C8V4B1KQ7M3ZRXPT9WNJ0GHA2E';

function options(overrides: Partial<ConstructorParameters<typeof RoomRegistry>[0]> = {}) {
  return {
    retainMaxBytes: 1024,
    retainGlobalBudgetBytes: 4096,
    retainTtlMs: 60_000,
    maxRooms: 10,
    maxConnsPerRoom: 3,
    dedupWindow: 4,
    presenceDebounceMs: 0,
    ...overrides,
  };
}

function connection(id: string, roomId: string, sink: string[] = []): Connection {
  return {
    id,
    roomId,
    send: (data: string) => sink.push(data),
    close: () => undefined,
  };
}

test('joining and leaving tracks the peer count', () => {
  const registry = new RoomRegistry(options());
  const a = connection('a', ROOM);
  const b = connection('b', ROOM);

  assert.deepEqual(registry.join(a, 0), { ok: true, peers: 1 });
  assert.deepEqual(registry.join(b, 0), { ok: true, peers: 2 });
  assert.equal(registry.peers(ROOM), 2);

  registry.leave(b, 0);
  assert.equal(registry.peers(ROOM), 1);
});

test('a room refuses more connections than its cap', () => {
  const registry = new RoomRegistry(options({ maxConnsPerRoom: 2 }));
  registry.join(connection('a', ROOM), 0);
  registry.join(connection('b', ROOM), 0);
  assert.deepEqual(registry.join(connection('c', ROOM), 0), { ok: false, reason: 'room_full' });
});

test('room creation is refused past the global cap', () => {
  const registry = new RoomRegistry(options({ maxRooms: 1 }));
  registry.join(connection('a', ROOM), 0);
  assert.deepEqual(registry.join(connection('b', OTHER_ROOM), 0), {
    ok: false,
    reason: 'too_many_rooms',
  });
});

test('broadcast reaches every peer except the sender', () => {
  const registry = new RoomRegistry(options());
  const aSink: string[] = [];
  const bSink: string[] = [];
  const cSink: string[] = [];
  const a = connection('a', ROOM, aSink);
  const b = connection('b', ROOM, bSink);
  const c = connection('c', ROOM, cSink);
  registry.join(a, 0);
  registry.join(b, 0);
  registry.join(c, 0);

  const delivered = registry.broadcast(ROOM, a, 'frame', 0);
  assert.equal(delivered, 2);
  assert.deepEqual(aSink, [], 'the sender must not receive its own message');
  assert.deepEqual(bSink, ['frame']);
  assert.deepEqual(cSink, ['frame']);
});

test('duplicate message ids are detected within a bounded window', () => {
  const registry = new RoomRegistry(options({ dedupWindow: 3 }));
  registry.join(connection('a', ROOM), 0);

  assert.equal(registry.isDuplicate(ROOM, 'm1'), false);
  assert.equal(registry.isDuplicate(ROOM, 'm1'), true);

  // Push m1 out of the window.
  registry.isDuplicate(ROOM, 'm2');
  registry.isDuplicate(ROOM, 'm3');
  registry.isDuplicate(ROOM, 'm4');
  assert.equal(registry.isDuplicate(ROOM, 'm1'), false, 'the window is bounded, not infinite');
});

test('a message above the retain cap is forwarded but not stored', () => {
  const registry = new RoomRegistry(options({ retainMaxBytes: 64 }));
  registry.join(connection('a', ROOM), 0);

  assert.equal(registry.retain(ROOM, Buffer.alloc(65), 'm1', 0), false);
  assert.equal(registry.retainedFor(ROOM, 0), null);

  assert.equal(registry.retain(ROOM, Buffer.alloc(64), 'm2', 0), true);
  assert.notEqual(registry.retainedFor(ROOM, 0), null);
});

test('only the newest clip is retained, and the byte count follows it', () => {
  const registry = new RoomRegistry(options());
  registry.join(connection('a', ROOM), 0);

  registry.retain(ROOM, Buffer.alloc(100), 'm1', 0);
  registry.retain(ROOM, Buffer.alloc(200), 'm2', 1);
  assert.equal(registry.retainedByteCount, 200, 'the previous clip must be released');
  assert.equal(registry.retainedFor(ROOM, 1)?.msgId, 'm2');
});

test('an expired clip is never served, even before the sweep runs', () => {
  const registry = new RoomRegistry(options({ retainTtlMs: 1000 }));
  registry.join(connection('a', ROOM), 0);
  registry.retain(ROOM, Buffer.alloc(10), 'm1', 0);

  assert.notEqual(registry.retainedFor(ROOM, 1000), null, 'still inside the ttl');
  assert.equal(registry.retainedFor(ROOM, 1001), null, 'lazily expired on read');
  assert.equal(registry.retainedByteCount, 0);
});

test('the sweep drops expired clips and forgets empty rooms', () => {
  const registry = new RoomRegistry(options({ retainTtlMs: 1000 }));
  const a = connection('a', ROOM);
  registry.join(a, 0);
  registry.retain(ROOM, Buffer.alloc(10), 'm1', 0);
  registry.leave(a, 0);

  assert.equal(registry.roomCount, 1, 'kept while a clip is retained');
  assert.equal(registry.sweep(2000), 1);
  assert.equal(registry.roomCount, 0);
  assert.equal(registry.retainedByteCount, 0);
});

test('the global budget evicts the least recently active rooms', () => {
  const registry = new RoomRegistry(options({ retainMaxBytes: 1000, retainGlobalBudgetBytes: 1000 }));
  const rooms = [ROOM, OTHER_ROOM, 'ABCDEFGHJKMNPQRSTVWXYZ0123'];
  rooms.forEach((room, index) => {
    registry.join(connection(`c${index}`, room), index);
    registry.retain(room, Buffer.alloc(400), `m${index}`, index);
  });

  // Three rooms at 400 bytes exceed the 1000 byte ceiling, so the oldest must have gone.
  assert.ok(registry.retainedByteCount <= 1000, `budget respected, got ${registry.retainedByteCount}`);
  assert.equal(registry.retainedFor(rooms[0] as string, 10), null, 'oldest evicted first');
  assert.notEqual(registry.retainedFor(rooms[2] as string, 10), null, 'newest kept');
});
