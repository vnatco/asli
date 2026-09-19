/**
 * Rooms, retention and presence.
 *
 * Everything here is in memory by design. Nothing is written to disk, which bounds what an
 * operator can be compelled to hand over to whatever is in RAM at that moment.
 *
 * The retention numbers matter more than they look. Retaining the last clip per room at the frame
 * cap, across ten thousand rooms, is fifty gigabytes. The three controls that make it bounded are
 * a small per message cap, a global byte budget with least recently used eviction, and a TTL that
 * is both swept and checked on read.
 */

import type { Buffer as NodeBuffer } from 'node:buffer';

export type Retained = {
  /** The raw frame bytes, stored once. Never a parsed object and never a string. */
  frame: NodeBuffer;
  storedAtMs: number;
  msgId: string;
};

export type Connection = {
  id: string;
  roomId: string;
  send: (data: string) => void;
  close: (code: number, reason?: string) => void;
};

type Room = {
  id: string;
  connections: Set<Connection>;
  retained: Retained | null;
  lastActiveMs: number;
  /** Recent message ids, for dedup. Bounded by the configured window. */
  seen: Set<string>;
  seenOrder: string[];
  presenceTimer: NodeJS.Timeout | null;
};

export type RegistryOptions = {
  retainMaxBytes: number;
  retainGlobalBudgetBytes: number;
  retainTtlMs: number;
  maxRooms: number;
  maxConnsPerRoom: number;
  dedupWindow: number;
  presenceDebounceMs: number;
};

export type JoinResult =
  | { ok: true; peers: number }
  | { ok: false; reason: 'too_many_rooms' | 'room_full' };

export class RoomRegistry {
  private readonly rooms = new Map<string, Room>();
  private retainedBytes = 0;
  private readonly options: RegistryOptions;

  constructor(options: RegistryOptions) {
    this.options = options;
  }

  get roomCount(): number {
    return this.rooms.size;
  }

  get retainedByteCount(): number {
    return this.retainedBytes;
  }

  get connectionCount(): number {
    let total = 0;
    for (const room of this.rooms.values()) total += room.connections.size;
    return total;
  }

  join(connection: Connection, nowMs: number): JoinResult {
    let room = this.rooms.get(connection.roomId);
    if (room === undefined) {
      // At the cap, the room idle the longest makes way, losing only its retained clip. Refusing
      // instead let anyone fill every slot for a day: an empty room that holds a retained clip is
      // kept until the clip expires, and minting a room costs nothing but a keypair.
      if (this.rooms.size >= this.options.maxRooms && !this.evictIdlestRoom()) {
        return { ok: false, reason: 'too_many_rooms' };
      }
      room = {
        id: connection.roomId,
        connections: new Set(),
        retained: null,
        lastActiveMs: nowMs,
        seen: new Set(),
        seenOrder: [],
        presenceTimer: null,
      };
      this.rooms.set(connection.roomId, room);
    }

    if (room.connections.size >= this.options.maxConnsPerRoom) {
      return { ok: false, reason: 'room_full' };
    }

    room.connections.add(connection);
    room.lastActiveMs = nowMs;
    return { ok: true, peers: room.connections.size };
  }

  leave(connection: Connection, nowMs: number): void {
    const room = this.rooms.get(connection.roomId);
    if (room === undefined) return;
    room.connections.delete(connection);
    room.lastActiveMs = nowMs;

    // A room with no connections and nothing retained holds no state worth keeping.
    if (room.connections.size === 0 && room.retained === null) {
      if (room.presenceTimer !== null) clearTimeout(room.presenceTimer);
      this.rooms.delete(room.id);
    }
  }

  peers(roomId: string): number {
    return this.rooms.get(roomId)?.connections.size ?? 0;
  }

  /**
   * Records a message id and reports whether it was already seen.
   *
   * Dedup protects peers from a duplicate delivery and stops a reconnecting client's own message
   * from being echoed back to the room.
   */
  isDuplicate(roomId: string, msgId: string): boolean {
    const room = this.rooms.get(roomId);
    if (room === undefined) return false;
    if (room.seen.has(msgId)) return true;

    room.seen.add(msgId);
    room.seenOrder.push(msgId);
    if (room.seenOrder.length > this.options.dedupWindow) {
      const oldest = room.seenOrder.shift();
      if (oldest !== undefined) room.seen.delete(oldest);
    }
    return false;
  }

  /** Forwards a frame to every connection in the room except the sender. Returns the fan out count. */
  broadcast(roomId: string, sender: Connection, frame: string, nowMs: number): number {
    const room = this.rooms.get(roomId);
    if (room === undefined) return 0;
    room.lastActiveMs = nowMs;

    let delivered = 0;
    for (const peer of room.connections) {
      if (peer === sender) continue;
      peer.send(frame);
      delivered += 1;
    }
    return delivered;
  }

  /**
   * Stores a frame as the room's retained clip, if it is small enough.
   *
   * Exactly one clip is retained per room. The clipboard is last write wins, so a history would be
   * storage spent on something no client would ever ask for.
   */
  retain(roomId: string, frame: NodeBuffer, msgId: string, nowMs: number): boolean {
    if (frame.length > this.options.retainMaxBytes) return false;
    const room = this.rooms.get(roomId);
    if (room === undefined) return false;

    if (room.retained !== null) this.retainedBytes -= room.retained.frame.length;
    room.retained = { frame, storedAtMs: nowMs, msgId };
    this.retainedBytes += frame.length;
    room.lastActiveMs = nowMs;

    this.evictUntilWithinBudget(roomId);
    return true;
  }

  /**
   * Returns the retained clip, or null.
   *
   * The TTL is checked here as well as in the sweep, so an expired entry is never served even when
   * the sweep is behind.
   */
  retainedFor(roomId: string, nowMs: number): Retained | null {
    const room = this.rooms.get(roomId);
    if (room === undefined || room.retained === null) return null;
    if (nowMs - room.retained.storedAtMs > this.options.retainTtlMs) {
      this.dropRetained(room);
      return null;
    }
    return room.retained;
  }

  /** Removes the empty room that has been idle longest. Returns false when every room is in use. */
  private evictIdlestRoom(): boolean {
    let idlest: Room | null = null;
    for (const room of this.rooms.values()) {
      if (room.connections.size > 0) continue;
      if (idlest === null || room.lastActiveMs < idlest.lastActiveMs) idlest = room;
    }
    if (idlest === null) return false;
    if (idlest.retained !== null) this.dropRetained(idlest);
    if (idlest.presenceTimer !== null) clearTimeout(idlest.presenceTimer);
    this.rooms.delete(idlest.id);
    return true;
  }

  /** Expires retained clips and forgets empty rooms. Returns the number of entries dropped. */
  sweep(nowMs: number): number {
    let dropped = 0;
    for (const room of [...this.rooms.values()]) {
      if (room.retained !== null && nowMs - room.retained.storedAtMs > this.options.retainTtlMs) {
        this.dropRetained(room);
        dropped += 1;
      }
      if (room.connections.size === 0 && room.retained === null) {
        if (room.presenceTimer !== null) clearTimeout(room.presenceTimer);
        this.rooms.delete(room.id);
      }
    }
    return dropped;
  }

  /** Schedules a debounced presence broadcast, so a reconnect storm does not flicker every tray. */
  schedulePresence(roomId: string, emit: (peers: number) => void): void {
    const room = this.rooms.get(roomId);
    if (room === undefined) return;
    if (room.presenceTimer !== null) clearTimeout(room.presenceTimer);

    const fire = (): void => {
      const current = this.rooms.get(roomId);
      if (current === undefined) return;
      current.presenceTimer = null;
      emit(current.connections.size);
    };

    if (this.options.presenceDebounceMs === 0) {
      fire();
      return;
    }
    room.presenceTimer = setTimeout(fire, this.options.presenceDebounceMs);
    room.presenceTimer.unref?.();
  }

  /** Releases every timer. Used on shutdown so the process can exit promptly. */
  clearTimers(): void {
    for (const room of this.rooms.values()) {
      if (room.presenceTimer !== null) {
        clearTimeout(room.presenceTimer);
        room.presenceTimer = null;
      }
    }
  }

  private dropRetained(room: Room): void {
    if (room.retained === null) return;
    this.retainedBytes -= room.retained.frame.length;
    room.retained = null;
  }

  /**
   * Enforces the global retention budget by evicting the least recently active rooms.
   *
   * This is the control that makes the memory ceiling a fact rather than an estimate: it holds no
   * matter how many rooms exist.
   */
  private evictUntilWithinBudget(exceptRoomId: string): void {
    if (this.retainedBytes <= this.options.retainGlobalBudgetBytes) return;

    const candidates = [...this.rooms.values()]
      .filter((room) => room.retained !== null && room.id !== exceptRoomId)
      .sort((a, b) => a.lastActiveMs - b.lastActiveMs);

    for (const room of candidates) {
      if (this.retainedBytes <= this.options.retainGlobalBudgetBytes) return;
      this.dropRetained(room);
    }
  }
}
