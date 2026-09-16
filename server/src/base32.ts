/**
 * Crockford base32, needed to decode the room id from the auth message.
 *
 * Per docs/PROTOCOL.md section 4.4: uppercase alphabet without I, L, O or U, no padding, decoders
 * accept lowercase and map I and L to 1 and O to 0, and reject U and everything else.
 */

const VALUES = new Map<string, number>();
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

for (let i = 0; i < ALPHABET.length; i += 1) {
  const symbol = ALPHABET[i];
  if (symbol === undefined) continue;
  VALUES.set(symbol, i);
  VALUES.set(symbol.toLowerCase(), i);
}
// Crockford's documented confusions. U is deliberately absent: it is rejected, not folded.
for (const [from, to] of [
  ['I', 1],
  ['i', 1],
  ['L', 1],
  ['l', 1],
  ['O', 0],
  ['o', 0],
] as const) {
  VALUES.set(from, to);
}

/**
 * Decodes Crockford base32 and checks the decoded length.
 *
 * Returns null on any problem rather than throwing, because every caller is handling untrusted
 * input and wants a single failure path.
 */
export function decodeCrockford(input: string, expectedBytes: number): Buffer | null {
  if (typeof input !== 'string' || input.length === 0) return null;

  const out = Buffer.alloc(expectedBytes);
  let written = 0;
  let buffer = 0;
  let bits = 0;

  for (const character of input) {
    const value = VALUES.get(character);
    if (value === undefined) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (written >= expectedBytes) return null;
      out[written] = (buffer >> bits) & 0xff;
      written += 1;
    }
  }

  // Leftover bits must be the encoder's zero padding. Anything else means the string was truncated
  // or tampered with.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null;
  if (written !== expectedBytes) return null;

  return out;
}
