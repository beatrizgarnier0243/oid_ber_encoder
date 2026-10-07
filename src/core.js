/**
 * OID BER encoding and decoding.
 *
 * ASN.1 object identifiers are written in dotted decimal form, e.g.
 * "1.2.840.113549.1.1.11". The Basic Encoding Rules (BER) — and DER, which
 * agrees on this point — represent an OID value as a TLV whose value bytes
 * encode each subidentifier in base 128, most significant digit first, with
 * the high bit of every byte except the last set to 1.
 *
 * The first two arcs are packed into a single subidentifier as 40*X + Y
 * because the first arc is always 0, 1, or 2 and the second is small. This
 * packing is the one non-obvious wrinkle in the whole encoding; everything
 * else is straightforward variable-length base-128.
 */

/**
 * Encode a dotted-decimal OID string into its BER value bytes (the V of TLV).
 *
 * Returns a Uint8Array of the content bytes only — no tag or length prefix.
 * Callers needing a full TLV must prepend 0x06 and the length themselves.
 */
export const oidToBytes = function oidToBytes(oid) {
  if (typeof oid !== 'string') {
    throw new TypeError('OID must be a dotted-decimal string');
  }
  if (oid.length === 0) {
    throw new Error('OID must have at least two arcs');
  }

  const parts = oid.split('.');
  if (parts.length < 2) {
    throw new Error('OID must have at least two arcs');
  }

  const arcs = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (!/^\d+$/.test(p)) {
      throw new Error(`Invalid arc "${p}": arcs must be non-negative integers`);
    }
    arcs.push(BigInt(p));
  }

  const first = arcs[0];
  const second = arcs[1];
  if (first > 2n) {
    throw new Error('First arc must be 0, 1, or 2');
  }
  if (first < 2n && second >= 40n) {
    throw new Error(`Second arc must be less than 40 when first arc is ${first}`);
  }

  const subids = [];
  subids.push(first * 40n + second);
  for (let i = 2; i < arcs.length; i++) {
    subids.push(arcs[i]);
  }

  const out = [];
  for (const s of subids) {
    if (s === 0n) {
      out.push(0x00);
      continue;
    }
    const chunks = []
    let v = s;
    while (v > 0n) {
      chunks.push(Number(v & 0x7fn));
      v >>= 7n;
    }
    chunks.reverse();
    for (let i = 0; i < chunks.length; i++) {
      out.push(i < chunks.length - 1 ? (chunks[i] | 0x80) : chunks[i]);
    }
  }

  return new Uint8Array(out);
};

/**
 * Alias kept for clarity at call sites that think in terms of bytes.
 * Same function as oidToBytes; both names are exported from index.js.
 */
export const encode = oidToBytes;

/**
 * Decode BER value bytes back into a dotted-decimal OID string.
 *
 * Accepts a Uint8Array containing only the content bytes — no tag, no length.
 * This mirrors encode(), which produces only content bytes, so the two are
 * exact inverses for well-formed input.
 */
export const bytesToOid = function bytesToOid(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Input must be a Uint8Array');
  }
  if (bytes.length === 0) {
    throw new Error('OID content cannot be empty');
  }

  const subids = [];
  let i = 0;
  while (i < bytes.length) {
    let value = 0n;
    let count = 0;
    let contByte;
    do {
      if (i >= bytes.length) {
        throw new Error('Truncated subidentifier: high bit set but no continuation byte');
      }
      contByte = bytes[i];
      i++;
      value = (value << 7n) | BigInt(contByte & 0x7f);
      count++;
      if (count > 10) {
        throw new Error('Subidentifier too long');
      }
    } while (contByte & 0x80);
    subids.push(value);
  }

  const firstSub = subids[0];
  let first, second;
  if (firstSub < 40n) {
    first = 0n;
    second = firstSub;
  } else if (firstSub < 80n) {
    first = 1n;
    second = firstSub - 40n;
  } else {
    first = 2n;
    second = firstSub - 80n;
  }

  const arcs = [first, second];
  for (let j = 1; j < subids.length; j++) {
    arcs.push(subids[j]);
  }

  return arcs.map(a => a.toString()).join('.');
};

/**
 * Alias for bytesToOid, exported for symmetry with encode/oidToBytes.
 */
export const decode = bytesToOid;
