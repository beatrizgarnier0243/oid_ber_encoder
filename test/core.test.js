import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encode, decode, oidToBytes, bytesToOid } from '../src/core.js';

test('round-trip a common OID (RSA SHA-256)', () => {
  const oid = '1.2.840.113549.1.1.11';
  const encoded = encode(oid);
  // Known-good BER content for this OID.
  const expected = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
  assert.deepEqual(encoded, expected);
  assert.equal(decode(encoded), oid);
});

test('round-trip a common OID (sha256WithRSAEncryption has known bytes)', () => {
  // 2.5.4.3 — commonName
  const oid = '2.5.4.3';
  const encoded = encode(oid);
  assert.deepEqual(encoded, new Uint8Array([0x55, 0x04, 0x03]));
  assert.equal(decode(encoded), oid);
});

test('first arc zero, second arc large allowed up to 39', () => {
  const oid = '0.39';
  const encoded = encode(oid);
  assert.deepEqual(encoded, new Uint8Array([39]));
  assert.equal(decode(encoded), oid);
});

test('first arc zero, second arc 40 is rejected', () => {
  assert.throws(() => encode('0.40'), /Second arc must be less than 40/);
});

test('first arc one, second arc 39 allowed', () => {
  const oid = '1.39';
  const encoded = encode(oid);
  assert.deepEqual(encoded, new Uint8Array([79]));
  assert.equal(decode(encoded), oid);
});

test('first arc one, second arc 40 rejected', () => {
  assert.throws(() => encode('1.40'), /Second arc must be less than 40/);
});

test('first arc two, second arc unbounded', () => {
  const oid = '2.999';
  const encoded = encode(oid);
  // 2*40 + 999 = 1079 = 0x437
  // base128 digits (LSB first): 0x37 (55), 0x08 (8)
  // reversed: [0x08, 0x37] -> with continuation: [0x88, 0x37]
  assert.deepEqual(encoded, new Uint8Array([0x88, 0x37]));
  assert.equal(decode(encoded), oid);
});

test('first arc three rejected', () => {
  assert.throws(() => encode('3.1'), /First arc must be 0, 1, or 2/);
});

test('single arc rejected (need at least two)', () => {
  assert.throws(() => encode('1'), /at least two arcs/);
});

test('empty string rejected', () => {
  assert.throws(() => encode(''), /at least two arcs/);
});

test('non-numeric arc rejected', () => {
  assert.throws(() => encode('1.2.abc'), /Invalid arc/);
});

test('negative arc rejected', () => {
  assert.throws(() => encode('1.-1'), /Invalid arc/);
});

test('trailing dot rejected', () => {
  assert.throws(() => encode('1.2.'), /Invalid arc/);
});

test('leading dot rejected', () => {
  assert.throws(() => encode('.1.2'), /Invalid arc/);
});

test('zero subidentifier encodes as single 0x00 byte', () => {
  const oid = '0.0';
  const encoded = encode(oid);
  assert.deepEqual(encoded, new Uint8Array([0x00]));
  assert.equal(decode(encoded), oid);
});

test('large arc with multi-byte encoding round-trips', () => {
  // 1.2.840.113549 — the RSA data security arc
  const oid = '1.2.840.113549';
  const encoded = encode(oid);
  // 113549 = 0x1BB8D = 0b1_1011_1011_1000_1101
  // base128: [0x86, 0xF7, 0x0D]  (6=110, 119=1110111, 13=1101)
  assert.deepEqual(encoded, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]));
  assert.equal(decode(encoded), oid);
});

test('truncated subidentifier (high bit set, no continuation) rejected', () => {
  assert.throws(() => decode(new Uint8Array([0x80])), /Truncated/);
});

test('empty byte array rejected on decode', () => {
  assert.throws(() => decode(new Uint8Array([])), /empty/);
});

test('non-Uint8Array input rejected on decode', () => {
  assert.throws(() => decode([]), /Uint8Array/);
});

test('non-string input rejected on encode', () => {
  assert.throws(() => encode(123), /string/);
});

test('oidToBytes is the same function as encode', () => {
  assert.equal(oidToBytes, encode);
  const a = encode('1.2.3');
  const b = oidToBytes('1.2.3');
  assert.deepEqual(a, b);
});

test('bytesToOid is the same function as decode', () => {
  assert.equal(bytesToOid, decode);
  const enc = encode('1.2.3');
  assert.equal(bytesToOid(enc), decode(enc));
});

test('round-trip a long OID with many arcs', () => {
  const oid = '1.3.6.1.4.1.311.21.7.1.1';
  const encoded = encode(oid);
  assert.equal(decode(encoded), oid);
});

test('very large arc value round-trips', () => {
  // A hypothetical large arc to exercise multi-byte path beyond two bytes.
  const oid = `1.2.840.9999997`;
  const encoded = encode(oid);
  assert.equal(decode(encoded), oid);
});
