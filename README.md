# OID BER Encoder

Encodes and decodes ASN.1 object identifiers between dotted decimal strings and BER content bytes. Zero dependencies, ESM only.

```js
import { encode, decode } from 'oid-ber-encoder';

const bytes = encode('1.2.840.113549.1.1.11');
// Uint8Array [ 42, 134, 72, 134, 247, 13, 1, 1, 11 ]

const oid = decode(bytes);
// '1.2.840.113549.1.1.11'
```

`encode` returns only the value bytes — the content of the TLV, without the tag or length. `decode` takes those same value bytes back. If you need a full TLV, prepend the OID tag `0x06` and the DER length yourself.

This exists because pulling in a full ASN.1 library to read or write a handful of OIDs is disproportionate. The trade-off: this library handles only OIDs and only their content bytes. It does not emit or parse tags, lengths, or any other ASN.1 type.

The awkward edge: the first two arcs are packed into one byte as `40 * first + second`. The first arc must be 0, 1, or 2, and when it is 0 or 1 the second arc must be less than 40. When it is 2, the second arc is unbounded. `encode` validates this and throws; `decode` reverses the packing by range-checking the first subidentifier.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

