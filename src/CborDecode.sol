// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {LibBytes} from "./LibBytes.sol";

type CborElement is uint256;

library LibCborElement {
    // Cbor element type
    function cborType(CborElement self) internal pure returns (uint8) {
        return uint8(CborElement.unwrap(self));
    }

    // First byte index of the content
    function start(CborElement self) internal pure returns (uint256) {
        return uint80(CborElement.unwrap(self) >> 80);
    }

    // First byte index of the next element (exclusive end of content)
    function end(CborElement self) internal pure returns (uint256) {
        return start(self) + length(self);
    }

    // Content length (0 for non-string types)
    function length(CborElement self) internal pure returns (uint256) {
        uint8 _type = cborType(self);
        if (_type == 0x40 || _type == 0x60) {
            // length is non-zero only for byte strings and text strings
            return value(self);
        }
        return 0;
    }

    // Value of the element (length for string/map/array types, value for others)
    function value(CborElement self) internal pure returns (uint64) {
        return uint64(CborElement.unwrap(self) >> 160);
    }

    // Returns true if the element is null
    function isNull(CborElement self) internal pure returns (bool) {
        uint8 _type = cborType(self);
        return _type == 0xf6 || _type == 0xf7; // null or undefined
    }

    // Pack 3 uint80s into a uint256
    function toCborElement(uint256 _type, uint256 _start, uint256 _length) internal pure returns (CborElement) {
        return CborElement.wrap(_type | _start << 80 | _length << 160);
    }
}

library CborDecode {
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    // Calculate the keccak256 hash of the given cbor element
    function keccak(bytes memory cbor, CborElement ptr) internal pure returns (bytes32) {
        return cbor.keccak(ptr.start(), ptr.length());
    }

    // Take a slice of the given cbor element
    function slice(bytes memory cbor, CborElement ptr) internal pure returns (bytes memory) {
        return cbor.slice(ptr.start(), ptr.length());
    }

    function byteStringAt(bytes memory cbor, uint256 ix) internal pure returns (CborElement) {
        return elementAt(cbor, ix, 0x40, true);
    }

    function nextByteString(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), 0x40, true);
    }

    function nextByteStringOrNull(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), 0x40, false);
    }

    function nextTextString(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), 0x60, true);
    }

    function nextPositiveInt(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), 0x00, true);
    }

    function mapAt(bytes memory cbor, uint256 ix) internal pure returns (CborElement) {
        return elementAt(cbor, ix, 0xa0, true);
    }

    function nextMap(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return mapAt(cbor, ptr.end());
    }

    function nextArray(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), 0x80, true);
    }

    // Returns the index immediately after the complete CBOR data item that starts at `ix`,
    // descending into nested arrays/maps and following indefinite-length containers to their
    // 0xFF break marker. Unlike `elementAt`, this accepts every major type (ints, strings,
    // arrays, maps, tags, simple/float values), so it can skip over values whose shape is not
    // known ahead of time — e.g. the value of an unrecognised attestation key. Out-of-bounds
    // reads (including a truncated indefinite-length container with no break marker) revert.
    function skipValue(bytes memory cbor, uint256 ix) internal pure returns (uint256) {
        uint8 b = uint8(cbor[ix]);
        uint8 major = b >> 5;
        uint8 ai = b & 0x1f;

        uint256 header;
        uint64 arg;
        bool indefinite;
        if (ai < 24) {
            header = 1;
            arg = ai;
        } else if (ai == 24) {
            header = 2;
            arg = uint8(cbor[ix + 1]);
        } else if (ai == 25) {
            header = 3;
            arg = cbor.readUint16(ix + 1);
        } else if (ai == 26) {
            header = 5;
            arg = cbor.readUint32(ix + 1);
        } else if (ai == 27) {
            header = 9;
            arg = cbor.readUint64(ix + 1);
        } else if (ai == 31) {
            header = 1;
            indefinite = true;
        } else {
            // additional information 28..30 are reserved per RFC 8949
            revert("invalid cbor additional info");
        }

        uint256 p = ix + header;

        if (major == 0 || major == 1) {
            // unsigned / negative integer: the value lives entirely in the header
            require(!indefinite, "invalid integer encoding");
            return p;
        } else if (major == 2 || major == 3) {
            // byte string / text string
            if (indefinite) {
                while (uint8(cbor[p]) != 0xff) {
                    p = skipValue(cbor, p);
                }
                return p + 1;
            }
            require(p + arg <= cbor.length, "cbor string out of bounds");
            return p + arg;
        } else if (major == 4) {
            // array
            if (indefinite) {
                while (uint8(cbor[p]) != 0xff) {
                    p = skipValue(cbor, p);
                }
                return p + 1;
            }
            for (uint64 i = 0; i < arg; i++) {
                p = skipValue(cbor, p);
            }
            return p;
        } else if (major == 5) {
            // map: each entry is a key item followed by a value item
            if (indefinite) {
                while (uint8(cbor[p]) != 0xff) {
                    p = skipValue(cbor, p);
                }
                return p + 1;
            }
            for (uint64 i = 0; i < arg; i++) {
                p = skipValue(cbor, p);
                p = skipValue(cbor, p);
            }
            return p;
        } else if (major == 6) {
            // tag: a single tagged data item follows the header
            require(!indefinite, "invalid tag encoding");
            return skipValue(cbor, p);
        } else {
            // major == 7: simple value / float; ai==31 (break) is not a standalone value
            require(!indefinite, "unexpected break");
            return p;
        }
    }

    function elementAt(bytes memory cbor, uint256 ix, uint8 expectedType, bool required)
        internal
        pure
        returns (CborElement)
    {
        uint8 _type = uint8(cbor[ix] & 0xe0);
        uint8 ai = uint8(cbor[ix] & 0x1f);
        if (_type == 0xe0) {
            // The primitive type can encode a float, bool, null, undefined, etc.
            // We only need support for null (and we treat undefined as null).
            require(ai == 22 || ai == 23, "only null primitive values are supported");
            require(!required, "null value for required element");
            // retain the additional information:
            return LibCborElement.toCborElement(_type | ai, ix + 1, 0);
        }
        require(_type == expectedType, "unexpected type");
        if (ai == 31) {
            // Indefinite-length encoding is only defined for maps (0xBF) and
            // arrays (0x9F) per RFC 8949.  Other major types with ai=31 (e.g.
            // 0x5F, 0x7F, 0x1F) are reserved or chunked encodings that this
            // decoder does not support.  Downstream validation in
            // validateAttestation() would also catch these cases, but rejecting
            // here gives an immediate, unambiguous revert.
            require(_type == 0xa0 || _type == 0x80, "indefinite-length only for maps/arrays");
            return LibCborElement.toCborElement(_type, ix + 1, 0);
        }
        require(ai < 28, "unsupported type");
        if (ai == 24) {
            return LibCborElement.toCborElement(_type, ix + 2, uint8(cbor[ix + 1]));
        } else if (ai == 25) {
            return LibCborElement.toCborElement(_type, ix + 3, cbor.readUint16(ix + 1));
        } else if (ai == 26) {
            return LibCborElement.toCborElement(_type, ix + 5, cbor.readUint32(ix + 1));
        } else if (ai == 27) {
            return LibCborElement.toCborElement(_type, ix + 9, cbor.readUint64(ix + 1));
        }
        return LibCborElement.toCborElement(_type, ix + 1, ai);
    }
}
