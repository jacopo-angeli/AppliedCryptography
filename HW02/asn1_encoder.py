#!/usr/bin/env python3
import sys

# took 2.5 hours

def ib(n, length = 0):
    if length == 0:
        b = b""
        while n > 0:
            b = bytes([n & 0xFF]) + b
            n >>= 8
        if b == b"":
            b = b"\x00"
        return b
    else:
        b = b''
        while length > 0:
            b = bytes([n & 0xFF]) + b
            n >>= 8
            length -= 1
        return b    

def sp(byte_repr):
    if len(byte_repr) == 0:
        return b"\x00"
    if byte_repr[0] & 0x80:
        return b"\x00" + bytes(byte_repr)
    return bytes(byte_repr)

def asn1_len(value_bytes):
    length = len(value_bytes)
    if length < 128:
        return bytes([length])
    else:
        len_bytes = ib(length)
        return bytes([len(len_bytes) | 0x80]) + len_bytes

def asn1_boolean(boolean):
    if boolean:
        boolean = b"\xff"
    else:
        boolean = b"\x00"
    return bytes([0x01]) + asn1_len(boolean) + boolean

def asn1_null():
    return bytes([0x05, 0x00])

def asn1_integer(i):
    encoded_value = sp(ib(i))
    encoded_length = asn1_len(encoded_value)
    return bytes([0x02]) + encoded_length + encoded_value

def asn1_bitstring(bitstr):
    if len(bitstr) == 0:
        return bytes([0x03, 0x01, 0x00])
    # build integer value from bit string
    value = 0
    for ch in bitstr:
        value = (value << 1) | (1 if ch == "1" else 0)
    # number of unused bits in final octet
    padding = (8 - (len(bitstr) % 8)) % 8
    # shift to make total bits byte-aligned
    value <<= padding
    total_bytes = (len(bitstr) + padding) // 8
    value_bytes = ib(value, total_bytes)
    content = bytes([padding]) + value_bytes
    return bytes([0x03]) + asn1_len(content) + content

def asn1_octetstring(octets):
    return bytes([0x04]) + asn1_len(octets) + octets

def asn1_objectidentifier(oid):
    first_byte = 40 * oid[0] + oid[1]
    content = bytes([first_byte])

    def _base128_encode(n):
        if n == 0:
            return b"\x00"
        parts = []
        while n > 0:
            parts.append(n & 0x7F)
            n >>= 7
        parts.reverse()
        for i in range(len(parts) - 1):
            parts[i] |= 0x80
        return bytes(parts)

    for comp in oid[2:]:
        content += _base128_encode(comp)

    return bytes([0x06]) + asn1_len(content) + content

def asn1_sequence(der):
    return bytes([0x30]) + asn1_len(der) + der

def asn1_set(der):
    return bytes([0x31]) + asn1_len(der) + der

def asn1_utf8string(utf8bytes):
    return bytes([0x0C]) + asn1_len(utf8bytes) + bytes(utf8bytes)

def asn1_utctime(time):
    return bytes([0x17]) + asn1_len(time) + bytes(time)

def asn1_tag_explicit(der, tag):
    tag_octet = 0xA0 | (tag & 0x1F)
    tag_bytes = bytes([tag_octet])
    return tag_bytes + asn1_len(der) + der

asn1 = asn1_tag_explicit(
    asn1_sequence(
        asn1_set(  
            asn1_integer(5) + 
            asn1_tag_explicit(asn1_integer(200),2) +
            asn1_tag_explicit(asn1_integer(65407), 11)
        ) +
        asn1_boolean(True) + 
        asn1_bitstring("011") + 
        asn1_octetstring(b"\x00\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02") + 
        asn1_null() +
        asn1_objectidentifier([1,2,840,113549,1]) +
        asn1_utf8string(b'hello.') +
        asn1_utctime(bytes(b"250223010900Z"))
    ), 0)
open(sys.argv[1], 'wb').write(asn1)