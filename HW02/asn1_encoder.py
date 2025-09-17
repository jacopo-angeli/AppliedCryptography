#!/usr/bin/env python3
import sys

# took (16.48 - 17.03) (9:55 - 10:37) (10:46 - 11:29) (12:49-13.30) (14.45 - ) x.y hours (please specify here how much time your solution required)

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
            length -= 8
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
    value = 0
    for ch in bitstr:
        value <<= 1
        if ch == "1":
            value |= 1
    padding = (8 - (len(bitstr) % 8)) % 8
    value <<= padding
    value = ib(padding) + ib(value, len(bitstr) + padding)
    return bytes([0x03]) + asn1_len(value) + value


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
    tag_octet = 0xA0 | (
        tag & 0x1F
    )  # context-specific (0x80) + constructed (0x20) + tag
    return bytes([tag_octet]) + asn1_len(der) + der
