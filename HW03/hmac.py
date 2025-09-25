#!/usr/bin/env python3

import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py
import hmac # do not use any other imports/libraries

# took 2 hours 

#==== ASN1 encoder start ====
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

#==== ASN1 encoder end ====

def mac(filename):
    key = input("[?] Enter key: ").encode()
    
    h = hmac.new(key, None, hashlib.sha256)
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(512)
            if not chunk:
                break
            h.update(chunk)
    digest = h.digest()
    print("[+] Calculated HMAC-SHA256: {}".format(digest.hex()))

    print("[+] Writing HMAC DigestInfo to {}".format(filename+".hmac"))
    with open(filename + ".hmac", 'wb') as f:
        f.write(
            asn1_sequence(
                asn1_sequence(
                    asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) +
                    asn1_null()
                ) +
                asn1_octetstring(digest)
            )
        )

def verify(filename):
    print("[+] Reading HMAC DigestInfo from {}".format(filename+".hmac"))
    
    # print out the digest
    der = open(filename + ".hmac", 'rb').read()
    decoded, _ = decoder.decode(der)
    alg_seq = decoded[0]
    oid_obj = alg_seq[0]
    oid_str = '.'.join(str(x) for x in oid_obj)
    digest = decoded[1].asOctets()
    print("[+] HMAC in file: {}".format(digest.hex()))
    
    # ask for the key
    key = input("[?] Enter key: ").encode()

    # print out the calculated HMAC-X digest
    if oid_str == '1.2.840.113549.2.5':
        digestmod = hashlib.md5
        alg_name = 'MD5'
    elif oid_str == '1.3.14.3.2.26':
        digestmod = hashlib.sha1
        alg_name = 'SHA1'
    elif oid_str == '2.16.840.1.101.3.4.2.1':
        digestmod = hashlib.sha256
        alg_name = 'SHA256'
    else:
        print("[-] Unsupported algorithm OID: {}".format(oid_str))
        return

    h = hmac.new(key, None, digestmod)
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(512)
            if not chunk:
                break
            h.update(chunk)
            
    digest_calculated = h.digest()
    print("[+] Calculated HMAC-{}: {}".format(alg_name, digest_calculated.hex()))

    if digest_calculated != digest:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")

def usage():
    print("Usage:")
    print("-mac <filename>")
    print("-verify <filename>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
