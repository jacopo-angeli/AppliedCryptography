#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from secp256r1 import curve
from pyasn1.codec.der import decoder

# 7h

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

# --------------- asn1 DER encoder

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
        value = (value << 1) | (1 if ch == "1" else 0)
    padding = (8 - (len(bitstr) % 8)) % 8
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

# --------------- asn1 DER encoder end


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads EC private key file and returns the private key integer (d)
    with open(filename, 'rb') as f:
        der = decoder.decode(pem_to_der(f.read()))    
    ECPrivateKey = decoder.decode(der[0][2].asOctets())
    d = bi(ECPrivateKey[0][1])
    return d

def get_pubkey(filename):
    # reads EC public key file and returns coordinates (x, y) of the public key point
    with open(filename, 'rb') as f:
        der = decoder.decode(pem_to_der(f.read()))
    ECPoint = der[0][1]
    ECPoint_bytes = ECPoint.asOctets()
    if ECPoint_bytes[0] == 0x04:
        # uncompressed form
        field_size = (curve.p.bit_length() + 7) // 8
        x = bi(ECPoint_bytes[1:1+field_size])
        y = bi(ECPoint_bytes[1+field_size:1+2*field_size])
    elif ECPoint_bytes[0] in (0x02, 0x03):
        # compressed form
        field_size = (curve.p.bit_length() + 7) // 8
        x = bi(ECPoint_bytes[1:1+field_size])
        # decompress y
        alpha = (x * x * x + curve.a * x + curve.b) % curve.p
        beta = pow(alpha, (curve.p + 1) // 4, curve.p)
        if (beta % 2) == (ECPoint_bytes[0] & 1):
            y = beta
        else:
            y = curve.p - beta
    elif ECPoint_bytes[0] == 0x00:
        # point at infinity
        x = 0
        y = 0
    return (x,y)

def ecdsa_sign(keyfile, filetosign, signaturefile):

    # get the private key
    d = get_privkey(keyfile)

    # calculate SHA-384 hash of the file to be signed
    with open(filetosign, 'rb') as f:
        data = f.read()
    h = hashlib.sha384(data).digest()
    
    # truncate the hash value to the curve size
    n = curve.n
    nbytes = (n.bit_length() + 7) // 8
    h_trunc = h[:nbytes]
    
    # convert hash to integer
    z = bi(h_trunc)
    
    # generate a random nonce k in the range [1, n-1]
    while True:
        k = bi(os.urandom(nbytes)) % (n - 1) + 1
        # calculate ECDSA signature components r and s
        R = curve.mul(curve.g, k)
        r = R[0] % n
        if r == 0:
            continue
        k_inv = pow(k, -1, n)
        s = (k_inv * (z + r * d)) % n
        if s == 0:
            continue
        break

    # DER-encode r and s
    der_seq = asn1_sequence(asn1_integer(r) + asn1_integer(s))

    # write DER structure to file
    with open(signaturefile, 'wb') as f:
        f.write(der_seq)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    Qx, Qy = get_pubkey(keyfile)
    Q = (Qx, Qy)
    
    with open(signaturefile, 'rb') as f:
        sig = f.read()
    seq, _ = decoder.decode(sig)
    r = int(seq.getComponentByPosition(0))
    s = int(seq.getComponentByPosition(1))

    n = curve.n
    if not (1 <= r < n and 1 <= s < n):
        print("Verification failure")
        return

    with open(filetoverify, 'rb') as f:
        data = f.read()
    h = hashlib.sha384(data).digest()
    nbytes = (n.bit_length() + 7) // 8
    z = bi(h[:nbytes])

    try:
        w = pow(s, -1, n)
    except TypeError:
        w = pow(s, n-2, n)

    u1 = (z * w) % n
    u2 = (r * w) % n

    P1 = curve.mul(curve.g, u1)
    P2 = curve.mul(Q, u2)
    R = curve.add(P1, P2)

    if R is None or R[0] is None:
        print("Verification failure")
        return

    if (R[0] % n) == r:
        print("Verified OK")
    else:
        print("Verification failure")


def usage():
    print("Usage:")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
