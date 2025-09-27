#!/usr/bin/env python3

import time, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-pycryptodome
sys.path = sys.path[1:] # removes current directory from aes.py search path
from Cryptodome.Cipher import AES          # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
from Cryptodome.Util.strxor import strxor  # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-strxor-module
from hashlib import pbkdf2_hmac
import hashlib, hmac # do not use any other imports/libraries

# took 4 hours

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

#==== ASN1 encoder end ====

# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():
    
    # measure time for performing 10000 iterations
    start = time.time()
    pbkdf2_hmac('sha1', b'password', b'salt', 10000, 48)
    stop = time.time()
    took = stop-start
    
    # extrapolate to 1 second
    iter = int(10000/took)
    
    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))
    
    return iter # returns number of iterations that can be performed in 1 second

def encrypt(pfile, cfile):
        
    def _pkcs5_pad(b):
        blocksize = 16
        padlen = blocksize - (len(b) % blocksize)
        return b + bytes([padlen]) * padlen
    
    # benchmarking
    iterations = benchmark()
    
    # asking for a password
    psw = input("[?] Enter password: ")    
    
    # derieving keys
    salt = os.urandom(8)
    keys = pbkdf2_hmac('sha1', psw.encode(), salt, iterations, 48)
    aes_key = keys[:16]
    mac_key = keys[16:]
    
    # reading plaintext
    with open(pfile, 'rb') as f:
        plaintext = f.read()
            
    # padding plaintext
    plaintext = _pkcs5_pad(plaintext)
    
    # encrypting padded plaintext
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = b''
    iv_current = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        cblock = cipher.encrypt(strxor(block, iv_current))
        ciphertext += cblock
        iv_current = cblock
    
    # MAC calculation (iv+ciphertext)
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    
    # constructing DER header
    EncInfo = asn1_sequence(
        asn1_sequence(
            asn1_octetstring(salt) +
            asn1_integer(iterations) +
            asn1_integer(48)
        ) + 
        asn1_sequence(
            asn1_objectidentifier((2,16,840,1,101,3,4,1,2)) +
            asn1_octetstring(iv)
        ) + 
        asn1_sequence(
            asn1_sequence(
                asn1_objectidentifier((2,16,840,1,101,3,4,2,1)) +
                asn1_null()
            ) +
            asn1_octetstring(mac)        
        )
    )
    
    # writing DER header and ciphertext to file
    with open(cfile, 'wb') as f:
        f.write(EncInfo)
        f.write(ciphertext)
        

def decrypt(cfile, pfile):
    
    def _pkcs5_unpad(b):
        padlen = b[-1]
        return b[:-padlen]
    
    # reading DER header and ciphertext
    with open(cfile, 'rb') as f:
        asn1, ciphertext = decoder.decode(f.read())        
        
        pbkdf2params = asn1[0]
        salt = bytes(pbkdf2params[0])
        iterations = int(pbkdf2params[1])
        keylen = int(pbkdf2params[2])
        
        aesInfo = asn1[1]
        iv = bytes(aesInfo[1])
        
        hmacInfo = asn1[2]
        mac_from_header = bytes(hmacInfo[1])
    
    # asking for a password
    psw = input("[?] Enter password: ")    

    # derieving keys
    keys = pbkdf2_hmac('sha1', psw.encode(), salt, iterations, keylen)
    aes_key = keys[:16]
    mac_key = keys[16:]

    # reading ciphertext

    # before decryption checking MAC (iv+ciphertext)
    mac_calc = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_calc, mac_from_header):
        print("[-] HMAC verification failure: wrong password or modified ciphertext!")
        return

    # decrypting ciphertext
    cipher = AES.new(aes_key, AES.MODE_ECB)
    iv_current = iv
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        cblock = ciphertext[i:i+16]
        pblock = strxor(cipher.decrypt(cblock), iv_current)
        plaintext += pblock
        iv_current = cblock

    # removing padding and writing plaintext to file
    plaintext = _pkcs5_unpad(plaintext)
    with open(pfile, 'wb') as f:
        f.write(plaintext)

def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
