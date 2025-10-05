#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# 4.5h (please specify here how much time your solution required)

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
    for byte in b:
        i <<= 8
        i |= byte
    return i

#==== ASN1 encoder start ====

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

def pem_to_der(content):
    # converts PEM content to DER
    content = content.strip()
    if content.startswith(b'-----BEGIN'):
        # extract base64 body between BEGIN/END and decode
        b64 = b''.join(content.splitlines()[1:-1])
        return codecs.decode(b64, 'base64')
    else:
        # assume already DER
        return content

def get_pubkey(filename):
    # reads public key file encoded using SubjectPublicKeyInfo structure and returns (N, e)
    with open(filename, 'rb') as f:
        pem = f.read()
    der = decoder.decode(pem_to_der(pem))
    # DER-decode the DER to get RSAPublicKey DER structure, which is encoded as BITSTRING
    RSAPublicKey = der[0][1]
    # convert BITSTRING to bytestring
    RSAPublicKey = RSAPublicKey.asOctets()
    # DER-decode the bytestring (which is actually DER) and return (N, e)
    pubkey = decoder.decode(RSAPublicKey)[0]
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file encoded using PrivateKeyInfo (PKCS#8) structure and returns (N, d)
    with open(filename, 'rb') as f:
        pem = f.read()
    der = decoder.decode(pem_to_der(pem))
    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    RSAPrivateKey = der[0][2].asOctets()
    # DER-decode the octetstring (which is actually DER) and return (N, d)
    privkey = decoder.decode(RSAPrivateKey)
    return int(privkey[0][1]), int(privkey[0][3])
    

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate number of bytes required to represent the modulus N
    k = (n.bit_length() + 7) // 8
    
    # plaintext must be at least 11 bytes smaller than the modulus
    if len(plaintext) > k - 11:
        raise ValueError("Plaintext too long")
    
    # generate padding bytes
    PS = b''
    while len(PS) < k - len(plaintext) - 3:
        b = os.urandom(1)
        if b != b'\x00':
            PS += b

    padded_plaintext = b'\x00\x02' + PS + b'\x00' + plaintext
    return padded_plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5
    
    # calculate bytelength of modulus N
    k = (n.bit_length() + 7) // 8
    
    # plaintext must be at least 11 bytes smaller than the modulus N
    if len(plaintext) > k - 11:
        raise ValueError("Plaintext too long")
    
    # generate padding bytes
    PS = b'\xff' * (k - len(plaintext) - 3)
            
    # return padded_plaintext
    return b'\x00\x01' + PS + b'\x00' + plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    return plaintext[(plaintext.find(b'\x00', 2))+1:]

def encrypt(keyfile, plaintextfile, ciphertextfile):
    N,e = get_pubkey(keyfile)
    
    # Pad plain text
    with open(plaintextfile, 'rb') as f:
        plaintext = pkcsv15pad_encrypt(f.read(), N)    
    
    # Convert padded byte string to integer
    m = bi(plaintext)
    
    # Calculate ciphertext: c = m^e mod N
    c = pow(m,e,N)
    
    # Convert ciphertext integer to byte string
    k = (N.bit_length()+7)//8
    ciphertext = ib(c,k)
      
    # Write ciphertext to file
    with open(ciphertextfile, 'wb') as f:
        f.write(ciphertext)        

def decrypt(keyfile, ciphertextfile, plaintextfile):
    
    N,e = get_privkey(keyfile)
    
    # Convert ciphertext to integer
    with open(ciphertextfile, 'rb') as f:
        ciphertext = bi(f.read())  
    
    # Calculate decryption: m = c^d mod N
    m = 1
    for bit in bin(e)[2:]:
        m = (m * m) % N
        if bit == '1':
            m = (m * ciphertext) % N
       
    # Convert decrypted integer to byte string
    plaintext = ib(m,(N.bit_length()+7)//8)

    # Remove padding
    plaintext = pkcsv15pad_remove(plaintext)

    # Write plaintext to file
    with open(plaintextfile, 'wb') as f:
        f.write(plaintext)

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    with open(filename, 'rb') as f:
        digest = hashlib.sha256(f.read()).digest()
    der = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) + # OID for SHA-256
            asn1_null()
        ) + 
        asn1_octetstring(digest)
    )
    return der

def sign(keyfile, filetosign, signaturefile):
    N,d = get_privkey(keyfile)
    
    # Construct plaintext (DER DigestInfo of the file to sign)
    plaintext = digestinfo_der(filetosign)
    
    
    # Pad plaintext
    plaintext = pkcsv15pad_sign(plaintext, N)
    
    # Convert padded byte string to integer
    m = bi(plaintext)
    
    # Calculate signature: s = m^d mod N
    s = pow(m,d,N)

    # Convert signature integer to byte string
    k = (N.bit_length()+7)//8
    signature = ib(s,k)

    # Write signature to file
    with open(signaturefile, 'wb') as f:
        f.write(signature)

def verify(keyfile, signaturefile, filetoverify):
    N,e = get_pubkey(keyfile)
    
    # Convert signature byte string to integer
    with open(signaturefile, 'rb') as f:
        signature = f.read()
    s = bi(signature)
    
    # Calculate decryption: m = s^e mod N
    m = pow(s,e,N)

    # Convert decrypted integer to byte string
    k = (N.bit_length()+7)//8
    plaintext = ib(m,k)
    
    # Remove padding to obtain DER DigestInfo structure
    plaintext = pkcsv15pad_remove(plaintext)

    # Compare DigestInfo with DigestInfo of the signed file
    expected = digestinfo_der(filetoverify)
    if plaintext == expected:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
