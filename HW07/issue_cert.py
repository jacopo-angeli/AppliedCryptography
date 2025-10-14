#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took x.y hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

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
# put your DER encoder functions here

#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads RSA private key file and returns (n, d)

    return int(privkey[0][1]), int(privkey[0][3])

def pkcsv15pad_sign(plaintext, n):
    # pads plaintext for signing according to PKCS#1 v1.5

    # calculate byte size of modulus n

    # plaintext must be at least 11 bytes smaller than modulus

    # add padding bytes

def digestinfo_der(m):
    # returns ASN.1 DER-encoded DigestInfo structure containing SHA256 digest of m
    return der


def sign(m, keyfile):
    # signs DigestInfo of message m

    return signature


def get_subject_cn(csr_der):
    # returns CommonName value from CSR's Distinguished Name field

    # looping over Distinguished Name entries until CN found

def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR

def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    return encoder.encode(decoder.decode(cert_der)[0][0][5])

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    # returns X.509v3 certificate in PEM format

    return pem

# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN for end-entity's certificate
subject = asn1_sequence(...)

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)
