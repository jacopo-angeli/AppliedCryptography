#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys  # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took 8 hours


# parse arguments
parser = argparse.ArgumentParser(
    description="issue TLS server certificate based on CSR", add_help=False
)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()


def ib(i, length=False):
    # converts integer to bytes
    b = b""
    if length == False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xFF]) + b
        i >>= 8
    return b


def bi(b):
    # converts bytes to integer
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i


# ==== ASN1 encoder start ====


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


# ==== ASN1 encoder end ====


def der_to_pem(der):
    b64 = codecs.encode(der, "base64").replace(b"\n", b"")
    pem = b"-----BEGIN CERTIFICATE-----\n"
    for i in range(0, len(b64), 64):
        pem += b64[i : i + 64] + b"\n"
    pem += b"-----END CERTIFICATE-----\n"
    return pem


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b"--":
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, "base64")
    return content


def get_privkey(filename):
    # reads RSA private key file and returns (n, d)
    der = decoder.decode(pem_to_der(open(filename, "rb").read()))
    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    RSAPrivateKey = der[0][2].asOctets()
    # DER-decode the octetstring (which is actually DER) and return (N, d)
    privkey = decoder.decode(RSAPrivateKey)
    return int(privkey[0][1]), int(privkey[0][3])


def pkcsv15pad_sign(plaintext, n):
    k = (n.bit_length() + 7) // 8
    padding_len = k - len(plaintext) - 3
    if padding_len < 8:
        raise ValueError("message too long")
    return b"\x00\x01" + b"\xff" * padding_len + b"\x00" + plaintext


def digestinfo_der(m):
    # returns ASN.1 DER-encoded DigestInfo structure containing SHA256 digest of m
    der = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier((2, 16, 840, 1, 101, 3, 4, 2, 1)) + asn1_null()
        )
        + asn1_octetstring(hashlib.sha256(m).digest())
    )
    return der


def sign(m, keyfile):
    # signs DigestInfo of message m
    n, d = get_privkey(keyfile)
    di = digestinfo_der(m)
    em = pkcsv15pad_sign(di, n)
    s = pow(bi(em), d, n)
    k = (n.bit_length() + 7) // 8
    signature = ib(s, k)
    return signature


def get_subject_cn(csr_der):
    # returns CommonName value from CSR's Distinguished Name field
    CSR = decoder.decode(csr_der)[0]
    certificationRequestInfo = CSR[0]
    subject = certificationRequestInfo[1]

    # looping over Distinguished Name entries until CN found
    # subject is SEQUENCE of SETs of SEQUENCE { oid, value }
    for rdn in subject:
        for atv in rdn:
            oid = tuple(int(x) for x in atv[0])
            if oid == (2, 5, 4, 3):
                val = atv[1]
                try:
                    b = val.asOctets()
                except Exception:
                    try:
                        b = bytes(val)
                    except Exception:
                        return str(val)
                try:
                    return b.decode("utf-8")
                except Exception:
                    try:
                        return b.decode("latin-1")
                    except Exception:
                        return str(val)
    raise ValueError("CommonName (2.5.4.3) not found in CSR subject")


def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR
    csr = decoder.decode(csr_der)[0]
    cri = csr[0]  # CertificationRequestInfo
    spki = cri[2]  # SubjectPublicKeyInfo
    return encoder.encode(spki)


def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    return encoder.encode(decoder.decode(cert_der)[0][0][5])


def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    # returns X.509v3 certificate in PEM format
    tbsCertificate = asn1_sequence(
        asn1_tag_explicit(
            # version
            asn1_integer(2),
            0,
        )
        + asn1_integer(
            # serialNumber
            int.from_bytes(os.urandom(16), "big")
            or 1
        )
        + asn1_sequence(
            # signature
            asn1_objectidentifier((1, 2, 840, 113549, 1, 1, 11))
            + asn1_null()
        )
        + issuer
        + asn1_sequence(
            # validity
            asn1_utctime(b"250101000000Z")
            + asn1_utctime(b"260101000000Z")
        )
        + subject
        + pubkey
        + asn1_tag_explicit(
            asn1_sequence(
                # extensions
                asn1_sequence(
                    # basic constraints
                    asn1_objectidentifier((2, 5, 29, 19))
                    + asn1_boolean(True)
                    + asn1_octetstring(asn1_sequence(asn1_boolean(False)) + asn1_null())
                )
                + asn1_sequence(
                    # key usage
                    asn1_objectidentifier((2, 5, 29, 15))
                    + asn1_boolean(True)
                    + asn1_octetstring(
                        # digitalSignature (0)
                        # nonRepudiation   (1)
                        # keyEncipherment  (2)
                        # dataEncipherment (4)
                        # keyCertSign      (5)
                        # cRLSign          (6)
                        # encipherOnly     (7)
                        # decipherOnly     (8)
                        asn1_bitstring("10000000")
                    )
                )
                + asn1_sequence(
                    # extended key usage
                    asn1_objectidentifier((2, 5, 29, 37))
                    + asn1_boolean(True)
                    + asn1_octetstring(
                        asn1_sequence(
                            # id-kp-serverAuth      1 3 6 2 5 5 7 3 1
                            # id-kp-clientAuth      1 3 6 2 5 5 7 3 2
                            # id-kp-codeSigning     1 3 6 2 5 5 7 3 3
                            # id-kp-emailProtection 1 3 6 2 5 5 7 3 4
                            asn1_objectidentifier((1, 3, 6, 1, 5, 5, 7, 3, 1))
                        )
                    )
                )
            ),
            3,
        )
    )

    return der_to_pem(
        asn1_sequence(
            tbsCertificate
            + asn1_sequence(
                asn1_objectidentifier((1, 2, 840, 113549, 1, 1, 11)) + asn1_null()
            )
            + asn1_bitstring(
                "".join(f"{b:08b}" for b in sign(tbsCertificate, private_key_file))
            )
        )
    )


# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, "rb").read())
subject_cn_text = get_subject_cn(csr_der)

print('[+] Issuing certificate for "%s"' % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)


# construct subject name DN for end-entity's certificate
subject = asn1_sequence(
    asn1_set(
        asn1_sequence(
            asn1_objectidentifier((2, 5, 4, 3))
            + asn1_utf8string(subject_cn_text.encode("utf-8"))
        )
    )
)

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, "rb").read())
CAsubject = get_subjectName(CAcert)


# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, "wb").write(cert_pem)
