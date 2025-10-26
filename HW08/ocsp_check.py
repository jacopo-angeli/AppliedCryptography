#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

# took x.y hours (please specify here how much time your solution required)

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
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    return encoder.encode(decoder.decode(cert)[0][0][5])

def get_key(cert):
    return decoder.decode(cert)[0][0][6][1].asOctets()

def get_serial(cert):
    return int(decoder.decode(cert)[0][0][1])

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form

    # construct CertID (use SHA1)
    issuer_name = get_name(issuer_cert)
    issuer_key = get_key(issuer_cert)
    serial = get_serial(cert)

    print("[+] OCSP request for serial:", serial)

    # construct entire OCSP request
    reqCert = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier((1, 3, 14, 3, 2, 26)) +  # SHA-1 OID
            asn1_null()
        ) +
        asn1_octetstring(hashlib.sha1(issuer_name).digest()) +
        asn1_octetstring(hashlib.sha1(issuer_key).digest()) +
        asn1_integer(serial)
    )

    request = asn1_sequence(reqCert)
    request_list = asn1_sequence(request)
    tbsRequest = asn1_sequence(request_list)
    OCSPRequest = asn1_sequence(tbsRequest)
    
    return OCSPRequest

def send_req(ocsp_req, ocsp_url):
    # sends OCSP request to OCSP responder

    # parse OCSP responder's url
    url = urlparse(ocsp_url)
    host = url.hostname
    if host is None:
        print("[-] Invalid issuer URL")
        exit(1)
    port = url.port or (443 if url.scheme == 'https' else 80)
    path = url.path or '/'
    if url.query:
        path += '?' + url.query
        
    # connect to host
    print("[+] Connecting to %s..." % (host))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    if url.scheme == 'https':
        import ssl
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)
        
    # send HTTP POST request
    req_headers = (
        "POST {path} HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Type: application/ocsp-request\r\n"
        "Accept: application/ocsp-response\r\n"
        "Connection: close\r\n"
        "Content-Length: {length}\r\n"
        "\r\n"
    ).format(path=path, host=host, length=len(ocsp_req)).encode()
    s.sendall(req_headers + ocsp_req)

    # read HTTP response header
    header = b''
    while b'\r\n\r\n' not in header:
        bch = s.recv(1)
        if not bch:
            break
        header += bch
    header_raw, body = header.split(b'\r\n\r\n', 1)
    status_line = header_raw.split(b'\r\n', 1)[0].decode(errors='ignore')
    status_code = int(status_line.split()[1])
    if status_code != 200:
        s.close(); print(f"[-] HTTP GET returned status {status_code}"); exit(1)  # noqa: E702

    # get HTTP response length
    headers = {}
    for line in header_raw.split(b'\r\n')[1:]:
        if b':' in line:
            k, v = line.split(b':', 1)
            headers[k.decode().strip().lower()] = v.decode().strip()
    length = int(headers['content-length'])

    # read HTTP response body
    data = body
    while len(data) < length:
        chunk = s.recv(1)
        if not chunk:
            s.close(); print("[-] Connection closed while reading body"); exit(1)  # noqa: E702
        data += chunk
    s.close()
    ocsp_resp = data[:length]

    return ocsp_resp

def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension

    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())

    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0]) == '1.3.6.1.5.5.7.1.1':  # AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                # id-ad-caIssuers OID
                if str(aia[0]) == '1.3.6.1.5.5.7.48.2':
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] issuer cert URL not found in the certificate!")
    exit(1)

def download_issuer_cert(issuer_cert_url):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)
    host = url.hostname
    if host is None:
        print("[-] Invalid issuer URL")
        exit(1)
    port = url.port or (443 if url.scheme == 'https' else 80)
    path = url.path or '/'
    if url.query:
        path += '?' + url.query

    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    if url.scheme == 'https':
        import ssl
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)

    # send HTTP GET request
    req = (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
    ).format(path=path, host=host).encode()
    s.sendall(req)

    # read HTTP response header
    header = b''
    while b'\r\n\r\n' not in header:
        bch = s.recv(1)
        if not bch:
            s.close() ;print("[-] Connection closed while reading header") ; exit(1)  # noqa: E702
        header += bch
    header_raw, body = header.split(b'\r\n\r\n', 1)

    status_line = header_raw.split(b'\r\n', 1)[0].decode(errors='ignore')
    status_code = int(status_line.split()[1])
    if status_code != 200:
        s.close(); print(f"[-] HTTP GET returned status {status_code}"); exit(1)  # noqa: E702

    headers = {}
    for line in header_raw.split(b'\r\n')[1:]:
        if b':' in line:
            k, v = line.split(b':', 1)
            headers[k.decode().strip().lower()] = v.decode().strip()

    # get HTTP response length
    length = int(headers['content-length'])
    data = body
    while len(data) < length:
        chunk = s.recv(1)
        if not chunk:
            s.close(); print("[-] Connection closed while reading body"); exit(1)  # noqa: E702
        data += chunk
    s.close()
    issuer_cert = data[:length]

    # read HTTP response body
    return issuer_cert

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
