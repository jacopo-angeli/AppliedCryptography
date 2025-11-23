#!/usr/bin/env python3

import argparse, codecs, datetime, os, socket, sys, time # do not use any other imports/libraries
from urllib.parse import urlparse

# took x.y hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
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

# returns TLS record that contains ClientHello Handshake message
def client_hello():
    print("--> ClientHello()")
    
    # Client random ----------------------------------------------
    gmt_unix_time = int(time.time())
    client_random = ib(gmt_unix_time, 4) + os.urandom(28)
    # ------------------------------------------------------------

    # Chipher suites ---------------------------------------------
    csuite  = b"\xC0\x2F"              # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    csuite += b"\xC0\x30"              # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    csuite += b"\xC0\x2B"              # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    csuite += b"\xC0\x2C"              # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    csuite += b"\x00\x05"              # TLS_RSA_WITH_RC4_128_SHA
    csuite += b"\x00\x2f"              # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite += b"\x00\x35"              # TLS_RSA_WITH_AES_256_CBC_SHA
    csuite += b"\x00\x39"              # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    # ------------------------------------------------------------
    
    # Extensions ------------------------------------------------
    extensions = b""
    # SNI Extension 
    hostname = host.encode("ascii")              
    sni_name = b"\x00" + ib(len(hostname), 2) + hostname            # ServerName = name_type(1) + name_len(2) + host
    sni_list = ib(len(sni_name), 2) + sni_name                      # ServerNameList = list_len(2) + sni_name
    sni_ext = b"\x00\x00" + ib(len(sni_list), 2) + sni_list         # Extension "server_name" = type(2) + ext_len(2) + sni_list
    extensions += sni_ext                                           # Extensions block = all_extensions_length(2) + sni_ext
    # Signature_algorithms
    sigs = b"\x04\x03\x04\x01"
    sigs_list = ib(len(sigs), 2) + sigs
    extensions += b"\x00\x0d" + ib(len(sigs_list), 2) + sigs_list
    # ------------------------------------------------------------
    
    # Body -------------------------------------------------------
    hello  = b"\x03\x03"                # TLS 1.2
    hello += client_random              # 32 bytes
    hello += b"\x00"                    # Session ID length = 0
    hello += ib(len(csuite), 2)         # Cipher suites length
    hello += csuite
    hello += b"\x01"                    # Compression methods length
    hello += b"\x00"                    # "null" compression
    hello += ib(len(extensions), 2) + extensions
    # ------------------------------------------------------------

    # Handshake header -------------------------------------------
    handshake  = b"\x01"                # Handshake type: ClientHello
    handshake += ib(len(hello), 3)      # Length (3 bytes)
    handshake += hello
    # ------------------------------------------------------------

    # TLS record -------------------------------------------------
    record  = b"\x16"                   # Handshake record
    record += b"\x03\x03"               # TLS 1.2 record version
    record += ib(len(handshake), 2)     # Record length
    record += handshake
    # ------------------------------------------------------------

    return record

def alert():
    print("--> Alert()")
    level = b"\x02"                     # Fatal
    description = b"\x2e"               # certificate_unknown (46)
    alert_msg = level + description
    record  = b"\x15"                   # Content type: Alert (21)
    record += b"\x03\x03"               # TLS version: TLS 1.2
    record += ib(len(alert_msg), 2)     # Length (2 bytes)
    record += alert_msg
    return record


def parsehandshake(r):
    global server_hello_done_received

    print("<--- Handshake()")

    if len(r) < 4:
        print("[-] Handshake message too short!")
        sys.exit(1)

    htype = r[0:1]       
    hlen  = bi(r[1:4]) 

    if len(r) < 4 + hlen:
        print("[-] Incomplete handshake message!")
        sys.exit(1)

    body = r[4:4+hlen]
    leftover = r[4+hlen:]  

    # ServerHello ------------------------------------------
    if htype == b"\x02":
        print("    <--- ServerHello()")
        server_rand = body[2:34]
        sess_id_len = body[34]
        pos = 35
        sess_id = body[pos:pos+sess_id_len] 
        pos += sess_id_len
        cipher = body[pos:pos+2]
        pos += 2
        compression = body[pos:pos+1]
        pos += 1
        gmt_unix_time = bi(server_rand[:4])
        dt = datetime.datetime.fromtimestamp(gmt_unix_time)
        print("    [+] server randomness:", server_rand.hex().upper())
        print("    [+] server timestamp:", dt.strftime("%Y-%m-%d %H:%M:%S"))
        print("    [+] TLS session ID:", sess_id.hex().upper())
        ciphers_map = {
            b"\x00\x05": "TLS_RSA_WITH_RC4_128_SHA",
            b"\x00\x2f": "TLS_RSA_WITH_AES_128_CBC_SHA",
            b"\x00\x35": "TLS_RSA_WITH_AES_256_CBC_SHA",
            b"\x00\x39": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            b"\xC0\x2F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            b"\xC0\x30": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            b"\xC0\x2B": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            b"\xC0\x2C": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        }
        print("    [+] Cipher suite:", ciphers_map.get(cipher, "UNKNOWN " + cipher.hex()))
        if compression != b"\x00":
            print("[-] Wrong compression:", compression.hex())
            sys.exit(1)
    # ------------------------------------------------------------

    # Certificate ------------------------------------------------
    elif htype == b"\x0b":
        print("    <--- Certificate()")

        certlist_len = bi(body[0:3])
        print("    [+] Server certificate length:", certlist_len)

        cert_len = bi(body[3:6])
        cert_data = body[6:6+cert_len]

        if args.certificate:
            print(f"    [+] Saving server certificate to: {args.certificate}")
            with open(args.certificate, "wb") as f:
                pem = b"-----BEGIN CERTIFICATE-----\n"
                b64_cert = codecs.encode(cert_data, "base64")       
                if isinstance(pem, bytes):
                    pem += b64_cert
                else:
                    pem += b64_cert.decode("ascii")
                pem += b"-----END CERTIFICATE-----\n"
                f.write(pem)
    # ------------------------------------------------------------

    # ServerHelloDone --------------------------------------------
    elif htype == b"\x0e":
        print("    <--- ServerHelloDone()")
        server_hello_done_received = True
    # ------------------------------------------------------------
        
    # ServerKeyExchange ------------------------------------------
    elif htype == b"\x0c":
        print("    <--- ServerKeyExchange() (ignored)")
    # ------------------------------------------------------------

    # Fallback ---------------------------------------------------
    else:
        print("[-] Unknown Handshake type:", htype.hex())
        sys.exit(1)
    # ------------------------------------------------------------
    
    if len(leftover):
        parsehandshake(leftover)
        
        
def parserecord(r):
    
    if len(r) < 5:
        print("[-] Record too short!")
        sys.exit(1)

    rtype = r[0:1]
    length = bi(r[3:5])

    if len(r) != 5 + length:
        print("[-] Invalid TLS record length!")
        sys.exit(1)

    body = r[5:]

    # Handshake --------------------------------------------------
    if rtype == b"\x16": 
        parsehandshake(body)
    # ------------------------------------------------------------
        

    # Alert ------------------------------------------------------
    elif rtype == b"\x15": 
        print("<--- Alert()")

        if len(body) != 2:
            print("[-] Invalid alert message!")
            sys.exit(1)

        level = body[0]
        desc = body[1]

        if level == 1:
            print("[-] warning:", desc)
        elif level == 2:
            print("[-] fatal:", desc)
        else:
            print("[-] unknown alert level:", level)

        sys.exit(1)
    # ------------------------------------------------------------

    else:
        print("[-] Unexpected TLS record type:", rtype.hex())
        sys.exit(1)


def readrecord():
    global s

    record = b""
    header = b""
    while len(header) < 5:
        chunk = s.recv(5 - len(header))
        if not chunk:
            print("[-] Connection closed while reading TLS header")
            sys.exit(1)
        header += chunk

    length = bi(header[3:5])
    body = b""
    while len(body) < length:
        chunk = s.recv(length - len(body))
        if not chunk:
            print("[-] Connection closed while reading TLS body")
            sys.exit(1)
        body += chunk

    record = header + body
    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]
path = url.path

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    parserecord(readrecord())
s.send(alert())

print("[+] Closing TCP connection!")
s.close()
