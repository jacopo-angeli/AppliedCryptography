#!/usr/bin/env python3

import argparse, codecs, hmac, socket, sys, time, os, datetime
from hashlib import sha1, sha256
from Cryptodome.Cipher import ARC4
from pyasn1.codec.der import decoder  # do not use any other imports/libraries
from urllib.parse import urlparse

# took 8 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def get_pubkey_certificate(cert):
    
    def pem_to_der(content):
        if content[:2] == b'--':
            content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
            content = content.replace(b"-----END CERTIFICATE-----", b"")
            content = codecs.decode(content, 'base64')
        return content
    
    with open(cert, 'rb') as f:
        pem = f.read()

    cert_der, _ = decoder.decode(pem_to_der(pem))
    spk_bitstring = cert_der[0][6][1]
    rsapub_der = spk_bitstring.asOctets()  
    rsapub, _ = decoder.decode(rsapub_der) 

    return int(rsapub[0]), int(rsapub[1])

def pkcsv15pad_encrypt(plaintext, n):
    k = (n.bit_length() + 7) // 8
    if len(plaintext) > k - 11:
        raise ValueError("Plaintext too long")
    PS = b''
    while len(PS) < k - len(plaintext) - 3:
        b = os.urandom(1)
        if b != b'\x00':
            PS += b
    return b'\x00\x02' + PS + b'\x00' + plaintext

def rsa_encrypt(cert, m):
    # encrypts message m using public key from certificate cert
    N,e = get_pubkey_certificate(cert)    
    return ib(pow(bi(pkcsv15pad_encrypt(m, N)),e,N), (N.bit_length()+7)//8)

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if not length:
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

def send_alert(level, description):
    # level: 1=warning, 2=fatal; description examples: 20=bad_record_mac
    print("--> Alert()")
    alert_body = bytes([level, description])
    record  = b"\x15"        # Alert record type
    record += b"\x03\x03"    # TLS 1.2
    record += ib(len(alert_body), 2)
    record += alert_body
    try:
        s.send(record)
    except Exception:
        pass

# returns TLS record that contains ClientHello handshake message
def client_hello():
    global client_random, handshake_messages

    print("--> ClientHello()")
    
    # Client random ----------------------------------------------
    gmt_unix_time = int(time.time())
    client_random = ib(gmt_unix_time, 4) + os.urandom(28)
    # ------------------------------------------------------------
    
    # Chipher suites ---------------------------------------------
    csuite = b"\x00\x05"              # TLS_RSA_WITH_RC4_128_SHA
    # ------------------------------------------------------------
    
    # Extensions ------------------------------------------------
    extensions = b""
    
    # SNI Extension 
    hostname = host.encode("ascii")              
    sni_name = b"\x00" + ib(len(hostname), 2) + hostname            # ServerName = name_type(1) + name_len(2) + host
    sni_list = ib(len(sni_name), 2) + sni_name                      # ServerNameList = list_len(2) + sni_name
    sni_ext = b"\x00\x00" + ib(len(sni_list), 2) + sni_list         # Extension "server_name" = type(2) + ext_len(2) + sni_list
    extensions += sni_ext                                           
    
    # Signature_algorithms
    sigs = b"\x04\x03\x04\x01"
    sigs_list = ib(len(sigs), 2) + sigs
    sigs_ext = b"\x00\x0d" + ib(len(sigs_list), 2) + sigs_list
    extensions += sigs_ext

    # Supported Groups (Elliptic Curves) - RFC 4492 / RFC 8422
    groups  = b"\x00\x1d"  # x25519
    groups += b"\x00\x17"  # secp256r1
    groups += b"\x00\x18"  # secp384r1
    groups += b"\x00\x19"  # secp521r1
    groups_list = ib(len(groups), 2) + groups
    groups_ext = b"\x00\x0a" + ib(len(groups_list), 2) + groups_list
    extensions += groups_ext

    # Certificate Status Request (OCSP stapling) - RFC 6066
    status_req = b"\x01\x00\x00\x00\x00"  # type=ocsp(1), empty lists
    status_req_ext = b"\x00\x05" + ib(len(status_req), 2) + status_req
    extensions += status_req_ext

    # Session Ticket (RFC 5077) - empty payload to request a ticket
    extensions += b"\x00\x23" + ib(0, 2)

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
    
    handshake_messages += handshake
    
    return record

# returns TLS record that contains ClientKeyExchange message containing encrypted pre-master secret
def client_key_exchange():
    global server_cert, premaster, handshake_messages

    print("--> ClientKeyExchange()")
    
    # Generate premaster secret (48 bytes) -------------------
    premaster = b"\x03\x03"              # TLS 1.2 version
    premaster += os.urandom(46)          # 46 random bytes (total = 48 bytes)
    # --------------------------------------------------------
    
    # Encrypt premaster with server's RSA public key ---------
    encrypted_premaster = rsa_encrypt(server_cert, premaster)
    # --------------------------------------------------------

    # Body (encrypted premaster secret) ----------------------
    body = ib(len(encrypted_premaster), 2) + encrypted_premaster
    # --------------------------------------------------------
    
    # Handshake header ---------------------------------------
    handshake  = b"\x10"                # Handshake type: ClientKeyExchange
    handshake += ib(len(body), 3)       # Length (3 bytes)
    handshake += body
    # --------------------------------------------------------
    
    # Save for handshake verification (Finished message)
    handshake_messages += handshake
    
    # TLS record ---------------------------------------------
    record  = b"\x16"                   # Handshake record
    record += b"\x03\x03"               # TLS 1.2 record version
    record += ib(len(handshake), 2)     # Record length
    record += handshake
    # --------------------------------------------------------

    return record

# returns TLS record that contains ChangeCipherSpec message
def change_cipher_spec():
    print("--> ChangeCipherSpec()")
    
    # ChangeCipherSpec message body -------------------------
    # This message has only one byte: 0x01
    body = b"\x01"
    # --------------------------------------------------------
    
    # TLS record ---------------------------------------------
    record  = b"\x14"                   # ChangeCipherSpec record type
    record += b"\x03\x03"               # TLS 1.2 record version
    record += ib(len(body), 2)          # Record length
    record += body
    # --------------------------------------------------------
    
    return record

# returns TLS record that contains encrypted Finished handshake message
def finished():
    global handshake_messages, master_secret
    print("--> Finished()")
    
    # Compute verify_data using PRF ------------------------
    client_verify = PRF(master_secret, b"client finished" + sha256(handshake_messages).digest(), 12)
    # --------------------------------------------------------
    
    # Body (verify_data) ------------------------------------
    body = client_verify
    # --------------------------------------------------------
    
    # Handshake header ---------------------------------------
    handshake  = b"\x14"                # Handshake type: Finished
    handshake += ib(len(body), 3)       # Length (3 bytes)
    handshake += body
    # --------------------------------------------------------
    
    # Save for server's Finished verification
    handshake_messages += handshake
    
    # TLS record ---------------------------------------------
    record  = b"\x16"                   # Handshake record
    record += b"\x03\x03"               # TLS 1.2 record version
    # --------------------------------------------------------
    
    # Encrypt the handshake message -------------------------
    encrypted_handshake = encrypt(handshake, b"\x16", b"\x03\x03")
    # --------------------------------------------------------
    
    # Add encrypted length and data to record
    record += ib(len(encrypted_handshake), 2)
    record += encrypted_handshake
    
    return record

# returns TLS record that contains encrypted Application data
def application_data(data):
    print("--> Application_data()")
    print(data.decode().strip())
    
    # Encrypt the application data --------------------------
    encrypted_data = encrypt(data, b"\x17", b"\x03\x03")
    # --------------------------------------------------------
    
    # TLS record ---------------------------------------------
    record  = b"\x17"                       # Application data record type
    record += b"\x03\x03"                   # TLS 1.2 record version
    record += ib(len(encrypted_data), 2)    # Record length
    record += encrypted_data
    # --------------------------------------------------------
    
    return record

# parse TLS Handshake messages
def parsehandshake(r):

    global server_hello_done_received, server_random, server_cert, handshake_messages, server_change_cipher_spec_received, server_finished_received

    if server_change_cipher_spec_received:
        r = decrypt(r, b"\x16", b"\x03\x03")

    htype, hlength = r[0:1], bi(r[1:4])

    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages+= handshake
    
    # ServerHello ------------------------------------------
    if htype == b"\x02":
        print("    <--- ServerHello()")
        server_random = body[2:34]
        sess_id_len = body[34]
        pos = 35
        sess_id = body[pos:pos+sess_id_len] 
        pos += sess_id_len
        cipher = body[pos:pos+2]
        pos += 2
        compression = body[pos:pos+1]
        pos += 1
        gmt_unix_time = bi(server_random[:4])
        dt = datetime.datetime.fromtimestamp(gmt_unix_time)
        print("    [+] server randomness:", server_random.hex().upper())
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
            send_alert(2, 47)
            print("[-] Closing TCP connection!")
            s.close()
            sys.exit(1)
    # ------------------------------------------------------------
    
    # Certificate ------------------------------------------------
    elif htype == b"\x0b":
        cert_len = bi(body[3:6])
        cert_data = body[6:6+cert_len]   
        
        print("    <--- Certificate()")             
        print("    [+] Server certificate length:", cert_len)
        
        server_cert = "server.pem"
        with open(server_cert, "wb") as f:
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
        
    # NewSessionTicket -------------------------------------------
    elif htype == b"\x04":
        print("    <--- NewSessionTicket() (ignored)")
    # ------------------------------------------------------------  
    
    # Finished ---------------------------------------------------
    elif htype == b"\x14":
        print("    <--- Finished()")
        server_verify = body  # Extract verify_data from server
        verify_data_calc = PRF(master_secret, b"server finished" + sha256(handshake_messages[:-4-hlength]).digest(), 12)
        if server_verify != verify_data_calc:
            print("[-] Server finished verification failed!")
            send_alert(2, 51)
            print("[-] Closing TCP connection!")
            s.close()
            sys.exit(1)
        server_finished_received = True
    # ------------------------------------------------------------  
    
    # Fallback ---------------------------------------------------
    else:
        print("[-] Unknown Handshake Type:", htype.hex())
        sys.exit(1)
    # ------------------------------------------------------------
    
    leftover = r[4+len(body):]
    if len(leftover):
        parsehandshake(leftover)

def parse_server_handshake(body):
    global printed_server_handshake_header
    if not printed_server_handshake_header:
        print("<--- Handshake()")
        printed_server_handshake_header = True
    parsehandshake(body)

# parses TLS record
def parserecord(r):
    global server_change_cipher_spec_received, printed_server_handshake_header

    ctype = r[0:1]
    c = r[5:]

    if ctype == b"\x16":
        parse_server_handshake(c)
    
    elif ctype == b"\x14":
        print("<--- ChangeCipherSpec()")
        server_change_cipher_spec_received = True
        printed_server_handshake_header = False
    
    elif ctype == b"\x15":
        print("<--- Alert()")
        level, desc = c[0], c[1]
        if level == 1:
            print("	[-] warning:", desc)
        elif level == 2:
            print("	[-] fatal:", desc)
            sys.exit(1)
        else:
            sys.exit(1)
    
    elif ctype == b"\x17":
        print("<--- Application_data()")
        data = decrypt(c, b"\x17", b"\x03\x03")
        print(data.decode().strip())
    
    else:
        print("[-] Unknown TLS Record type:", ctype.hex())
        sys.exit(1)

# PRF defined in TLS v1.2
def PRF(secret, seed, l):
    out = b""
    A = hmac.new(secret, seed, sha256).digest()
    while len(out) < l:
        out += hmac.new(secret, A + seed, sha256).digest()
        A = hmac.new(secret, A, sha256).digest()
    return out[:l]

# derives master_secret
def derive_master_secret():
    global premaster, master_secret, client_random, server_random
    master_secret = PRF(premaster, b"master secret" + client_random + server_random, 48)

# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s

    key_block = PRF(master_secret, b"key expansion" + server_random + client_random, 136)
    mac_size = 20
    key_size = 16
    iv_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]

    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c

    mac = HMAC_sha1(client_mac_key, ib(client_seq, 8) + type + version + ib(len(plain), 2) + plain)
    ciphertext = rc4c.encrypt(plain + mac)
    client_seq+= 1
    return ciphertext
    
# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s

    d = rc4s.decrypt(ciphertext)
    mac = d[-20:]
    plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(server_mac_key, ib(server_seq, 8) + type + version + ib(len(plain), 2) + plain)
    if mac!=mac_calc:
        print("[-] MAC verification failed!")
        send_alert(2, 20)
        print("[-] Closing TCP connection!")
        s.close()
        sys.exit(1)
    server_seq+= 1
    return plain

# read from the socket full TLS record
def readrecord():
    record = b""

    # read TLS record header (5 bytes)
    for _ in range(5):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

    # find data length
    datalen = bi(record[3:5])

    # read TLS record body
    for _ in range(datalen):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

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

printed_server_handshake_header = False

client_random = b""	# will hold client randomness
server_random = b""	# will hold server randomness
server_cert = b""	# will hold DER encoded server certificate
premaster = b""		# will hold 48 byte pre-master secret
master_secret = b""	# will hold master secret
handshake_messages = b"" # will hold concatenation of handshake messages

# client/server keys and sequence numbers
client_mac_key = b""
server_mac_key = b""
client_enc_key = b""
server_enc_key = b""
client_seq = 0
server_seq = 0

# client/server RC4 instances
rc4c = b""
rc4s = b""

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
server_change_cipher_spec_received = False
server_finished_received = False

while not server_hello_done_received:
    parserecord(readrecord())

s.send(client_key_exchange())
s.send(change_cipher_spec())
derive_master_secret()
derive_keys()
s.send(finished())

while not server_finished_received:
    parserecord(readrecord())

s.send(application_data(b"GET / HTTP/1.0\r\n\r\n"))
parserecord(readrecord())

print("[+] Closing TCP connection!")
s.close()
