#!/usr/bin/env python3

import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py
import hmac # do not use any other imports/libraries

# took x.y hours (please specify here how much time your solution required)

#==== ASN1 encoder start ====
# put your DER encoder functions here

#==== ASN1 encoder end ====

def mac(filename):
    key = input("[?] Enter key: ").encode()

    print("[+] Calculated HMAC-SHA256:", digest.hex())

    print("[+] Writing HMAC DigestInfo to", filename+".hmac")

def verify(filename):
    print("[+] Reading HMAC DigestInfo from", filename+".hmac")

    # print out the digest

    # ask for the key

    # print out the calculated HMAC-X digest

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
