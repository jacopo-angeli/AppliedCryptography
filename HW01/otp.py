#!/usr/bin/env python3
import os, sys 
# took .5 hours

def bi(b):
    result = 0
    for byte in b:
        result = (result << 8) | byte
    return result

def ib(i, length):
    b = b''
    for shift in range(length-1, -1, -1):
        b += bytes([(i >> (shift * 8)) & 0xFF])
    return b

def encrypt(pfile, kfile, cfile):
    PTbytes = open(pfile, 'rb').read()
    PTInt = bi(PTbytes)
    Kbytes = os.urandom(len(PTbytes))
    KInt = bi(Kbytes)
    CTInt = PTInt ^ KInt
    CTbytes = ib(CTInt, len(PTbytes))
    open(cfile, 'wb').write(CTbytes)
    open(kfile, 'wb').write(Kbytes)    

def decrypt(cfile, kfile, pfile):
    CTBytes = open(cfile, 'rb').read()
    KBytes = open(kfile, 'rb').read()
    KInt = bi(KBytes)
    CTInt = bi(CTBytes)
    PTInt = CTInt ^ KInt
    PTBytes = ib(PTInt, len(CTBytes))
    open(pfile, 'wb').write(PTBytes)

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()