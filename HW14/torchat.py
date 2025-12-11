#!/usr/bin/env python3

import argparse
import socks
import socket
import sys
import secrets # https://docs.python.org/3/library/secrets.html


# took x.y hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TorChat client')
parser.add_argument('--myself', required=True, type=str, help='My TorChat ID')
parser.add_argument('--peer', required=True, type=str, help='Peer\'s TorChat ID')
args = parser.parse_args()

# route outgoing connections through Tor
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

# reads and returns torchat command from the socket
def read_torchat_cmd(incoming_socket):
    buf = b""
    while True:
        chunk = incoming_socket.recv(4096)
        if not chunk:
            # connection closed
            return ""
        buf += chunk
        if b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            # keep any extra data in the socket's internal buffer is not possible,
            # so we just return the first line
            return line.strip(b"\r").decode("utf-8", errors="replace")

def send_torchat_cmd(outgoing_socket, cmd):
    if not isinstance(cmd, str):
        cmd = str(cmd)
    print(f"[>] {cmd}")
    data = (cmd + "\n").encode("utf-8")
    try:
        outgoing_socket.sendall(data)
    except Exception as e:
        print(f"[!] Failed to send command: {e}")

# connecting to peer

# sending ping

# listening for the incoming connection
print("[+] Listening...")


print("[+] Client %s:%s" % (address[0], address[1]))


incoming_authenticated = False
status_received = False
cookie_peer = ""

# the main loop for processing the received commands
while True:
    cmdr = read_torchat_cmd(incoming_socket)

    cmd = cmdr.split(' ')

    if cmd[0]=='ping':
        pass
