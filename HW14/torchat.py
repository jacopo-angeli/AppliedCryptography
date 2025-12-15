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
        
def log_received(line):
    if line:
        print(f"[+] Received: {line}")

my_id = args.myself.strip()
peer_id_arg = args.peer.strip()
peer_host = peer_id_arg.strip() if peer_id_arg.strip().endswith(".onion") else (peer_id_arg.strip() + ".onion")
peer_id_plain = peer_id_arg.rstrip(".onion")
peer_port = 11009
cookie_self = str(secrets.randbits(128))

# connecting to peer
try:
    outgoing = socks.socksocket()
    print(f"[+] Connecting to peer {peer_host}")
    outgoing.settimeout(30)
    outgoing.connect((peer_host, peer_port))
except Exception as e:
    print(f"[!] Failed to connect to peer: {e}")
    sys.exit(1)

# sending ping
send_torchat_cmd(outgoing, f"ping {my_id} {cookie_self}")

# listening for the incoming connection
print("[+] Listening...")
try:
    sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sserv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sserv.bind(("127.0.0.1", 8888))
    sserv.listen(0)
    print("[+] Listening...")
    incoming_socket, address = sserv.accept()
    print("[+] Client %s:%s" % (address[0], address[1]))
except Exception as e:
    print(f"[!] Failed to listen/accept: {e}")
    outgoing.close()
    sys.exit(1)

incoming_authenticated = False
cookie_peer = ""

def send_post_auth():
        send_torchat_cmd(outgoing, "add_me")
        send_torchat_cmd(outgoing, f"status {args.status}")
        send_torchat_cmd(outgoing, f"profile_name {args.name}")

try:
    while True:
        cmdr = read_torchat_cmd(incoming_socket)
        if cmdr == "":
            break
        log_received(cmdr)
        parts = cmdr.split(' ')
        if not parts:
            continue
        op = parts[0]

        if op == "ping":
            # Expected: ping <peer_id> <cookie_peer>
            if len(parts) >= 3:
                recv_peer = parts[1].rstrip(".onion")
                cookie_peer = " ".join(parts[2:]).strip()
                if recv_peer != peer_id_plain:
                    print(f"[!] Peer ID mismatch: expected {peer_id_plain}, got {recv_peer}")
                    cookie_peer = ""
                    continue
            else:
                print("[!] Malformed ping")
                continue

        elif op == "pong":
            # Expected: pong <cookie_self>
            if len(parts) >= 2:
                recv_cookie = " ".join(parts[1:]).strip()
                if recv_cookie == cookie_self:
                    if not incoming_authenticated:
                        incoming_authenticated = True
                        print("[+] Incoming connection authenticated!")
                        if cookie_peer:
                            send_torchat_cmd(outgoing, f"pong {cookie_peer}")
                        send_post_auth()
                else:
                    print(f"[!] Cookie mismatch: expected {cookie_self}, got {recv_cookie}")
            else:
                print("[!] Malformed pong")

        elif op == "message":
            if incoming_authenticated:
                try:
                    reply = input("[?] Enter message: ").strip()
                except EOFError:
                    reply = ""
                if reply:
                    send_torchat_cmd(outgoing, f"message {reply}")
            else:
                print("[!] Ignoring message until authenticated")

        elif op in ("client", "version", "profile_name", "status"):
            # Informational; no action required here
            pass

        else:
            # Unknown command
            pass
finally:
    incoming_socket.close()
    sserv.close()
    outgoing.close()