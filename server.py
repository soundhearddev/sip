import json
import os
import secrets
import socket
import threading
import time
from bootstrap import build_handshake
from registry import load_registry, save_registry, SUFFIX
from netIP import load_or_create_keys, load_public_key, base_address
from session import (
    gen_ephemeral, derive_session_key,
    check_timestamp, verify_hello,
    sign_hello, store_session
)
from utils import load_env

load_env()
PASSWORD = os.environ.get("MESH_PASSWORD", "").encode()

HOST           = "::"
HANDSHAKE_PORT = 9998
MESH_PORT      = 9999

def handle_handshake(conn, addr):
    with conn:
        data = conn.recv(65535)
        msg  = json.loads(data.decode())

        if msg.get("type") == "SESSION_HELLO":
            handle_session_hello(conn, addr, msg)
        else:
            handle_bootstrap(conn, addr, msg)

def handle_bootstrap(conn, addr, hs):
    own_hs = build_handshake()
    conn.sendall(json.dumps(own_hs).encode())
    name = hs["name"]
    reg  = load_registry()
    reg[name] = {
        "address": hs["mesh_addr"],
        "pubkey":  hs["pubkey"],
        "ipv6":    addr[0],
        "port":    hs["port"],
    }
    save_registry(reg)
    print(f"[+] Bootstrap: {name} → {hs['mesh_addr']}")

def handle_session_hello(conn, addr, msg):
    # Peer aus Registry laden
    peer_mesh   = msg["mesh_addr"]
    reg         = load_registry()
    peer_entry  = next((e for e in reg.values() if e.get("address") == peer_mesh), None)

    if not peer_entry:
        print(f"[!] Session von unbekanntem Peer {peer_mesh} — abgelehnt")
        conn.sendall(json.dumps({"type": "ERROR", "reason": "unknown peer"}).encode())
        return

    peer_pubkey = bytes.fromhex(peer_entry["pubkey"])
    b_pub_bytes = bytes.fromhex(msg["ephemeral_pub"])
    challenge   = bytes.fromhex(msg["challenge"])
    ts          = msg["timestamp"]
    sig         = bytes.fromhex(msg["sig"])

    # Prüfungen
    if not check_timestamp(ts):
        print(f"[!] Timestamp abgelaufen von {addr[0]}")
        conn.sendall(json.dumps({"type": "ERROR", "reason": "timestamp"}).encode())
        return

    if not verify_hello(peer_pubkey, b_pub_bytes, challenge, ts, sig):
        print(f"[!] Signatur ungültig von {addr[0]}")
        conn.sendall(json.dumps({"type": "ERROR", "reason": "invalid sig"}).encode())
        return

    # Eigene ephemeral Keys + Signatur
    pub_bytes, _ = load_public_key()
    ed_priv, _   = load_or_create_keys(PASSWORD)
    own_priv, own_pub = gen_ephemeral()
    own_ts       = time.time()
    own_sig      = sign_hello(ed_priv, own_pub, challenge, own_ts)

    conn.sendall(json.dumps({
        "type":         "SESSION_HELLO_ACK",
        "ephemeral_pub": own_pub.hex(),
        "sig":          own_sig.hex(),
        "timestamp":    own_ts,
    }).encode())

    # Session Key ableiten + speichern
    session_key = derive_session_key(own_priv, b_pub_bytes)
    conn_id     = int.from_bytes(secrets.token_bytes(8), "big")
    store_session(conn_id, session_key, peer_mesh)

    print(f"[✓] Session aktiv: {peer_mesh} conn_id={conn_id}")

def handle_mesh(data: bytes, addr: tuple):
    print(f"[<] Mesh-Paket von {addr[0]}: {len(data)} Bytes")

def tcp_listener():
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, HANDSHAKE_PORT))
        s.listen()
        print(f"[*] Handshake auf [::]:{HANDSHAKE_PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_handshake, args=(conn, addr), daemon=True).start()

def udp_listener():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, MESH_PORT))
        print(f"[*] Mesh auf [::]:{MESH_PORT}")
        while True:
            data, addr = s.recvfrom(65535)
            threading.Thread(target=handle_mesh, args=(data, addr), daemon=True).start()

def start():
    threading.Thread(target=tcp_listener, daemon=True).start()
    threading.Thread(target=udp_listener, daemon=True).start()
    print("[*] Server läuft — Ctrl+C zum Beenden")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Server gestoppt")

if __name__ == "__main__":
    start()