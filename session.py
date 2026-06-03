"""
session.py - X25519 Key Exchange + Session Key Ableitung + Ed25519 Signatur
"""
import hashlib
import secrets
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from netIP import load_public_key, base_address, load_or_create_keys
from utils import load_env
import os

load_env()
password = os.environ.get("MESH_PASSWORD", "").encode()


_sessions: dict[int, dict] = {}

# ----------------------------
# Session Store
# ----------------------------
def store_session(conn_id: int, session_key: bytes, peer_mesh: str):
    _sessions[conn_id] = {
        "key":       session_key,
        "peer_mesh": peer_mesh,
        "created":   time.time(),
    }
    print(f"[+] Session gespeichert: {conn_id} ↔ {peer_mesh}")

def get_session(conn_id: int) -> dict | None:
    return _sessions.get(conn_id)

def remove_session(conn_id: int):
    _sessions.pop(conn_id, None)

# ----------------------------
# Ephemeral Key
# ----------------------------
def gen_ephemeral() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    )
    return priv_raw, pub

def derive_session_key(own_priv: bytes, peer_pub_bytes: bytes) -> bytes:
    own      = X25519PrivateKey.from_private_bytes(own_priv)
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared   = own.exchange(peer_pub)
    return hashlib.sha256(shared).digest()

# ----------------------------
# Challenge + Timestamp
# ----------------------------
def gen_challenge() -> bytes:
    return secrets.token_bytes(32)

def check_timestamp(ts: float, window: int = 30) -> bool:
    return abs(time.time() - ts) <= window

# ----------------------------
# Signatur
# ----------------------------
def sign_hello(ed_priv: Ed25519PrivateKey, ephemeral_pub: bytes, challenge: bytes, timestamp: float) -> bytes:
    msg = ephemeral_pub + challenge + str(timestamp).encode()
    return ed_priv.sign(msg)

def verify_hello(ed_pub_bytes: bytes, ephemeral_pub: bytes, challenge: bytes, timestamp: float, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        msg = ephemeral_pub + challenge + str(timestamp).encode()
        Ed25519PublicKey.from_public_bytes(ed_pub_bytes).verify(sig, msg)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    import os
    


    pub_bytes, _  = load_public_key()
    own_mesh      = base_address(pub_bytes)
    ed_priv, _    = load_or_create_keys(password)
    conn_id       = int.from_bytes(secrets.token_bytes(8), "big")

    print(f"[*] Eigene mesh-addr : {own_mesh}")
    print(f"[*] Conn ID          : {conn_id}")

    a_priv, a_pub = gen_ephemeral()
    b_priv, b_pub = gen_ephemeral()
    print(f"[*] A ephemeral pub  : {a_pub.hex()[:32]}...")
    print(f"[*] B ephemeral pub  : {b_pub.hex()[:32]}...")

    challenge = gen_challenge()
    ts        = time.time()

    sig = sign_hello(ed_priv, a_pub, challenge, ts)
    print(f"\n[*] Signatur         : {sig.hex()[:32]}...")

    valid = verify_hello(pub_bytes, a_pub, challenge, ts, sig)
    print(f"[✓] Signatur gültig  : {'JA ✔' if valid else 'NEIN ❌'}")
    print(f"[✓] Timestamp frisch : {check_timestamp(ts)}")

    a_session = derive_session_key(a_priv, b_pub)
    b_session = derive_session_key(b_priv, a_pub)
    print(f"\n[*] A session key    : {a_session.hex()[:32]}...")
    print(f"[*] B session key    : {b_session.hex()[:32]}...")
    print(f"[✓] Identisch        : {'JA ✔' if a_session == b_session else 'NEIN ❌'}")

    store_session(conn_id, a_session, "peer-mesh-addr")

    from translation import encrypt_fragment, decrypt_fragment
    msg       = b"Hallo Session Test"
    encrypted = encrypt_fragment(msg, a_session, conn_id)
    decrypted = decrypt_fragment(encrypted, b_session, conn_id)
    print(f"\n[*] Original         : {msg}")
    print(f"[✓] Decrypted        : {decrypted}")
    print(f"[✓] Korrekt          : {'JA ✔' if decrypted == msg else 'NEIN ❌'}")