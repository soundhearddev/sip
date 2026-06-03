"""
translation.py - Mesh Packet → verschlüsselt → IPv6-ready bytes
"""
import os
import hashlib
import struct
import time
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from fragmentation import fragment_data, parse_packet, CHUNK_SIZE
from header import PacketType, Priority

# ----------------------------
# Session Key (in Realität per Key Exchange — hier demo)
# ----------------------------
SESSION_KEY = secrets.token_bytes(32)  # ChaCha20 braucht 32 Bytes

# ----------------------------
# Ein Fragment verschlüsseln
# ChaCha20-Poly1305: Nonce(12) + Ciphertext + Auth-Tag(16) eingebaut
# ----------------------------
def encrypt_fragment(raw: bytes, key: bytes, conn_id: int) -> bytes:
    nonce = secrets.token_bytes(12)
    aad   = conn_id.to_bytes(8, "big")  # ConnID als Associated Data
    ct    = ChaCha20Poly1305(key).encrypt(nonce, raw, aad)
    return nonce + ct

def decrypt_fragment(data: bytes, key: bytes, conn_id: int) -> bytes | None:
    if len(data) < 12:
        return None
    nonce, ct = data[:12], data[12:]
    aad = conn_id.to_bytes(8, "big")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except Exception:
        return None

# ----------------------------
# Translate: rohe Daten → verschlüsselte IPv6-ready Fragmente
# ----------------------------
def translate_outbound(data: bytes, src: str, dst: str, key: bytes = SESSION_KEY) -> list[bytes]:
    """
    Nimmt rohe Daten, fragmentiert, verschlüsselt jedes Fragment.
    Gibt Liste von bytes zurück — fertig zum Senden über IPv6/UDP.
    """
    packets  = fragment_data(data, src, dst)
    outbound = []

    for pkt in packets:
        encrypted = encrypt_fragment(pkt, key)
        outbound.append(encrypted)

    return outbound

def translate_inbound(fragments: list[bytes], key: bytes = SESSION_KEY) -> bytes | None:
    """
    Nimmt empfangene verschlüsselte Fragmente, entschlüsselt + reassembliert.
    """
    parsed_fragments = {}

    for raw in fragments:
        decrypted = decrypt_fragment(raw, key)
        if not decrypted:
            print(f"[!] Fragment entschlüsselung fehlgeschlagen — verworfen")
            continue

        parsed = parse_packet(decrypted)
        if not parsed or not parsed["auth_ok"]:
            print(f"[!] Auth fehlgeschlagen — verworfen")
            continue

        parsed_fragments[parsed["seq"]] = parsed["payload"]

    if not parsed_fragments:
        return None

    return b"".join(parsed_fragments[i] for i in sorted(parsed_fragments))

# ----------------------------
# Demo
# ----------------------------
if __name__ == "__main__":
    import hashlib

    src  = "fbfe3f0f1530d41a60a81c6d84a6e4d9"
    dst  = "a3f9b2c8d4e1f5a6b7c8d9e0f1a2b3c4"
    data = os.urandom(3500)

    print(f"[*] Original         : {len(data)} Bytes")
    print(f"[*] SHA256           : {hashlib.sha256(data).hexdigest()[:32]}...")
    print()

    # Outbound
    outbound = translate_outbound(data, src, dst)
    print(f"[*] Fragmente        : {len(outbound)}")
    print(f"[*] Größe pro Frag.  : ~{len(outbound[0])} Bytes (inkl. Nonce+AuthTag)")
    print(f"[*] Total outbound   : {sum(len(f) for f in outbound)} Bytes")
    print()

    # Inbound
    result = translate_inbound(outbound)
    print(f"[✓] Reassembliert    : {len(result)} Bytes")
    print(f"[✓] SHA256           : {hashlib.sha256(result).hexdigest()[:32]}...")
    print(f"[✓] Identisch        : {'JA ✔' if result == data else 'NEIN ❌'}")