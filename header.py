import struct
import hashlib
import secrets
import time
from enum import IntEnum

PROTOCOL_VERSION = 1
MAGIC            = 0x4D455348  # "MESH"

class PacketType(IntEnum):
    DATA      = 0x01
    ACK       = 0x02
    CONTROL   = 0x03
    ERROR     = 0x04
    HANDSHAKE = 0x05
    MIGRATION = 0x06

class Priority(IntEnum):
    REALTIME = 0x00
    HIGH     = 0x01
    NORMAL   = 0x02
    BULK     = 0x03

FLAG_ENCRYPTED       = 0x01
FLAG_FORWARD_SECRECY = 0x02
FLAG_MIGRATION       = 0x04
FLAG_LAST_FRAGMENT   = 0x08

# ----------------------------
# Header Layout (64 Bytes)
#
# Offset  Size  Field
# 0       4     Magic
# 4       1     Version
# 5       1     PacketType
# 6       1     Priority
# 7       1     Flags
# 8       16    Source mesh-addr
# 24      16    Destination mesh-addr
# 40      8     Connection ID
# 48      2     Sequence Number 
# 50      2     ACK Number       
# 52      2     Payload Length   
# 54      1     Path ID          
# 55      1     Congestion Hint  
# + 8     Timestamp (unix)  → total 64 Bytes
# ----------------------------
HEADER_FORMAT = "!IBBBB16s16sQHHHBBQ" 
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)
AUTH_TAG_SIZE = 16

def build_packet(
    src:       str,
    dst:       str,
    payload:   bytes,
    ptype:     PacketType = PacketType.DATA,
    priority:  Priority   = Priority.NORMAL,
    conn_id:   int        = 0,
    seq:       int        = 0,
    ack:       int        = 0,  
    path_id:   int        = 0,
    cong_hint: int        = 0,
    flags:     int        = FLAG_ENCRYPTED,
) -> bytes:

    src_bytes = bytes.fromhex(src)[:16]
    dst_bytes = bytes.fromhex(dst)[:16]
    ts = time.time_ns()

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        PROTOCOL_VERSION,
        int(ptype),
        int(priority),
        flags,
        src_bytes,
        dst_bytes,
        conn_id,
        seq,
        ack,  
        len(payload),
        path_id,
        cong_hint,
        ts,
    )

    auth_tag = hashlib.sha256(header + payload).digest()[:AUTH_TAG_SIZE]
    return header + payload + auth_tag

def parse_packet(data: bytes) -> dict | None:
    if len(data) < HEADER_SIZE + AUTH_TAG_SIZE:
        return None

    try:
        (
            magic, version, ptype, priority, flags,
            src, dst,
            conn_id, seq, ack,
            payload_len, path_id, cong_hint, timestamp
        ) = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    except struct.error:
        return None

    if magic != MAGIC:
        return None

    payload  = data[HEADER_SIZE:HEADER_SIZE + payload_len]
    auth_tag = data[HEADER_SIZE + payload_len:HEADER_SIZE + payload_len + AUTH_TAG_SIZE]

    expected = hashlib.sha256(data[:HEADER_SIZE] + payload).digest()[:AUTH_TAG_SIZE]
    if not secrets.compare_digest(auth_tag, expected):
        return None

    return {
        "version":   version,
        "type":      PacketType(ptype),
        "priority":  Priority(priority),
        "flags":     flags,
        "src":       src.hex(),
        "dst":       dst.hex(),
        "conn_id":   conn_id,
        "seq":       seq,
        "ack":       ack, 
        "path_id":   path_id,
        "cong_hint": cong_hint,
        "timestamp": timestamp,
        "payload":   payload,
        "auth_ok":   True,
    }