const std = @import("std");
const header = @import("header.zig");

pub const CHUNK_SIZE: usize = 1200;

// Flag für letztes Fragment
pub const FLAG_LAST: u8 = 0x08;

pub const Fragment = struct {
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Fragment) void {
        self.allocator.free(self.data);
    }
};

pub const FragmentList = struct {
    items: []Fragment,
    allocator: std.mem.Allocator,

    pub fn deinit(self: FragmentList) void {
        for (self.items) |frag| {
            frag.deinit();
        }
        self.allocator.free(self.items);
    }
};

// ----------------------------
// Daten in SIP-Fragmente aufteilen
// Gibt eine Liste von fertigen Paketen zurück (Header + Payload)
// ----------------------------
pub fn fragmentData(
    allocator: std.mem.Allocator,
    data: []const u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
) !FragmentList {
    const total_chunks = (data.len + CHUNK_SIZE - 1) / CHUNK_SIZE;

    const fragments = try allocator.alloc(Fragment, total_chunks);
    errdefer allocator.free(fragments);

    for (0..total_chunks) |seq| {
        const start = seq * CHUNK_SIZE;
        const end = @min(start + CHUNK_SIZE, data.len);
        const chunk = data[start..end];

        const is_last = (seq == total_chunks - 1);
        const flags: u8 = if (is_last) FLAG_LAST else 0x00;

        // Puffer für Header + Chunk
        const buf = try allocator.alloc(u8, header.HEADER_SIZE + chunk.len);
        errdefer allocator.free(buf);

        const pkt = try header.buildPacket(
            buf,
            src,
            dst,
            conn_id,
            .data,
            chunk,
        );

        // flags & seq manuell in den Header schreiben
        // Im header.zig Layout: flags liegen nicht explizit drin — wir nutzen
        // die letzten freien Bytes des Payloads NICHT, stattdessen bauen wir
        // seq und flags direkt in conn_id-Bereich (Upper 32 Bit von conn_id)
        // Encoding: conn_id = base_conn_id | (seq << 32) | (flags << 56)
        const encoded_conn_id: u64 =
            (conn_id & 0x00000000FFFFFFFF) |
            (@as(u64, @intCast(seq)) << 32) |
            (@as(u64, flags) << 56);

        std.mem.writeInt(u64, buf[34..42], encoded_conn_id, .little);

        _ = pkt; // pkt zeigt auf buf, buf wird in Fragment gespeichert

        fragments[seq] = Fragment{
            .data = buf,
            .allocator = allocator,
        };
    }

    return FragmentList{
        .items = fragments,
        .allocator = allocator,
    };
}

// ----------------------------
// conn_id dekodieren → base id, seq, flags
// ----------------------------
pub const DecodedConnId = struct {
    base_id: u32,
    seq: u32,
    flags: u8,
};

pub fn decodeConnId(conn_id: u64) DecodedConnId {
    return DecodedConnId{
        .base_id = @truncate(conn_id & 0x00000000FFFFFFFF),
        .seq = @truncate((conn_id >> 32) & 0x00FFFFFF),
        .flags = @truncate((conn_id >> 56) & 0xFF),
    };
}

pub fn isLastFragment(conn_id: u64) bool {
    const decoded = decodeConnId(conn_id);
    return (decoded.flags & FLAG_LAST) != 0;
}
