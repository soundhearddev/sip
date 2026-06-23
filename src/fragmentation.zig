// DEPRECATED
// villeicht in der zukunft wieder nutzbar aber vorerst nicht,
// da zurzeit nur mit tcp gearbeitet wird und dies dafür nicht gebraucht wird

const std = @import("std");
const header = @import("header");

pub const CHUNK_SIZE: usize = 1200;

pub const FLAG_LAST: u8 = 0x08;

pub const MAX_TOTAL_CHUNKS: usize = std.math.maxInt(u16);

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

pub fn fragmentData(
    allocator: std.mem.Allocator,
    data: []const u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
) !FragmentList {
    const total_chunks = (data.len + CHUNK_SIZE - 1) / CHUNK_SIZE;

    if (total_chunks > MAX_TOTAL_CHUNKS) return error.MessageTooLarge;

    const fragments = try allocator.alloc(Fragment, total_chunks);
    errdefer allocator.free(fragments);

    for (0..total_chunks) |seq| {
        const start = seq * CHUNK_SIZE;
        const end = @min(start + CHUNK_SIZE, data.len);
        const chunk = data[start..end];

        const is_last = (seq == total_chunks - 1);
        const flags: u8 = if (is_last) FLAG_LAST else 0x00;

        const buf = try allocator.alloc(u8, header.HEADER_SIZE + chunk.len);
        errdefer allocator.free(buf);

        // deprecated header layout!!!!! MUSS FIXEN IN ZUKUNFT
        const pkt = try header.buildPacket(
            buf,
            src,
            dst,
            conn_id,
            .data,
            chunk,
            @intCast(total_chunks),
        );

        const encoded_conn_id: u64 =
            (conn_id & 0x00000000FFFFFFFF) |
            (@as(u64, @intCast(seq)) << 32) |
            (@as(u64, flags) << 56);

        std.mem.writeInt(u64, buf[34..42], encoded_conn_id, .little);

        _ = pkt;

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
