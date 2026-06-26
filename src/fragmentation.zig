const std = @import("std");
const header = @import("header.zig");
const protocol = @import("protocol.zig");
const translation = @import("translation.zig");

// Fragmentierung kommt nur zum Einsatz, wenn eine Payload das Limit für ein
// einzelnes Paket überschreitet (translation.MAX_PACKET_SIZE). Für alles
// darunter wird ganz normal translation.buildOutboundPacket mit
// command = .Data verwendet - kein Chunking nötig.
//
// fragmentation.zig baut nur die fertigen, verschlüsselten Wire-Pakete
// (DataChunk für alle bis auf den letzten, DataEnd für den letzten).
// Das tatsächliche Senden über den Socket bleibt Aufgabe des Aufrufers.

pub const FragmentationError = error{
    TooManyChunks,
    BufferTooSmall,
} || std.mem.Allocator.Error || translation.TranslationError;

// Etwas kleiner als translation.MAX_PACKET_SIZE wählen, um Spielraum für
// zukünftige Overheads zu lassen (z.B. falls der Header nochmal wächst).
pub const CHUNK_SIZE: usize = translation.MAX_PACKET_SIZE - (1024 * 1024); // 15 MiB

pub const MAX_CHUNKS: usize = std.math.maxInt(u32);

pub const WirePacketList = struct {
    items: [][]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: WirePacketList) void {
        for (self.items) |pkt| self.allocator.free(pkt);
        self.allocator.free(self.items);
    }
};

/// Baut die fertigen, verschlüsselten Wire-Pakete für eine (potenziell große)
/// Payload. Payloads <= translation.MAX_PACKET_SIZE werden als ein einzelnes
/// .Data-Paket gebaut. Größere Payloads werden in CHUNK_SIZE-Stücke
/// aufgeteilt: alle bis auf den letzten Chunk als .DataChunk, der letzte als
/// .DataEnd - jeweils mit derselben conn_id und aufsteigender seq_num (0-basiert).
///
/// Der Aufrufer ist für das Senden der zurückgegebenen Pakete (in Reihenfolge!)
/// sowie für das spätere Freigeben (WirePacketList.deinit) verantwortlich.
pub fn fragmentPayload(
    io: std.Io,
    allocator: std.mem.Allocator,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    payload: []const u8,
    key: [translation.KEY_SIZE]u8,
) FragmentationError!WirePacketList {
    if (payload.len <= translation.MAX_PACKET_SIZE) {
        const wire = try translation.buildOutboundPacket(
            io,
            allocator,
            src,
            dst,
            conn_id,
            0,
            .Data,
            payload,
            key,
        );
        errdefer allocator.free(wire);

        const items = try allocator.alloc([]u8, 1);
        items[0] = wire;

        return WirePacketList{ .items = items, .allocator = allocator };
    }

    const total_chunks = (payload.len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    if (total_chunks > MAX_CHUNKS) return FragmentationError.TooManyChunks;

    const items = try allocator.alloc([]u8, total_chunks);
    var built: usize = 0;
    errdefer {
        for (items[0..built]) |pkt| allocator.free(pkt);
        allocator.free(items);
    }

    for (0..total_chunks) |i| {
        const start = i * CHUNK_SIZE;
        const end = @min(start + CHUNK_SIZE, payload.len);
        const chunk = payload[start..end];

        const is_last = (i == total_chunks - 1);
        const command: protocol.Command = if (is_last) .DataEnd else .DataChunk;
        const seq_num: u32 = @intCast(i);

        const wire = try translation.buildOutboundPacket(
            io,
            allocator,
            src,
            dst,
            conn_id,
            seq_num,
            command,
            chunk,
            key,
        );

        items[i] = wire;
        built += 1;
    }

    return WirePacketList{ .items = items, .allocator = allocator };
}

const testing = std.testing;

test "fragmentPayload: kleine Payload erzeugt ein einzelnes .Data Paket" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [translation.KEY_SIZE]u8 = [_]u8{0x11} ** translation.KEY_SIZE;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    const list = try fragmentPayload(io, allocator, src, dst, 1, "kleine payload", key);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.items.len);

    const decrypted = try translation.decryptPacket(allocator, list.items[0], key);
    defer allocator.free(decrypted);
    const parsed = try header.parsePacket(decrypted);

    try testing.expectEqual(protocol.Command.Data, parsed.command);
    try testing.expectEqualSlices(u8, "kleine payload", parsed.payload);
}

test "fragmentPayload: große Payload wird in DataChunk/DataEnd aufgeteilt" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [translation.KEY_SIZE]u8 = [_]u8{0x22} ** translation.KEY_SIZE;
    const src = [_]u8{0x03} ** 16;
    const dst = [_]u8{0x04} ** 16;

    const big_len = translation.MAX_PACKET_SIZE + 100;
    const big_payload = try allocator.alloc(u8, big_len);
    defer allocator.free(big_payload);
    for (big_payload, 0..) |*b, idx| b.* = @truncate(idx);

    const list = try fragmentPayload(io, allocator, src, dst, 42, big_payload, key);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 2), list.items.len);

    var reassembled: std.ArrayListUnmanaged(u8) = .empty;
    defer reassembled.deinit(allocator);

    for (list.items, 0..) |wire, idx| {
        const decrypted = try translation.decryptPacket(allocator, wire, key);
        defer allocator.free(decrypted);
        const parsed = try header.parsePacket(decrypted);

        try testing.expectEqual(@as(u64, 42), parsed.header.inner.conn_id);
        try testing.expectEqual(@as(u32, @intCast(idx)), parsed.header.inner.seq_num);

        if (idx == list.items.len - 1) {
            try testing.expectEqual(protocol.Command.DataEnd, parsed.command);
        } else {
            try testing.expectEqual(protocol.Command.DataChunk, parsed.command);
        }

        try reassembled.appendSlice(allocator, parsed.payload);
    }

    try testing.expectEqualSlices(u8, big_payload, reassembled.items);
}
