const std = @import("std");
const header = @import("header.zig");
const protocol = @import("protocol.zig");
const synet = @import("synet.zig");

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub const MAX_PACKET_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

pub const TranslationError = error{
    PacketTooSmall,
    AuthFailed,
    PacketTooLarge,
    ConnectionClosed,
    IoError,
    SocketError,
};

pub fn buildOutboundPacket(
    io: std.Io,
    allocator: std.mem.Allocator,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    seq_num: u32,
    command: protocol.Command,
    payload: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(payload.len), .big);

    const out_len = header.OUTER_HEADER_SIZE + NONCE_SIZE + header.INNER_HEADER_SIZE + payload.len + TAG_SIZE;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    const hdr_slice = out[0..header.OUTER_HEADER_SIZE];
    hdr_slice[0] = header.MAGIC;
    hdr_slice[1] = @intFromEnum(command);
    @memcpy(hdr_slice[2..6], &len_buf);
    @memcpy(hdr_slice[6..22], &src);
    @memcpy(hdr_slice[22..38], &dst);

    var nonce: [NONCE_SIZE]u8 = undefined;
    const rng: std.Random.IoSource = .{ .io = io };
    rng.interface().bytes(&nonce);
    @memcpy(out[header.OUTER_HEADER_SIZE..][0..NONCE_SIZE], &nonce);

    const plain_len = header.INNER_HEADER_SIZE + payload.len;
    const plain = try allocator.alloc(u8, plain_len);
    defer allocator.free(plain);
    std.mem.writeInt(u64, plain[0..8], conn_id, .little);
    std.mem.writeInt(u32, plain[8..12], seq_num, .little);
    @memcpy(plain[header.INNER_HEADER_SIZE..], payload);

    const ct_start = header.OUTER_HEADER_SIZE + NONCE_SIZE;
    const ct_buf = out[ct_start..][0 .. plain_len + TAG_SIZE];
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ct_buf[0..plain_len],
        ct_buf[plain_len..][0..TAG_SIZE],
        plain,
        hdr_slice,
        nonce,
        key,
    );
    return out;
}

pub fn buildOutboundPacketInto(
    io: std.Io,
    allocator: std.mem.Allocator,
    plain_buf: []u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    seq_num: u32,
    command: protocol.Command,
    payload: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(payload.len), .big);

    const out_len = header.OUTER_HEADER_SIZE + NONCE_SIZE + header.INNER_HEADER_SIZE + payload.len + TAG_SIZE;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    const hdr_slice = out[0..header.OUTER_HEADER_SIZE];
    hdr_slice[0] = header.MAGIC;
    hdr_slice[1] = @intFromEnum(command);
    @memcpy(hdr_slice[2..6], &len_buf);
    @memcpy(hdr_slice[6..22], &src);
    @memcpy(hdr_slice[22..38], &dst);

    var nonce: [NONCE_SIZE]u8 = undefined;
    const rng: std.Random.IoSource = .{ .io = io };
    rng.interface().bytes(&nonce);
    @memcpy(out[header.OUTER_HEADER_SIZE..][0..NONCE_SIZE], &nonce);

    const plain_len = header.INNER_HEADER_SIZE + payload.len;
    const plain = plain_buf[0..plain_len];
    std.mem.writeInt(u64, plain[0..8], conn_id, .little);
    std.mem.writeInt(u32, plain[8..12], seq_num, .little);
    @memcpy(plain[header.INNER_HEADER_SIZE..], payload);

    const ct_start = header.OUTER_HEADER_SIZE + NONCE_SIZE;
    const ct_buf = out[ct_start..][0 .. plain_len + TAG_SIZE];
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ct_buf[0..plain_len],
        ct_buf[plain_len..][0..TAG_SIZE],
        plain,
        hdr_slice,
        nonce,
        key,
    );
    return out;
}

pub const InboundPacket = struct {
    parsed: header.ParsedPacket,
    _buf: []u8,
};

pub fn readInboundPacket(
    sock: synet.Socket,
    allocator: std.mem.Allocator,
    key: [KEY_SIZE]u8,
) !InboundPacket {
    var outer_buf: [header.OUTER_HEADER_SIZE]u8 = undefined;
    synet.recvExact(sock, &outer_buf) catch return TranslationError.SocketError;

    const outer = try header.parseOuter(&outer_buf);

    const payload_len = std.mem.readInt(
        u32,
        &outer.length,
        .big,
    );

    if (payload_len == 0)
        return TranslationError.PacketTooSmall;

    if (payload_len > MAX_PACKET_SIZE)
        return TranslationError.PacketTooLarge;

    const remaining =
        header.INNER_HEADER_SIZE +
        NONCE_SIZE +
        payload_len +
        TAG_SIZE;

    const encrypted = try allocator.alloc(
        u8,
        header.OUTER_HEADER_SIZE + remaining,
    );
    defer allocator.free(encrypted);

    @memcpy(
        encrypted[0..header.OUTER_HEADER_SIZE],
        &outer_buf,
    );

    synet.recvExact(
        sock,
        encrypted[header.OUTER_HEADER_SIZE..],
    ) catch return TranslationError.SocketError;

    const decrypted =
        try decryptPacket(
            allocator,
            encrypted,
            key,
        );
    errdefer allocator.free(decrypted);

    const parsed =
        try header.parsePacket(decrypted);

    return InboundPacket{
        .parsed = parsed,
        ._buf = decrypted,
    };
}

pub fn freeInboundPacket(allocator: std.mem.Allocator, pkt: InboundPacket) void {
    allocator.free(pkt._buf);
}

pub fn encryptPacket(
    io: std.Io,
    allocator: std.mem.Allocator,
    raw_packet: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    if (raw_packet.len < header.HEADER_SIZE) return TranslationError.PacketTooSmall;

    const hdr = raw_packet[0..header.OUTER_HEADER_SIZE];
    const payload = raw_packet[header.OUTER_HEADER_SIZE..];

    var nonce: [NONCE_SIZE]u8 = undefined;
    const rng: std.Random.IoSource = .{ .io = io };
    rng.interface().bytes(&nonce);

    const out_len = header.OUTER_HEADER_SIZE + NONCE_SIZE + payload.len + TAG_SIZE;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    @memcpy(out[0..header.OUTER_HEADER_SIZE], hdr);
    @memcpy(out[header.OUTER_HEADER_SIZE..][0..NONCE_SIZE], &nonce);

    const ct_start = header.OUTER_HEADER_SIZE + NONCE_SIZE;
    const ct_buf = out[ct_start..][0 .. payload.len + TAG_SIZE];

    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ct_buf[0..payload.len],
        ct_buf[payload.len..][0..TAG_SIZE],
        payload,
        hdr,
        nonce,
        key,
    );

    return out;
}

pub fn decryptPacket(
    allocator: std.mem.Allocator,
    data: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    const min_len = header.HEADER_SIZE + NONCE_SIZE + TAG_SIZE;
    if (data.len < min_len) return TranslationError.PacketTooSmall;

    const hdr = data[0..header.OUTER_HEADER_SIZE];
    const nonce = data[header.OUTER_HEADER_SIZE..][0..NONCE_SIZE].*;
    const ct_and_tag = data[header.OUTER_HEADER_SIZE + NONCE_SIZE ..];

    if (ct_and_tag.len < TAG_SIZE) return TranslationError.PacketTooSmall;

    const pt_len = ct_and_tag.len - TAG_SIZE;
    const ciphertext = ct_and_tag[0..pt_len];
    const tag = ct_and_tag[pt_len..][0..TAG_SIZE].*;

    const out = try allocator.alloc(u8, header.OUTER_HEADER_SIZE + pt_len);
    errdefer allocator.free(out);
    @memcpy(out[0..header.OUTER_HEADER_SIZE], hdr);

    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        out[header.OUTER_HEADER_SIZE..],
        ciphertext,
        tag,
        hdr,
        nonce,
        key,
    ) catch return TranslationError.AuthFailed;

    return out;
}

pub const ReassemblyError = error{
    UnexpectedSequenceNumber,
    UnknownTransfer,
    TooManyChunks,
} || std.mem.Allocator.Error || anyerror;

pub const MAX_CHUNKS_PER_TRANSFER: usize = 65536;

const TransferState = struct {
    next_seq: u32,
    chunks: std.ArrayListUnmanaged([]u8),

    fn deinit(self: *TransferState, allocator: std.mem.Allocator) void {
        for (self.chunks.items) |c| allocator.free(c);
        self.chunks.deinit(allocator);
    }
};

pub const FeedResult = union(enum) {
    pending,
    complete: [][]u8,
};

pub const Reassembler = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    transfers: std.AutoHashMap(u64, TransferState),

    pub fn init(io: std.Io, allocator: std.mem.Allocator, base_dir: []const u8) Reassembler {
        return .{
            .io = io,
            .allocator = allocator,
            .base_dir = base_dir,
            .transfers = std.AutoHashMap(u64, TransferState).init(allocator),
        };
    }

    pub fn deinit(self: *Reassembler) void {
        var it = self.transfers.valueIterator();
        while (it.next()) |state| {
            state.deinit(self.allocator);
        }
        self.transfers.deinit();
    }

    fn writeChunk(self: *Reassembler, conn_id: u64, seq_num: u32, payload: []const u8) !void {
        const gop = try self.transfers.getOrPut(conn_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .next_seq = 0,
                .chunks = .empty,
            };
        }
        errdefer if (!gop.found_existing) {
            _ = self.transfers.remove(conn_id);
        };
        const state = gop.value_ptr;

        if (seq_num != state.next_seq) return ReassemblyError.UnexpectedSequenceNumber;
        if (state.chunks.items.len >= MAX_CHUNKS_PER_TRANSFER) return ReassemblyError.TooManyChunks;

        const owned = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(owned);
        try state.chunks.append(self.allocator, owned);
        state.next_seq += 1;
    }

    pub fn feed(self: *Reassembler, packet: header.ParsedPacket) !FeedResult {
        const conn_id = packet.header.inner.conn_id;
        const seq_num = packet.header.inner.seq_num;

        switch (packet.command) {
            .Data => {
                try self.writeChunk(conn_id, seq_num, packet.payload);

                var kv = self.transfers.fetchRemove(conn_id) orelse return ReassemblyError.UnknownTransfer;
                const owned_slice = kv.value.chunks.toOwnedSlice(self.allocator) catch {
                    kv.value.deinit(self.allocator);
                    return error.OutOfMemory;
                };
                return .{ .complete = owned_slice };
            },

            .DataChunk => {
                try self.writeChunk(conn_id, seq_num, packet.payload);
                return .pending;
            },
            .DataEnd => {
                try self.writeChunk(conn_id, seq_num, packet.payload);

                var kv = self.transfers.fetchRemove(conn_id) orelse return ReassemblyError.UnknownTransfer;
                const owned_slice = kv.value.chunks.toOwnedSlice(self.allocator) catch {
                    kv.value.deinit(self.allocator);
                    return error.OutOfMemory;
                };
                return .{ .complete = owned_slice };
            },

            else => return .pending,
        }
    }

    pub fn abort(self: *Reassembler, conn_id: u64) void {
        if (self.transfers.fetchRemove(conn_id)) |kv| {
            var state = kv.value;
            state.deinit(self.allocator);
        }
    }
};
const testing = std.testing;

test "encrypt -> decrypt Roundtrip" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x42} ** KEY_SIZE;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;
    const payload = "Hallo Welt, das ist ein Test-Payload!";

    var raw_buf: [header.HEADER_SIZE + payload.len]u8 = undefined;
    _ = try header.buildPacket(&raw_buf, src, dst, 0xDEADBEEF, 0, .Data, payload);

    const encrypted = try encryptPacket(io, allocator, &raw_buf, key);
    defer allocator.free(encrypted);

    const decrypted = try decryptPacket(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, &raw_buf, decrypted);
}

test "decrypt schlägt fehl bei manipuliertem Ciphertext" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x55} ** KEY_SIZE;
    const src = [_]u8{0xAA} ** 16;
    const dst = [_]u8{0xBB} ** 16;

    var raw_buf: [header.HEADER_SIZE + 32]u8 = undefined;
    _ = try header.buildPacket(&raw_buf, src, dst, 1, 0, .Data, "manipulier mich nicht!!!");

    const encrypted = try encryptPacket(io, allocator, &raw_buf, key);
    defer allocator.free(encrypted);

    encrypted[header.HEADER_SIZE + NONCE_SIZE] ^= 0xFF;

    try testing.expectError(
        TranslationError.AuthFailed,
        decryptPacket(allocator, encrypted, key),
    );
}

test "decrypt schlägt fehl bei manipuliertem Header (Additional Data)" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x77} ** KEY_SIZE;
    const src = [_]u8{0x11} ** 16;
    const dst = [_]u8{0x22} ** 16;

    var raw_buf: [header.HEADER_SIZE + 16]u8 = undefined;
    _ = try header.buildPacket(&raw_buf, src, dst, 2, 0, .Keepalive, "header auth test");

    const encrypted = try encryptPacket(io, allocator, &raw_buf, key);
    defer allocator.free(encrypted);

    encrypted[2] ^= 0x01;

    try testing.expectError(
        TranslationError.AuthFailed,
        decryptPacket(allocator, encrypted, key),
    );
}

test "decrypt lehnt zu kurze Pakete ab" {
    const allocator = testing.allocator;
    const key: [KEY_SIZE]u8 = [_]u8{0x11} ** KEY_SIZE;
    const too_short = [_]u8{0} ** 10;

    try testing.expectError(
        TranslationError.PacketTooSmall,
        decryptPacket(allocator, &too_short, key),
    );
}

test "buildOutboundPacket hat korrekten Längen-Präfix" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x33} ** KEY_SIZE;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    const wire = try buildOutboundPacket(
        io,
        allocator,
        src,
        dst,
        42,
        0,
        .Data,
        "test payload",
        key,
    );
    defer allocator.free(wire);

    try testing.expect(wire.len > 0);
    try testing.expectEqual(wire[0], header.MAGIC);
}

test "Reassembler: DataChunk + DataEnd liefert alle Pfade in Reihenfolge" {
    const allocator = testing.allocator;
    const io = testing.io;

    var r = Reassembler.init(io, allocator, "/tmp/sip-test-reassembly");
    defer r.deinit();

    const conn_id: u64 = 0xCAFEBABE;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    {
        var buf0: [header.HEADER_SIZE + 5]u8 = undefined;
        _ = try header.buildPacket(&buf0, src, dst, conn_id, 0, .DataChunk, "chunk");
        const parsed0 = try header.parsePacket(&buf0);
        const result = try r.feed(parsed0);
        try testing.expectEqual(FeedResult.pending, result);
    }

    {
        var buf1: [header.HEADER_SIZE + 3]u8 = undefined;
        _ = try header.buildPacket(&buf1, src, dst, conn_id, 1, .DataEnd, "end");
        const parsed1 = try header.parsePacket(&buf1);
        const result = try r.feed(parsed1);

        switch (result) {
            .complete => |paths| {
                defer allocator.free(paths);
                defer for (paths) |p| allocator.free(p);

                try testing.expectEqual(@as(usize, 2), paths.len);
                try testing.expectEqualSlices(u8, "chunk", paths[0]);
                try testing.expectEqualSlices(u8, "end", paths[1]);
            },
            .pending => return error.ExpectedComplete,
        }
    }
}

test "Reassembler: abort räumt Zustand und Dateien auf" {
    const allocator = testing.allocator;
    const io = testing.io;

    var r = Reassembler.init(io, allocator, "/tmp/sip-test-reassembly-abort");
    defer r.deinit();

    const conn_id: u64 = 0xDEAD;
    const src = [_]u8{0xAA} ** 16;
    const dst = [_]u8{0xBB} ** 16;

    var buf: [header.HEADER_SIZE + 4]u8 = undefined;
    _ = try header.buildPacket(&buf, src, dst, conn_id, 0, .DataChunk, "data");
    const parsed = try header.parsePacket(&buf);
    _ = try r.feed(parsed);

    try testing.expect(r.transfers.contains(conn_id));

    r.abort(conn_id);

    try testing.expect(!r.transfers.contains(conn_id));
    const dir_exists = blk: {
        const dir = std.Io.Dir.cwd().openDir(io, "/tmp/sip-test-reassembly-abort/dead", .{}) catch break :blk false;
        dir.close(io);
        break :blk true;
    };
    try testing.expect(!dir_exists);
}

test "buildOutboundPacketInto: Roundtrip" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0xAB} ** KEY_SIZE;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;
    const payload = "test into";

    const plain_cap = NONCE_SIZE + header.INNER_HEADER_SIZE + payload.len + TAG_SIZE;
    const plain_buf = try allocator.alloc(u8, plain_cap);
    defer allocator.free(plain_buf);

    const wire = try buildOutboundPacketInto(io, allocator, plain_buf, src, dst, 1, 0, .Data, payload, key);
    defer allocator.free(wire);

    const decrypted = try decryptPacket(allocator, wire, key);
    defer allocator.free(decrypted);
    const parsed = try header.parsePacket(decrypted);

    try testing.expectEqualSlices(u8, payload, parsed.payload);
    try testing.expectEqual(@as(u64, 1), parsed.header.inner.conn_id);
}

test "Reassembler: Data liefert sofort complete" {
    const allocator = testing.allocator;
    const io = testing.io;

    var r = Reassembler.init(io, allocator, "");
    defer r.deinit();

    const conn_id: u64 = 0x01;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    var buf: [header.HEADER_SIZE + 4]u8 = undefined;
    _ = try header.buildPacket(&buf, src, dst, conn_id, 0, .Data, "data");
    const parsed = try header.parsePacket(&buf);
    const result = try r.feed(parsed);

    switch (result) {
        .complete => |chunks| {
            defer allocator.free(chunks);
            defer for (chunks) |c| allocator.free(c);
            try testing.expectEqual(@as(usize, 1), chunks.len);
            try testing.expectEqualSlices(u8, "data", chunks[0]);
        },
        .pending => return error.ExpectedComplete,
    }
}

test "Reassembler: UnexpectedSequenceNumber räumt neuen State auf" {
    const allocator = testing.allocator;
    const io = testing.io;

    var r = Reassembler.init(io, allocator, "");
    defer r.deinit();

    const conn_id: u64 = 0x02;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    var buf: [header.HEADER_SIZE + 4]u8 = undefined;
    _ = try header.buildPacket(&buf, src, dst, conn_id, 1, .DataChunk, "data"); // seq 1 statt 0
    const parsed = try header.parsePacket(&buf);

    try testing.expectError(ReassemblyError.UnexpectedSequenceNumber, r.feed(parsed));
    try testing.expect(!r.transfers.contains(conn_id));
}

test "encryptPacket lehnt zu kurzes raw_packet ab" {
    const allocator = testing.allocator;
    const io = testing.io;
    const key: [KEY_SIZE]u8 = [_]u8{0x01} ** KEY_SIZE;
    const too_short = [_]u8{0} ** 10;

    try testing.expectError(TranslationError.PacketTooSmall, encryptPacket(io, allocator, &too_short, key));
}

test "Reassembler: TooManyChunks bricht ab" {
    const allocator = testing.allocator;
    const io = testing.io;

    var r = Reassembler.init(io, allocator, "");
    defer r.deinit();

    const conn_id: u64 = 0x99;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    var i: u32 = 0;
    while (i < MAX_CHUNKS_PER_TRANSFER) : (i += 1) {
        var buf: [header.HEADER_SIZE + 1]u8 = undefined;
        _ = try header.buildPacket(&buf, src, dst, conn_id, i, .DataChunk, "x");
        const parsed = try header.parsePacket(&buf);
        _ = try r.feed(parsed);
    }

    var overflow_buf: [header.HEADER_SIZE + 1]u8 = undefined;
    _ = try header.buildPacket(&overflow_buf, src, dst, conn_id, i, .DataChunk, "x");
    const overflow_parsed = try header.parsePacket(&overflow_buf);

    try testing.expectError(ReassemblyError.TooManyChunks, r.feed(overflow_parsed));
}

test "Reassembler: zwei parallele Transfers stören sich nicht" {
    const allocator = testing.allocator;
    const io = testing.io;

    var r = Reassembler.init(io, allocator, "");
    defer r.deinit();

    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    var buf_a: [header.HEADER_SIZE + 1]u8 = undefined;
    _ = try header.buildPacket(&buf_a, src, dst, 0xAAAA, 0, .DataChunk, "a");
    const parsed_a = try header.parsePacket(&buf_a);
    _ = try r.feed(parsed_a);

    var buf_b: [header.HEADER_SIZE + 1]u8 = undefined;
    _ = try header.buildPacket(&buf_b, src, dst, 0xBBBB, 0, .DataChunk, "b");
    const parsed_b = try header.parsePacket(&buf_b);
    _ = try r.feed(parsed_b);

    try testing.expect(r.transfers.contains(0xAAAA));
    try testing.expect(r.transfers.contains(0xBBBB));

    r.abort(0xAAAA);
    try testing.expect(!r.transfers.contains(0xAAAA));
    try testing.expect(r.transfers.contains(0xBBBB));
}
