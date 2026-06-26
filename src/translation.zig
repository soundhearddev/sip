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
    const raw_len = header.HEADER_SIZE + payload.len;
    const raw = try allocator.alloc(u8, raw_len);
    defer allocator.free(raw);

    _ = try header.buildPacket(
        raw,
        src,
        dst,
        conn_id,
        seq_num,
        command,
        payload,
    );

    return try encryptPacket(io, allocator, raw, key);
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

// ============================================================
// Reassembly: nimmt eingehende DataChunk/DataEnd-Pakete entgegen,
// schreibt deren Payload als Datei auf Disk und meldet, sobald
// ein Transfer (identifiziert über conn_id) vollständig ist.
//
// translation.zig entscheidet bewusst NICHT, was mit den fertigen
// Chunk-Dateien passiert (kein Zusammenfügen, kein finaler Pfad) -
// das bleibt Aufgabe des Aufrufers (z.B. ein sip-daemon).
// ============================================================

pub const ReassemblyError = error{
    UnexpectedSequenceNumber,
    UnknownTransfer,
    TooManyChunks,
} || std.mem.Allocator.Error || anyerror;

pub const MAX_CHUNKS_PER_TRANSFER: usize = 65536;

const TransferState = struct {
    next_seq: u32,
    chunk_paths: std.ArrayList([]u8),

    fn deinit(self: *TransferState, allocator: std.mem.Allocator) void {
        for (self.chunk_paths.items) |p| allocator.free(p);
        self.chunk_paths.deinit(allocator);
    }
};

pub const FeedResult = union(enum) {
    /// Paket war kein Chunk-Paket (z.B. .Data) oder Transfer ist noch nicht fertig.
    pending,
    /// Transfer ist komplett. Enthält die Pfade aller Chunk-Dateien dieses
    /// Transfers, in aufsteigender seq_num-Reihenfolge. Der Aufrufer ist für
    /// das spätere Löschen dieser Dateien verantwortlich.
    /// Speicher (die Slice selbst sowie die einzelnen Pfad-Strings) gehört dem
    /// Aufrufer und muss von ihm freigegeben werden.
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

    fn transferDir(self: *Reassembler, buf: []u8, conn_id: u64) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{x}", .{ self.base_dir, conn_id });
    }

    fn chunkPath(self: *Reassembler, buf: []u8, conn_id: u64, seq_num: u32) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{x}/{d}.chunk", .{ self.base_dir, conn_id, seq_num });
    }

    fn writeChunk(self: *Reassembler, conn_id: u64, seq_num: u32, payload: []const u8) !void {
        var dir_buf: [300]u8 = undefined;
        const dir = try self.transferDir(&dir_buf, conn_id);
        std.Io.Dir.cwd().createDirPath(self.io, dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var path_buf: [300]u8 = undefined;
        const path = try self.chunkPath(&path_buf, conn_id, seq_num);

        const f = try std.Io.Dir.cwd().createFile(self.io, path, .{});
        defer f.close(self.io);
        var iobuf: [4096]u8 = undefined;
        var w = f.writer(self.io, &iobuf);
        try w.interface.writeAll(payload);
        try w.flush();

        const gop = try self.transfers.getOrPut(conn_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .next_seq = 0,
                .chunk_paths = .empty,
            };
        }
        const state = gop.value_ptr;

        if (seq_num != state.next_seq) return ReassemblyError.UnexpectedSequenceNumber;
        if (state.chunk_paths.items.len >= MAX_CHUNKS_PER_TRANSFER) return ReassemblyError.TooManyChunks;

        const owned_path = try self.allocator.dupe(u8, path);
        try state.chunk_paths.append(self.allocator, owned_path);
        state.next_seq += 1;
    }

    /// Nimmt ein bereits entschlüsseltes & geparstes Paket entgegen.
    /// - command == .DataChunk: Chunk wird gespeichert, .pending wird zurückgegeben.
    /// - command == .DataEnd: letzter Chunk wird gespeichert, Transfer ist fertig,
    ///   .complete mit allen Chunk-Pfaden (Reihenfolge!) wird zurückgegeben. Der
    ///   Reassembler vergisst danach diesen Transfer (conn_id kann wiederverwendet
    ///   werden).
    /// - jedes andere Command: .pending, Reassembler tut nichts (kein Chunking).
    pub fn feed(self: *Reassembler, packet: header.ParsedPacket) !FeedResult {
        const conn_id = packet.header.inner.conn_id;
        const seq_num = packet.header.inner.seq_num;

        switch (packet.command) {
            // Ein normales .Data Paket verhält sich wie ein Single-Chunk-Transfer
            .Data => {
                try self.writeChunk(conn_id, seq_num, packet.payload);

                var state = self.transfers.get(conn_id) orelse return ReassemblyError.UnknownTransfer;
                _ = self.transfers.remove(conn_id);

                const owned_slice = try state.chunk_paths.toOwnedSlice(self.allocator);
                return .{ .complete = owned_slice };
            },
            .DataChunk => {
                try self.writeChunk(conn_id, seq_num, packet.payload);
                return .pending;
            },
            .DataEnd => {
                try self.writeChunk(conn_id, seq_num, packet.payload);

                var state = self.transfers.get(conn_id) orelse return ReassemblyError.UnknownTransfer;
                _ = self.transfers.remove(conn_id);

                const owned_slice = try state.chunk_paths.toOwnedSlice(self.allocator);
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

        var dir_buf: [300]u8 = undefined;
        const dir = self.transferDir(&dir_buf, conn_id) catch return;
        std.Io.Dir.cwd().deleteTree(self.io, dir) catch {};
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
                try testing.expect(std.mem.endsWith(u8, paths[0], "0.chunk"));
                try testing.expect(std.mem.endsWith(u8, paths[1], "1.chunk"));
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
