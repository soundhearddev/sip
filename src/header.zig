const std = @import("std");

pub const MAGIC: u8 = 0xA9;

const protocol = @import("protocol.zig");
const sip = @import("sip");
pub const Command = protocol.Command;

pub const LENGTH_SIZE: usize = 4;

pub const OUTER_HEADER_SIZE: usize = 38;
pub const INNER_HEADER_SIZE: usize = 8;
pub const HEADER_SIZE: usize = OUTER_HEADER_SIZE + INNER_HEADER_SIZE; // 46

// Offset  Size  Field
// 0       1     Magic
// 1       1     PacketType
// 2       4     Length
// 6       16    src mesh-addr
// 22      16    dst mesh-addr

// --- inner (verschlüsselbar) ---

// 38      8     Connection ID

// Ein ganz normales Struct – wir regeln das exakte Layout manuell über die Funktionen!
pub const OuterHeader = struct {
    magic: u8,
    command: u8,
    length: [4]u8,
    src: [16]u8,
    dst: [16]u8,
};

pub const InnerHeader = struct {
    conn_id: u64,
};

pub const Header = struct {
    outer: OuterHeader,
    inner: InnerHeader,
};

pub const ParsedPacket = struct {
    header: Header,
    command: protocol.Command,
    payload: []const u8,
};

// VORHERIGER FEHLER FIX: Hier wird exakt Byte für Byte ohne jegliches Compiler-Padding geschrieben
fn writeOuter(buf: []u8, o: OuterHeader) void {
    buf[0] = o.magic;
    buf[1] = o.command;
    @memcpy(buf[2..6], &o.length);
    @memcpy(buf[6..22], &o.src);
    @memcpy(buf[22..38], &o.dst);
}

// VORHERIGER FEHLER FIX: Hier wird exakt Byte für Byte ausgelesen. Kein Shift möglich.
fn readOuter(buf: []const u8) OuterHeader {
    var o: OuterHeader = undefined;

    o.magic = buf[0];
    o.command = buf[1];

    @memcpy(&o.length, buf[2..6]);
    @memcpy(&o.src, buf[6..22]);
    @memcpy(&o.dst, buf[22..38]);

    return o;
}

pub const DiscoveryOuterHeader = struct {
    magic: u8,
    command: u8,
    src: [16]u8,
    dst: [16]u8,
};

fn writeDiscoveryOuter(buf: []u8, o: DiscoveryOuterHeader) void {
    buf[0] = o.magic;
    buf[1] = o.command;

    @memcpy(buf[2..18], &o.src);
    @memcpy(buf[18..34], &o.dst);
}

fn writeInner(buf: []u8, i: InnerHeader) void {
    std.mem.writeInt(
        u64,
        buf[0..8],
        i.conn_id,
        .little,
    );
}

fn readInner(buf: []const u8) InnerHeader {
    return .{ .conn_id = std.mem.readInt(u64, buf[0..8], .little) };
}

fn writeHeader(buf: []u8, h: Header) void {
    writeOuter(buf[0..OUTER_HEADER_SIZE], h.outer);
    writeInner(buf[OUTER_HEADER_SIZE..HEADER_SIZE], h.inner);
}

fn readHeader(buf: []const u8) Header {
    return .{
        .outer = readOuter(buf[0..OUTER_HEADER_SIZE]),
        .inner = readInner(buf[OUTER_HEADER_SIZE..HEADER_SIZE]),
    };
}

pub fn buildPacket(
    buf: []u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    ptype: protocol.Command,
    payload: []const u8,
) ![]u8 {
    if (buf.len < HEADER_SIZE + payload.len) return error.BufferTooSmall;
    var len_buf: [4]u8 = undefined;

    std.mem.writeInt(u32, &len_buf, @intCast(payload.len), .big);

    const header = Header{
        .outer = .{
            .magic = MAGIC,
            .command = @intFromEnum(ptype),
            .length = len_buf,
            .src = src,
            .dst = dst,
        },
        .inner = .{ .conn_id = conn_id },
    };
    writeHeader(buf[0..HEADER_SIZE], header);
    @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);
    return buf[0 .. HEADER_SIZE + payload.len];
}

pub fn buildDiscoveryPacket(
    buf: []u8,
    src: [16]u8,
    dst: [16]u8,
) ![]u8 {
    if (buf.len < 34) return error.BufferTooSmall;

    writeDiscoveryOuter(buf[0..34], .{
        .magic = MAGIC,
        .command = @intFromEnum(protocol.Command.discovery),
        .src = src,
        .dst = dst,
    });

    return buf[0..34];
}

pub fn parsePacket(data: []const u8) !ParsedPacket {
    if (data.len < HEADER_SIZE) return error.PacketTooSmall;
    const header = readHeader(data[0..HEADER_SIZE]);
    if (header.outer.magic != MAGIC) return error.InvalidMagic;
    return ParsedPacket{
        .header = header,
        .command = protocol.parseCommand(header.outer.command),
        .payload = data[HEADER_SIZE..],
    };
}

pub fn parseOuter(data: []const u8) !OuterHeader {
    if (data.len < OUTER_HEADER_SIZE) return error.PacketTooSmall;
    const outer = readOuter(data[0..OUTER_HEADER_SIZE]);
    if (outer.magic != MAGIC) return error.InvalidMagic;
    return outer;
}
const testing = std.testing;

test "buildPacket schreibt MAGIC und Command korrekt" {
    const allocator = testing.allocator;
    _ = allocator;

    var buf: [HEADER_SIZE + 4]u8 = undefined;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    const pkt = try buildPacket(&buf, src, dst, 99, .Data, "test");

    try testing.expectEqual(MAGIC, pkt[0]);
    try testing.expectEqual(@intFromEnum(protocol.Command.Data), pkt[1]);
}

test "buildPacket schreibt src und dst korrekt" {
    var buf: [HEADER_SIZE + 0]u8 = undefined;
    const src = [_]u8{0xAA} ** 16;
    const dst = [_]u8{0xBB} ** 16;

    const pkt = try buildPacket(&buf, src, dst, 0, .Data, "");

    try testing.expectEqualSlices(u8, &src, pkt[6..22]);
    try testing.expectEqualSlices(u8, &dst, pkt[22..38]);
}

test "buildPacket schreibt conn_id korrekt (little-endian)" {
    var buf: [HEADER_SIZE]u8 = undefined;
    const src = [_]u8{0x00} ** 16;
    const dst = [_]u8{0x00} ** 16;

    const pkt = try buildPacket(&buf, src, dst, 0xDEADBEEFCAFEBABE, .Data, "");

    const conn_id = std.mem.readInt(u64, pkt[38..46], .little);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFEBABE), conn_id);
}

test "buildPacket schreibt payload korrekt" {
    const payload = "hallo welt";
    var buf: [HEADER_SIZE + payload.len]u8 = undefined;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    const pkt = try buildPacket(&buf, src, dst, 1, .Data, payload);

    try testing.expectEqualSlices(u8, payload, pkt[HEADER_SIZE..]);
}

test "parsePacket Roundtrip" {
    const payload = "roundtrip test";
    var buf: [HEADER_SIZE + payload.len]u8 = undefined;
    const src = [_]u8{0x11} ** 16;
    const dst = [_]u8{0x22} ** 16;

    const pkt = try buildPacket(&buf, src, dst, 0xCAFE, .Data, payload);
    const parsed = try parsePacket(pkt);

    try testing.expectEqual(MAGIC, parsed.header.outer.magic);
    try testing.expectEqualSlices(u8, &src, &parsed.header.outer.src);
    try testing.expectEqualSlices(u8, &dst, &parsed.header.outer.dst);
    try testing.expectEqual(@as(u64, 0xCAFE), parsed.header.inner.conn_id);
    try testing.expectEqualSlices(u8, payload, parsed.payload);
}

test "parsePacket lehnt falsches Magic ab" {
    var buf: [HEADER_SIZE]u8 = undefined;
    const src = [_]u8{0x00} ** 16;
    const dst = [_]u8{0x00} ** 16;

    _ = try buildPacket(&buf, src, dst, 0, .Data, "");
    buf[0] = 0x00; // Magic korrumpieren

    try testing.expectError(error.InvalidMagic, parsePacket(&buf));
}

test "parsePacket lehnt zu kurze Daten ab" {
    const too_short = [_]u8{0} ** 10;
    try testing.expectError(error.PacketTooSmall, parsePacket(&too_short));
}

test "buildPacket lehnt zu kleinen Buffer ab" {
    var buf: [HEADER_SIZE - 1]u8 = undefined;
    const src = [_]u8{0x00} ** 16;
    const dst = [_]u8{0x00} ** 16;

    try testing.expectError(error.BufferTooSmall, buildPacket(&buf, src, dst, 0, .Data, ""));
}

test "parseOuter liest src/dst korrekt" {
    var buf: [HEADER_SIZE]u8 = undefined;
    const src = [_]u8{0x33} ** 16;
    const dst = [_]u8{0x44} ** 16;

    _ = try buildPacket(&buf, src, dst, 0, .Data, "");
    const outer = try parseOuter(&buf);

    try testing.expectEqualSlices(u8, &src, &outer.src);
    try testing.expectEqualSlices(u8, &dst, &outer.dst);
}
