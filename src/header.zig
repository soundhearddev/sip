const std = @import("std");

pub const MAGIC: u8 = 0x4D;

pub const PacketType = enum(u8) {
    data = 0x01,
    ack = 0x02,
    control = 0x03,
    err = 0x04,
    handshake = 0x05,
    migration = 0x06,
};

pub const HEADER_SIZE: usize = 42;

// Offset  Size  Field
//
// 0       1     Magic
// 1       1     PacketType
// 2       16    src mesh-addr
// 18      16    dst mesh-addr
// 34      8     Connection ID

//TODO implemntierung von protocol.zig in header format

pub const Header = struct {
    magic: u8,
    packet_type: u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
};

pub const ParsedPacket = struct {
    header: Header,
    payload: []const u8,
};

fn writeHeader(buf: []u8, h: Header) void {
    buf[0] = h.magic;
    buf[1] = h.packet_type;

    @memcpy(buf[2..18], &h.src);
    @memcpy(buf[18..34], &h.dst);

    std.mem.writeInt(u64, buf[34..42], h.conn_id, .little);
}

fn readHeader(buf: []const u8) Header {
    var h: Header = undefined;

    h.magic = buf[0];
    h.packet_type = buf[1];

    @memcpy(&h.src, buf[2..18]);
    @memcpy(&h.dst, buf[18..34]);

    h.conn_id = std.mem.readInt(u64, buf[34..42], .little);

    return h;
}

pub fn buildPacket(
    buf: []u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    ptype: PacketType,
    payload: []const u8,
) ![]u8 {
    if (buf.len < HEADER_SIZE + payload.len) return error.BufferTooSmall;

    const header = Header{
        .magic = MAGIC,
        .packet_type = @intFromEnum(ptype),
        .src = src,
        .dst = dst,
        .conn_id = conn_id,
    };

    writeHeader(buf[0..HEADER_SIZE], header);
    @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);

    return buf[0 .. HEADER_SIZE + payload.len];
}

pub fn parsePacket(data: []const u8) !ParsedPacket {
    if (data.len < HEADER_SIZE) return error.PacketTooSmall;

    const header = readHeader(data[0..HEADER_SIZE]);

    if (header.magic != MAGIC) return error.InvalidMagic;

    return ParsedPacket{
        .header = header,
        .payload = data[HEADER_SIZE..],
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = std.heap.page_allocator;

    const cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, "../dump/linux.svg", .{ .mode = .read_only });
    defer file.close(io);

    const file_size = (try file.stat(io)).size;
    const bytes = try allocator.alloc(u8, file_size);
    defer allocator.free(bytes);

    var fr = file.reader(io, bytes);
    try fr.interface.fill(file_size);

    const src = [_]u8{0x0b} ++ [_]u8{0x82} ++ [_]u8{0} ** 14;
    const dst = [_]u8{0xa3} ++ [_]u8{0xf9} ++ [_]u8{0} ** 14;

    const total = HEADER_SIZE + bytes.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);

    const pkt = try buildPacket(buf, src, dst, 12345678, .data, bytes);

    std.debug.print("HEADER HEX:\n", .{});
    for (pkt[0..HEADER_SIZE], 0..) |b, i| {
        std.debug.print("{d:0>3} ", .{b});
        if ((i + 1) % 8 == 0) std.debug.print("\n", .{});
    }
    std.debug.print("\nPaket gebaut: {d} Bytes\n", .{pkt.len});

    const parsed = try parsePacket(pkt);
    std.debug.print("Payload: {d} Byte\n", .{parsed.payload.len});
}
