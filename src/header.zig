const std = @import("std");

pub const MAGIC: u8 = 0xA9;

const protocol = @import("protocol");
const sip = @import("sip");
pub const Command = protocol.Command;


pub const OUTER_HEADER_SIZE: usize = 34; 
pub const INNER_HEADER_SIZE: usize = 8;  
pub const HEADER_SIZE:       usize = OUTER_HEADER_SIZE + INNER_HEADER_SIZE; // 42

// Offset  Size  Field
// 0       1     Magic
// 1       1     PacketType
// 2       16    src mesh-addr
// 18      16    dst mesh-addr
// --- inner (verschlüsselbar) ---
// 34      8     Connection ID

pub const OuterHeader = struct {
    magic:   u8,
    command: u8,
    src:     [16]u8,
    dst:     [16]u8,
};

pub const InnerHeader = struct {
    conn_id: u64,
};

pub const Header = struct {
    outer: OuterHeader,
    inner: InnerHeader,
};

pub const ParsedPacket = struct {
    header:  Header,
    command: protocol.Command,  
    payload: []const u8,
};

// --- write/read Outer ---
fn writeOuter(buf: []u8, o: OuterHeader) void {
    buf[0] = o.magic;
    buf[1] = o.command;
    @memcpy(buf[2..18], &o.src);
    @memcpy(buf[18..34], &o.dst);
}

fn readOuter(buf: []const u8) OuterHeader {
    var o: OuterHeader = undefined;
    o.magic   = buf[0];
    o.command = buf[1];
    @memcpy(&o.src, buf[2..18]);
    @memcpy(&o.dst, buf[18..34]);
    return o;
}

// --- write/read Inner ---
fn writeInner(buf: []u8, i: InnerHeader) void {
    std.mem.writeInt(u64, buf[0..8], i.conn_id, .little);
}

fn readInner(buf: []const u8) InnerHeader {
    return .{ .conn_id = std.mem.readInt(u64, buf[0..8], .little) };
}

// --- write/read complete ---
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

// --- public API ---
pub fn buildPacket(
    buf:     []u8,
    src:     [16]u8,
    dst:     [16]u8,
    conn_id: u64,
    ptype:   protocol.Command,
    payload: []const u8,
) ![]u8 {
    if (buf.len < HEADER_SIZE + payload.len) return error.BufferTooSmall;
    const header = Header{
        .outer = .{
            .magic       = MAGIC,
            .command = @intFromEnum(ptype),
            .src         = src,
            .dst         = dst,
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
    if (buf.len < OUTER_HEADER_SIZE) return error.BufferTooSmall;
    writeOuter(buf[0..OUTER_HEADER_SIZE], .{
        .magic   = MAGIC,
        .command = @intFromEnum(protocol.Command.discovery),
        .src     = src,
        .dst     = dst,
    });
    return buf[0..OUTER_HEADER_SIZE];
}

pub fn parsePacket(data: []const u8) !ParsedPacket {
    if (data.len < HEADER_SIZE) return error.PacketTooSmall;
    const header = readHeader(data[0..HEADER_SIZE]);
    if (header.outer.magic != MAGIC) return error.InvalidMagic;
    return ParsedPacket{
        .header  = header,
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







// TEST BEFEHL!!!!
pub fn randomMeshAddr(io: std.Io) [16]u8 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();
    var addr: [16]u8 = undefined;
    rand.bytes(&addr);
    return addr;
}
pub fn randomConnId(io: std.Io) u64 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();
    return rand.int(u64);
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

    const src = randomMeshAddr(init.io);
    const dst = randomMeshAddr(init.io);

    const conn_id = randomConnId(init.io);

    const total = HEADER_SIZE + bytes.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);

    const pkt = try buildPacket(buf, src, dst, conn_id, .discovery, bytes);

    std.debug.print("HEADER HEX:\n", .{});
    for (pkt[0..HEADER_SIZE], 0..) |b, i| {
        std.debug.print("{d:0>3} ", .{b});
        if ((i + 1) % 8 == 0) std.debug.print("\n", .{});
    }
    std.debug.print("\nPaket gebaut: {d} Bytes\n", .{pkt.len});

    const parsed = try parsePacket(pkt);
    std.debug.print("Payload: {d} Byte\n", .{parsed.payload.len});
    std.debug.print("Command: {}\n", .{parsed.command}); 
}
