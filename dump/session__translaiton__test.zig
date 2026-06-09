const std = @import("std");
const frag = @import("fragmentation.zig");
const trans = @import("translation.zig");
const header = @import("header.zig");

// Dummy Session Key (32 Bytes) — normalerweise von session.zig
const TEST_KEY: [trans.KEY_SIZE]u8 = [_]u8{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
};

// Dummy mesh-Adressen (16 Bytes)
const SRC: [16]u8 = [_]u8{ 0x0b, 0x82 } ++ [_]u8{0x00} ** 14;
const DST: [16]u8 = [_]u8{ 0xa3, 0xf9 } ++ [_]u8{0x00} ** 14;

const CONN_ID: u64 = 0xDEADBEEF;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ------------------------------------------------------------
    // Daten laden — versuche externe Datei, sonst Dummy-Bytes
    // ------------------------------------------------------------
    const data = loadFile(io, allocator, "../dump/linux.svg") catch |err| blk: {
        if (err == error.FileNotFound) {
            std.debug.print("[*] test.jpg nicht gefunden — nutze Dummy-Daten ({d} Bytes)\n", .{frag.CHUNK_SIZE * 3 + 500});
            const dummy = try allocator.alloc(u8, frag.CHUNK_SIZE * 3 + 500);
            for (dummy, 0..) |*b, i| b.* = @truncate(i);
            break :blk dummy;
        }
        return err;
    };
    defer allocator.free(data);

    std.debug.print("\n=== SIP Translation Test ===\n", .{});
    std.debug.print("[+] Datengröße: {d} Bytes\n", .{data.len});
    std.debug.print("[+] Erwartete Fragmente: {d}\n\n", .{
        (data.len + frag.CHUNK_SIZE - 1) / frag.CHUNK_SIZE,
    });

    // ------------------------------------------------------------
    // OUTBOUND: fragmentieren + verschlüsseln
    // ------------------------------------------------------------
    std.debug.print("--- OUTBOUND ---\n", .{});

    const packets = try trans.translateOutbound(
        io,
        allocator,
        data,
        SRC,
        DST,
        CONN_ID,
        TEST_KEY,
    );
    defer {
        for (packets) |pkt| allocator.free(pkt);
        allocator.free(packets);
    }

    std.debug.print("[+] {d} Pakete verschlüsselt\n", .{packets.len});
    for (packets, 0..) |pkt, i| {
        const raw_header = pkt[0..header.HEADER_SIZE];
        const conn_id_raw = std.mem.readInt(u64, raw_header[34..42], .little);
        const decoded = frag.decodeConnId(conn_id_raw);
        const is_last = (decoded.flags & frag.FLAG_LAST) != 0;

        std.debug.print("  Paket #{d}: {d} Bytes | seq={d} | last={s}\n", .{
            i,
            pkt.len,
            decoded.seq,
            if (is_last) "YES" else "no",
        });
    }

    // ------------------------------------------------------------
    // INBOUND: entschlüsseln + reassemblieren
    // ------------------------------------------------------------
    std.debug.print("\n--- INBOUND ---\n", .{});

    var rbuf = trans.ReassemblyBuffer.init(allocator);
    defer rbuf.deinit();

    var reassembled: ?[]u8 = null;

    for (packets, 0..) |pkt, i| {
        const result = try trans.translateInbound(allocator, pkt, TEST_KEY, &rbuf);
        if (result) |r| {
            std.debug.print("[+] Reassembly komplett nach Paket #{d}!\n", .{i});
            reassembled = r;
            break;
        } else {
            std.debug.print("  [<] Paket #{d} gepuffert\n", .{i});
        }
    }

    // ------------------------------------------------------------
    // Vergleich: Original == Reassembled?
    // ------------------------------------------------------------
    std.debug.print("\n--- VERGLEICH ---\n", .{});

    if (reassembled) |r| {
        defer allocator.free(r);

        if (std.mem.eql(u8, data, r)) {
            std.debug.print("[OK] Daten stimmen überein! ({d} Bytes)\n", .{r.len});
        } else {
            std.debug.print("[FEHLER] Daten weichen ab!\n", .{});
            std.debug.print("    Original:     {d} Bytes\n", .{data.len});
            std.debug.print("    Reassembled:  {d} Bytes\n", .{r.len});
        }
    } else {
        std.debug.print("[!] Kein vollständiges Reassembly — Fragmente fehlen?\n", .{});
    }
}

fn loadFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);

    const stat = try file.stat(io);
    const buf = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buf);

    // file als eigenen Reader-Buffer nutzen (wie in header.zig)
    var reader = file.reader(io, buf);
    try reader.interface.fill(stat.size);

    std.debug.print("[+] Datei geladen: {s} ({d} Bytes)\n", .{ path, stat.size });
    return buf;
}
