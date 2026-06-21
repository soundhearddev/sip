// Deprecated!!!!

const std = @import("std");
const session = @import("session.zig");
const trust = @import("trust.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const BOOTSTRAP_PORT: u16 = 9871;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();

    const argv = try init.minimal.args.toSlice(allocator);
    const host = if (argv.len > 1) argv[1] else "::1";

    std.debug.print("[Bootstrap] Ziel: [{s}]:{d}\n", .{ host, BOOTSTRAP_PORT });

    const own_ed = Ed25519.KeyPair.generate(io);
    const own_pub = own_ed.public_key.toBytes();
    const own_mesh = session.peerMeshAddr(own_pub);

    std.debug.print("[Bootstrap] mesh-addr : {x}\n", .{own_mesh});
    std.debug.print("[Bootstrap] ed_pub    : {x}...\n\n", .{own_pub[0..8]});

    std.debug.print("[Bootstrap] Verbinde...\n", .{});
    const addr = try std.Io.net.IpAddress.parse(host, BOOTSTRAP_PORT);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    std.debug.print("[Bootstrap] Verbunden\n", .{});

    const name = "client-test.mesh";

    var w_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &w_buf);

    std.debug.print("[Bootstrap] Sende ed_pub ({d}B)...\n", .{own_pub.len});
    try writer.interface.writeAll(&own_pub);

    std.debug.print("[Bootstrap] Sende mesh_addr ({d}B)...\n", .{own_mesh.len});
    try writer.interface.writeAll(&own_mesh);

    std.debug.print("[Bootstrap] Sende name '{s}' ({d}B)...\n", .{ name, name.len });
    try writer.interface.writeByte(@intCast(name.len));
    try writer.interface.writeAll(name);

    std.debug.print("[Bootstrap] Sende has_invite=0\n", .{});
    try writer.interface.writeByte(0);
    try writer.interface.flush();

    var r_buf: [512]u8 = undefined;
    var reader = stream.reader(io, &r_buf);

    try writer.interface.flush();

    const chalp = try reader.interface.take(32);
    var challenge: [32]u8 = undefined;
    @memcpy(&challenge, chalp[0..32]);
    std.debug.print("[Bootstrap] Challenge empfangen\n", .{});

    const sig = try session.signChallenge(own_ed, challenge);
    try writer.interface.writeAll(&sig);
    try writer.interface.flush();
    std.debug.print("[Bootstrap] Signatur gesendet\n", .{});

    const status = try reader.interface.take(4);
    std.debug.print("[Bootstrap] Status bytes: {d}\n", .{status.len});
    std.debug.print("[Bootstrap] Server Status: '{s}'\n", .{status});

    if (!std.mem.eql(u8, status, "OK  ")) {
        std.debug.print("[Bootstrap] Abgelehnt\n", .{});
        return;
    }

    std.debug.print("[Bootstrap] Lese Server-Info...\n", .{});

    const srv_pub_slice = try reader.interface.take(32);
    var srv_pub: [32]u8 = undefined;
    @memcpy(&srv_pub, srv_pub_slice[0..32]);

    const srv_mesh_slice = try reader.interface.take(32);
    var srv_mesh: [32]u8 = undefined;
    @memcpy(&srv_mesh, srv_mesh_slice[0..32]);

    const srv_name_len = (try reader.interface.take(1))[0];
    std.debug.print("[Bootstrap] srv_name_len={d}\n", .{srv_name_len});
    const srv_name = try reader.interface.take(srv_name_len);

    std.debug.print("[Bootstrap] Server ed_pub    : {x}...\n", .{srv_pub[0..8]});
    std.debug.print("[Bootstrap] Server mesh_addr : {x}...\n", .{srv_mesh[0..8]});
    std.debug.print("[Bootstrap] Server name      : {s}\n", .{srv_name[0..srv_name_len]});

    try writer.interface.writeByte(1);
    try writer.interface.flush();

    std.debug.print("\n[✓] Bootstrap abgeschlossen\n", .{});
}
