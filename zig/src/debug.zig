const std = @import("std");
const process = std.process;

const address = @import("address.zig");
const bootstrap = @import("bootstrap.zig");
const header = @import("header.zig");
const server = @import("server.zig");
const session = @import("session.zig");
const sip = @import("SIP.zig");
const trust = @import("trust.zig");

const Module = struct {
    name: []const u8,
    run: *const fn (process.Init) anyerror!void,
};

const modules: []const Module = &.{
    .{ .name = "address", .run = address.main },
    .{ .name = "bootstrap", .run = bootstrap.main },
    .{ .name = "header", .run = header.main },
    .{ .name = "server", .run = server.main },
    .{ .name = "session", .run = session.main },
    .{ .name = "SIP", .run = sip.main },
    .{ .name = "trust", .run = trust.main },
};

pub fn main(init: process.Init) !void {
    const io = std.Io.Threaded.global_single_threaded.io();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

    var stdin_buf: [64]u8 = undefined;
    var stdin_r = std.Io.File.stdin().reader(io, &stdin_buf);
    const stdin = &stdin_r.interface;

    try stdout.writeAll("\n=== SIP Debug Runner ===\n\n");
    for (modules, 0..) |mod, i| {
        try stdout.print("  [{d}] {s}\n", .{ i + 1, mod.name });
    }
    try stdout.writeAll("  [0] Exit\n\nAuswahl: ");
    try stdout.flush();

    const line = stdin.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return,
        else => return err,
    };
    const trimmed = std.mem.trim(u8, line, " \t\r");

    const choice = std.fmt.parseInt(usize, trimmed, 10) catch {
        try stdout.print("Ungültige Eingabe: '{s}'\n", .{trimmed});
        try stdout.flush();
        return;
    };

    if (choice == 0) {
        try stdout.writeAll("Bye!\n");
        try stdout.flush();
        return;
    }
    if (choice > modules.len) {
        try stdout.print("Ungültige Auswahl: {d}\n", .{choice});
        try stdout.flush();
        return;
    }

    const mod = modules[choice - 1];
    try stdout.print("\n--- Starte {s}.main() ---\n\n", .{mod.name});
    try stdout.flush();
    try mod.run(init);
}
