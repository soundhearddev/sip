const std = @import("std");

const sip = @import("sip");
const header = @import("header");
const synet = @import("synet");
const translation = @import("translation");
const keyexchange = @import("keyexchange");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print("App starting...\n", .{});

    // Beispiel: prüfe ob Module erreichbar sind
    try stdout.print("Modules loaded: sip, header, synet, translation, keyexchange\n", .{});

    // optional: hier dein echter entry code
    // z.B. server start / client logic / dispatcher
}
