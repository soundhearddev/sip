const std = @import("std");
const io = std.io;
const posix = std.posix;

const MenuItem = struct {
    name: []const u8,
    file_name: []const u8,
};

pub fn main() !void {
    // 1. Deine zu testenden Dateien
    const items = [_]MenuItem{
        .{ .name = "Fragmentation Test", .file_name = "fragmentation.zig" },
        .{ .name = "Header Parser Test", .file_name = "header.zig" },
        .{ .name = "Net IP Validation Test", .file_name = "netIP.zig" },
        .{ .name = "Session Management Test", .file_name = "session.zig" },
        .{ .name = "Translation Engine Test", .file_name = "translation.zig" },
    };

    // Moderner DebugAllocator (Ersatz für den alten GeneralPurposeAllocator)
    var dbg_allocator = std.heap.DebugAllocator.init;
    defer dbg_allocator.deinit();
    const allocator = dbg_allocator.allocator();

    const stdout = io.getStdOut().writer();
    const stdin = io.getStdIn();

    // Raw-Mode für das Terminal über das moderne `std.posix` einstellen
    // (Verhindert, dass man nach jedem Tastendruck Enter drücken muss)
    const stdin_handle = stdin.handle;
    const orig_termios = try posix.tcgetattr(stdin_handle);
    var raw = orig_termios;
    raw.lflag &= ~@as(posix.tc.lflag_t, posix.tc.ICANON | posix.tc.ECHO);
    try posix.tcsetattr(stdin_handle, .NOW, raw);

    // Am Ende des Programms das Terminal wieder in den Normalzustand versetzen
    defer posix.tcsetattr(stdin_handle, .NOW, orig_termios) catch {};

    var selected_index: usize = 0;
    var running = true;

    // Cursor verstecken für die Optik
    try stdout.print("\x1B[?25l", .{});
    // Cursor beim Beenden wieder einblenden
    defer stdout.print("\x1B[?25h", .{}) catch {};

    while (running) {
        // Bildschirm leeren und Cursor nach oben links (Home)
        try stdout.print("\x1B[2J\x1B[H", .{});

        // Header
        try stdout.print("=== ZIG TEST RUNNER TUI (v0.16.0) ===\n", .{});
        try stdout.print("Steuerung: Pfeiltasten [Hoch/Runter] | Auswählen: [Enter] | Beenden: [q]\n", .{});
        try stdout.print("-------------------------------------------------------------------\n\n", .{});

        // Menü rendern
        for (items, 0..) |item, i| {
            if (i == selected_index) {
                // Blau markierte Auswahl mit einem schicken Pfeil
                try stdout.print("  \x1B[1;34m➔ [ ] {s}\x1B[0m ({s})\n", .{ item.name, item.file_name });
            } else {
                try stdout.print("     [ ] {s} ({s})\n", .{ item.name, item.file_name });
            }
        }

        // Tastatureingabe abfangen
        var buf: [3]u8 = undefined;
        const n = try stdin.read(&buf);

        if (n == 1) {
            if (buf[0] == 'q') {
                running = false;
            } else if (buf[0] == 10) { // Enter-Taste gedrückt
                try executeZigFile(items[selected_index], allocator);
                running = false; // Beendet die TUI nach dem Testlauf
            }
        } else if (n == 3 and buf[0] == 27 and buf[1] == 91) { // ANSI Escape-Sequenzen für Pfeiltasten
            if (buf[2] == 65) { // Pfeil HOCH
                if (selected_index > 0) {
                    selected_index -= 1;
                } else {
                    selected_index = items.len - 1; // Wrap-around nach unten
                }
            } else if (buf[2] == 66) { // Pfeil RUNTER
                if (selected_index < items.len - 1) {
                    selected_index += 1;
                } else {
                    selected_index = 0; // Wrap-around nach oben
                }
            }
        }
    }
}

// Funktion zur späteren Ausführung der selektierten Datei
fn executeZigFile(item: MenuItem, allocator: std.mem.Allocator) !void {
    const stdout = io.getStdOut().writer();

    try stdout.print("\x1B[2J\x1B[H", .{});
    try stdout.print("Starte Kompilation & Test für: \x1B[1;32m{s}\x1B[0m...\n", .{item.file_name});
    try stdout.print("==================================================\n\n", .{});

    // Hier kannst du in Zukunft std.process.Child nutzen, um "zig run" auszuführen:
    // var child = std.process.Child.init(&[_][]const u8{ "zig", "run", item.file_name }, allocator);
    // _ = try child.spawnAndWait();
    _ = allocator; // Temporär ungenutzt, um Compiler-Warnungen zu vermeiden

    try stdout.print("\n==================================================\n", .{});
    try stdout.print("Testlauf beendet. Drücke eine beliebige Taste...", .{});

    var buf: [1]u8 = undefined;
    _ = try io.getStdIn().read(&buf);
}
