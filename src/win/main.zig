const std = @import("std");
const utils = @import("utils.zig");

// Für den Testlauf auf true stellen, falls du kein echtes Interface nutzen willst.
// BEACHTE: Wenn false, versucht das Programm dein echtes Standard-Interface zu nutzen!
const DEBUG = true;
const ANZAHL_IPS: usize = 2;
const LEBENSDAUER_SEKUNDEN: ?u64 = 30; // 30 Sekunden Test-TTL

fn buildAddress(
    gpa: std.mem.Allocator,
    io: std.Io,
    count: usize,
    prefix: []const u8,
    before: *std.StringHashMap(void),
    iface: []const u8,
    ttl: ?u64,
) !std.ArrayListUnmanaged([]const u8) {
    var created: std.ArrayListUnmanaged([]const u8) = .empty;

    for (0..count) |_| {
        var new_addr = try utils.generateAddress(gpa, prefix);
        while (before.contains(new_addr)) {
            gpa.free(new_addr);
            new_addr = try utils.generateAddress(gpa, prefix);
        }

        // Versuche, die Adresse via PowerShell/System hinzuzufügen
        const success = try utils.addAddress(gpa, io, iface, new_addr, ttl);
        if (success) {
            try created.append(gpa, new_addr);
            try before.put(new_addr, {});
            if (ttl) |t| {
                std.debug.print("[✓] {s} erfolgreich hinzugefuegt! (TTL: {d}s)\n", .{ new_addr, t });
            } else {
                std.debug.print("[✓] {s} erfolgreich hinzugefuegt! (Permanent)\n", .{new_addr});
            }
        } else {
            std.debug.print("[✗] Fehler beim Hinzufuegen von {s}. (Admin-Rechte vorhanden?)\n", .{new_addr});
            gpa.free(new_addr);
        }
    }
    return created;
}

pub fn main() !void {
    // 1. Allocator initialisieren
    var gpa_impl = std.heap.DebugAllocator(.{}){};
    const gpa = gpa_impl.allocator();
    defer _ = gpa_impl.deinit();

    // 2. Das I/O-Subsystem mit leeren Optionen initialisieren
    var threaded_io = std.Io.Threaded.init(gpa, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    std.debug.print("==================================================\n", .{});
    std.debug.print("--- WINDOWS IPV6-ZUWEISUNGSTEST (VERBOSE MODE) ---\n", .{});
    std.debug.print("==================================================\n\n", .{});

    // --- VERBOSE: ipconfig ausführen und anzeigen ---
    std.debug.print("[DEBUG] Starte 'ipconfig /all', um den aktuellen Netzwerkstatus zu prüfen...\n", .{});
    const ipconfig_res = std.process.run(gpa, io, .{
        .argv = &.{ "ipconfig", "/all" },
    }) catch |err| {
        std.debug.print("[✗ DEBUG] Fehler beim Ausführen von ipconfig: {}\n", .{err});
        return err;
    };
    defer gpa.free(ipconfig_res.stdout);
    defer gpa.free(ipconfig_res.stderr);

    std.debug.print("--- START IPCONFIG AUSGABE ---\n{s}\n--- ENDE IPCONFIG AUSGABE ---\n\n", .{ipconfig_res.stdout});
    // ------------------------------------------------

    var interface: []u8 = undefined;
    if (DEBUG) {
        std.debug.print("[MODUS] DEBUG-Modus aktiv. Nutze Loopback-Adapter.\n", .{});
        interface = try utils.ensureDummyIface(gpa, io, "Loopback Pseudo-Interface 1");
    } else {
        std.debug.print("[MODUS] LIVE-Modus aktiv. Ermittle Standard-Interface...\n", .{});
        interface = utils.getDefaultIface(gpa, io) catch |err| {
            std.debug.print("[✗] Konnte Standard-Interface nicht finden: {}\n", .{err});
            return;
        };
    }
    std.debug.print("[i] Ziel-Interface gewählt: '{s}'\n", .{interface});
    defer gpa.free(interface);

    // --- VERBOSE: Präfix-Ermittlung ---
    std.debug.print("[DEBUG] Rufe utils.getPrefix auf für '{s}'...\n", .{interface});
    const prefix = utils.getPrefix(gpa, io, interface) catch |err| {
        std.debug.print("[✗ DEBUG] Fehler bei getPrefix: {}\n", .{err});
        return err;
    };
    std.debug.print("[i] Gefundenes IPv6-Präfix: {s}\n", .{prefix});
    defer gpa.free(prefix);

    // --- VERBOSE: Aktuelle Adressen auslesen ---
    std.debug.print("[DEBUG] Rufe utils.currentAddresses auf für '{s}'...\n", .{interface});
    var already_assigned = try utils.currentAddresses(gpa, io, interface);
    defer {
        var it = already_assigned.keyIterator();
        while (it.next()) |key| gpa.free(key.*);
        already_assigned.deinit();
    }
    std.debug.print("[i] Bereits zugewiesene Adressen auf diesem Interface: {d}\n", .{already_assigned.count()});

    // --- VERBOSE: Adresse generieren ---
    std.debug.print("[DEBUG] Generiere neue zufällige Adresse...\n", .{});
    const new_addr = try utils.generateAddress(gpa, prefix);
    std.debug.print("[i] Generierte Test-Adresse: {s}\n", .{new_addr});
    defer gpa.free(new_addr);

    // --- VERBOSE: Adresse hinzufügen ---
    std.debug.print("[DEBUG] Versuche Adresse '{s}' auf '{s}' mit TTL 60s hinzuzufügen...\n", .{ new_addr, interface });
    const success = try utils.addAddress(gpa, io, interface, new_addr, 60);
    if (success) {
        std.debug.print("[✓] Adresse erfolgreich via PowerShell gesetzt!\n", .{});
    } else {
        std.debug.print("[✗] PowerShell hat den Befehl abgelehnt (Rechte vorhanden?).\n", .{});
    }

    std.debug.print("\n[DEBUG] Programm beendet. Bereinige Speicher...\n", .{});
}
