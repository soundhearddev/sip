const std = @import("std");

extern fn get_windows_time_c() u32;

fn get_windows_time() u32 {
    return get_windows_time_c();
}

/// Prüft, ob das Programm mit Administratorrechten läuft
pub fn isRoot() void {
    // Unter Windows prüft man das am besten, indem man versucht, einen privilegierten System-Call zu machen,
    // oder man verlässt sich darauf, dass nachfolgende netsh/powershell Befehle fehlschlagen.
    // Für diesen Port lassen wir die Prüfung visuell über die Ausführung entscheiden.
}

/// Windows hat kein standardmäßiges "Dummy"-Interface wie Linux.
/// Wir nutzen hier ein Loopback-Interface oder ein bestehendes Interface.
pub fn ensureDummyIface(gpa: std.mem.Allocator, io: std.Io, name: []const u8) ![]u8 {
    _ = io;
    // Da man unter Windows nicht mal eben ein "dummy" Interface ohne Treiberinstallation erstellen kann,
    // geben wir einfach den Namen zurück. Tipp: Nutze unter Windows z.B. "Loopback Pseudo-Interface 1"
    return gpa.dupe(u8, name);
}

/// Ermittelt den Namen des Standard-Netzwerkadapters über die PowerShell
pub fn getDefaultIface(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    // Holt das Interface mit der aktivsten IPv4-Standardroute
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Get-NetAdapter).InterfaceName" },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    const trimmed = std.mem.trim(u8, result.stdout, "\n\r\t ");
    if (trimmed.len == 0) return error.NoDefaultInterface;
    return gpa.dupe(u8, trimmed);
}

/// Ermittelt das globale IPv6-Präfix des Interfaces
pub fn getPrefix(gpa: std.mem.Allocator, io: std.Io, iface: []const u8) ![]u8 {
    const cmd = try std.fmt.allocPrint(gpa, "(Get-NetIPAddress -InterfaceAlias '{s}' -AddressFamily IPv6 | Where-Object {{ $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -notlike '::1' }}).IPAddress", .{iface});
    defer gpa.free(cmd);

    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "powershell", "-Command", cmd },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const addr = std.mem.trim(u8, line, " \r\t");
        if (addr.len == 0) continue;

        // Extrahiere die ersten 4 Blöcke (64-Bit Präfix)
        var colon_count: usize = 0;
        var prefix_end: usize = 0;
        for (addr, 0..) |c, i| {
            if (c == ':') {
                colon_count += 1;
                if (colon_count == 4) {
                    prefix_end = i + 1;
                    break;
                }
            }
        }
        if (prefix_end == 0) continue;
        return gpa.dupe(u8, addr[0..prefix_end]);
    }

    return error.NoPrefixFound;
}

/// Generiert eine zufällige IPv6-Adresse basierend auf dem Präfix
pub fn generateAddress(gpa: std.mem.Allocator, prefix: []const u8) ![]u8 {
    const seed: u64 = @as(u64, get_windows_time());
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();
    const a = rng.int(u16);
    const b = rng.int(u16);
    const c = rng.int(u16);
    const d = rng.int(u16);
    return std.fmt.allocPrint(gpa, "{s}{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{ prefix, a, b, c, d });
}

/// Fügt die IPv6-Adresse dem Windows-Interface hinzu (inklusive TTL)
pub fn addAddress(gpa: std.mem.Allocator, io: std.Io, iface: []const u8, address: []const u8, ttl: ?u64) !bool {
    var cmd: []u8 = undefined;
    if (ttl) |t| {
        // Windows nutzt "ValidLifetime" (in Form von Timespan-Strings oder Sekunden) via PowerShell
        cmd = try std.fmt.allocPrint(gpa, "New-NetIPAddress -InterfaceAlias '{s}' -IPAddress '{s}' -PrefixLength 64 -ValidLifetime ([TimeSpan]::FromSeconds({d})) -PreferredLifetime ([TimeSpan]::FromSeconds({d})) -Confirm:$false", .{ iface, address, t, t });
    } else {
        cmd = try std.fmt.allocPrint(gpa, "New-NetIPAddress -InterfaceAlias '{s}' -IPAddress '{s}' -PrefixLength 64 -Confirm:$false", .{ iface, address });
    }
    defer gpa.free(cmd);

    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "powershell", "-Command", cmd },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    return result.term.exited == 0;
}

/// Listet die aktuell zugewiesenen IPv6-Adressen des Interfaces auf
pub fn currentAddresses(gpa: std.mem.Allocator, io: std.Io, iface: []const u8) !std.StringHashMap(void) {
    var set = std.StringHashMap(void).init(gpa);

    const cmd = try std.fmt.allocPrint(gpa, "(Get-NetIPAddress -InterfaceAlias '{s}' -AddressFamily IPv6).IPAddress", .{iface});
    defer gpa.free(cmd);

    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "powershell", "-Command", cmd },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const addr = std.mem.trim(u8, line, " \r\t");
        if (addr.len == 0) continue;

        const allocated_addr = try gpa.dupe(u8, addr);
        try set.put(allocated_addr, {});
    }
    return set;
}
