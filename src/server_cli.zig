const std = @import("std");
const synet = @import("synet.zig");
const keyexchange = @import("keyexchange.zig");
const header = @import("header.zig");
const translation = @import("translation.zig");

const DEFAULT_PORT: u16 = 9443;

const Mode = enum { server, client };

const Args = struct {
    mode: Mode,
    host: []const u8,
    port: u16,
    message: []const u8,
    use_v6: bool,
    output_path: ?[]const u8,
};

fn getLang() []const u8 {
    const lang = std.c.getenv("LANG");
    if (lang) |l| {
        return std.mem.span(l);
    }
    return "en";
}

fn printUsage() void {
    const lang = getLang();

    if (std.mem.startsWith(u8, lang, "de")) {
        std.debug.print(
            \\Verwendung:
            \\  server_cli --listen [--port PORT]
            \\  server_cli --connect [--host HOST] [--port PORT] --message TEXT
            \\
            \\Optionen:
            \\  --listen          Server-Modus: wartet auf eine eingehende Verbindung
            \\  --connect         Client-Modus: verbindet sich zu einem Server
            \\  --host HOST       Ziel-Host im Client-Modus (Standard: 127.0.0.1)
            \\  --port PORT       Port (Standard: {d})
            \\  --message TEXT    SIP-Payload (roher Text); mit @PFAD wird stattdessen
            \\                    der Inhalt der Datei unter PFAD als Payload gesendet        
            \\  --v6              Server: auf IPv6 (::) statt IPv4 (0.0.0.0) lauschen
            \\  --output PATH     Server: empfangenen Payload zusätzlich in Datei PATH schreiben
            \\  --help            Diese Hilfe anzeigen
        , .{DEFAULT_PORT});
    } else {
        std.debug.print(
            \\Usage:
            \\  server_cli --listen [--port PORT]
            \\  server_cli --connect [--host HOST] [--port PORT] --message TEXT
            \\
            \\Options:
            \\  --listen          Server mode: waits for an incoming connection
            \\  --connect         Client mode: connects to a server
            \\  --host HOST      Target host in client mode (default: 127.0.0.1)
            \\  --port PORT      Port (default: {d})
            \\  --message TEXT   SIP payload (raw text); if prefixed with @PATH, the
            \\                    content of the file at PATH is sent instead
            \\  --v6              Server: listen on IPv6 (::) instead of IPv4 (0.0.0.0)
            \\  --output PATH    Server: additionally write received payload to file PATH
            \\  --help           Show this help message
        , .{DEFAULT_PORT});
    }
}

fn parseArgs(allocator: std.mem.Allocator, raw_args: []const []const u8) !Args {
    var mode: ?Mode = null;
    var host: []const u8 = "127.0.0.1";
    var port: u16 = DEFAULT_PORT;
    var message: []const u8 = "";
    var use_v6: bool = false;
    var output_path: ?[]const u8 = null;

    var i: usize = 1;
    while (i < raw_args.len) {
        const arg = raw_args[i];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--listen")) {
            mode = .server;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--connect")) {
            mode = .client;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--host")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            host = raw_args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            port = std.fmt.parseInt(u16, raw_args[i + 1], 10) catch return error.InvalidPort;
            i += 2;
        } else if (std.mem.eql(u8, arg, "--message")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            message = raw_args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--v6")) {
            use_v6 = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--output")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            output_path = raw_args[i + 1];
            i += 2;
        } else {
            std.debug.print("Unbekanntes Argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }

    const resolved_mode = mode orelse return error.MissingMode;
    if (resolved_mode == .client and message.len == 0) {
        return error.MissingMessage;
    }

    _ = allocator;

    return Args{ .mode = resolved_mode, .host = host, .port = port, .message = message, .use_v6 = use_v6, .output_path = output_path };
}

fn parseIpv4(text: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var idx: usize = 0;
    while (it.next()) |part| {
        if (idx >= 4) return error.InvalidIpv4Address;
        result[idx] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4Address;
        idx += 1;
    }
    if (idx != 4) return error.InvalidIpv4Address;
    return result;
}

fn parseIpv6(text: []const u8) ![16]u8 {
    var result: [16]u8 = [_]u8{0} ** 16;

    // Position von "::" finden (Kompression), falls vorhanden.
    const double_colon = std.mem.indexOf(u8, text, "::");

    if (double_colon) |dc_pos| {
        const left = text[0..dc_pos];
        const right = text[dc_pos + 2 ..];

        var left_groups: [8]u16 = undefined;
        var left_count: usize = 0;
        if (left.len > 0) {
            var it = std.mem.splitScalar(u8, left, ':');
            while (it.next()) |part| {
                if (left_count >= 8) return error.InvalidIpv6Address;
                left_groups[left_count] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6Address;
                left_count += 1;
            }
        }

        var right_groups: [8]u16 = undefined;
        var right_count: usize = 0;
        if (right.len > 0) {
            var it = std.mem.splitScalar(u8, right, ':');
            while (it.next()) |part| {
                if (right_count >= 8) return error.InvalidIpv6Address;
                right_groups[right_count] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6Address;
                right_count += 1;
            }
        }

        if (left_count + right_count > 8) return error.InvalidIpv6Address;

        var groups: [8]u16 = [_]u16{0} ** 8;
        @memcpy(groups[0..left_count], left_groups[0..left_count]);
        @memcpy(groups[8 - right_count ..], right_groups[0..right_count]);

        for (groups, 0..) |g, i| {
            std.mem.writeInt(u16, result[i * 2 ..][0..2], g, .big);
        }
    } else {
        // Keine Kompression: genau 8 Gruppen erwartet.
        var it = std.mem.splitScalar(u8, text, ':');
        var idx: usize = 0;
        while (it.next()) |part| {
            if (idx >= 8) return error.InvalidIpv6Address;
            const g = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6Address;
            std.mem.writeInt(u16, result[idx * 2 ..][0..2], g, .big);
            idx += 1;
        }
        if (idx != 8) return error.InvalidIpv6Address;
    }

    std.debug.print("[debug] IPv6 geparst: {x}\n", .{result});
    return result;
}

fn looksLikeIpv6(text: []const u8) bool {
    return std.mem.indexOfScalar(u8, text, ':') != null;
}

fn readFileBytes(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    std.debug.print("[debug] readFileBytes: \"{s}\" ist {d} Byte gross\n", .{ path, stat.size });

    const data = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(data);

    var reader = file.reader(io, &.{});
    const bytes_read = try reader.interface.readSliceAll(data);
    _ = bytes_read;

    return data;
}

fn writeFileBytes(io: std.Io, path: []const u8, data: []const u8) !void {
    var file = std.Io.Dir.cwd().createFile(io, path, .{}) catch |err| {
        if (err == error.IsDir) {
            std.debug.print("[server] FEHLER: \"{s}\" ist ein Verzeichnis, kein Dateipfad. Bitte einen vollen Dateinamen angeben (z.B. \"{s}/empfangen.jpg\").\n", .{ path, path });
        }
        return err;
    };
    defer file.close(io);

    var writer = file.writer(io, &.{});
    try writer.interface.writeAll(data);
    try writer.interface.flush();

    std.debug.print("[debug] writeFileBytes: \"{s}\" geschrieben ({d} Byte)\n", .{ path, data.len });
}

const ResolvedMessage = struct {
    bytes: []const u8,
    owned: bool, // true = muss mit allocator.free() freigegeben werden

    fn deinit(self: ResolvedMessage, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.bytes);
    }
};

fn resolveMessage(io: std.Io, allocator: std.mem.Allocator, raw: []const u8) !ResolvedMessage {
    if (raw.len > 0 and raw[0] == '@') {
        const path = raw[1..];
        std.debug.print("[client] --message beginnt mit '@', lese Datei: \"{s}\"\n", .{path});
        const data = try readFileBytes(io, allocator, path);
        return ResolvedMessage{ .bytes = data, .owned = true };
    }
    std.debug.print("[client] --message wird als roher Text behandelt ({d} Byte)\n", .{raw.len});
    return ResolvedMessage{ .bytes = raw, .owned = false };
}

fn sendFramed(sock: synet.Socket, data: []const u8) !void {
    std.debug.print("[debug] sendFramed: schreibe {d} Byte (+4 Byte Längenpräfix)\n", .{data.len});
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try synet.sendAll(sock, &len_buf);
    try synet.sendAll(sock, data);
    std.debug.print("[debug] sendFramed: fertig gesendet\n", .{});
}

fn recvFramed(allocator: std.mem.Allocator, sock: synet.Socket) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try synet.recvExact(sock, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .big);

    const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;
    std.debug.print("[debug] recvFramed: Längenpräfix sagt {d} Byte\n", .{len});
    if (len > MAX_FRAME_SIZE) {
        std.debug.print("[debug] recvFramed: ABBRUCH, {d} Byte > Maximum {d}\n", .{ len, MAX_FRAME_SIZE });
        return error.FrameTooLarge;
    }

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try synet.recvExact(sock, buf);
    std.debug.print("[debug] recvFramed: {d} Byte vollständig empfangen\n", .{buf.len});
    return buf;
}

fn performKeyExchange(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: synet.Socket,
    is_initiator: bool,
) ![keyexchange.DERIVED_KEY_SIZE]u8 {
    const local = try keyexchange.generateLocalKeyPair(io);
    std.debug.print("[debug] keyexchange: eigenes Schlüsselpaar erzeugt (is_initiator={})\n", .{is_initiator});

    var peer_public_key: [keyexchange.PUBLIC_KEY_SIZE]u8 = undefined;

    if (is_initiator) {
        std.debug.print("[debug] keyexchange: sende eigenen Public Key zuerst\n", .{});
        try sendFramed(sock, &local.public_key);
        const received = try recvFramed(allocator, sock);
        defer allocator.free(received);
        if (received.len != keyexchange.PUBLIC_KEY_SIZE) {
            std.debug.print("[debug] keyexchange: ungültige Peer-Key-Länge {d} (erwartet {d})\n", .{ received.len, keyexchange.PUBLIC_KEY_SIZE });
            return error.InvalidPeerPublicKey;
        }
        @memcpy(&peer_public_key, received);
    } else {
        std.debug.print("[debug] keyexchange: warte zuerst auf Peer Public Key\n", .{});
        const received = try recvFramed(allocator, sock);
        defer allocator.free(received);
        if (received.len != keyexchange.PUBLIC_KEY_SIZE) {
            std.debug.print("[debug] keyexchange: ungültige Peer-Key-Länge {d} (erwartet {d})\n", .{ received.len, keyexchange.PUBLIC_KEY_SIZE });
            return error.InvalidPeerPublicKey;
        }
        @memcpy(&peer_public_key, received);
        try sendFramed(sock, &local.public_key);
    }

    std.debug.print("[debug] keyexchange: Peer Public Key erhalten, leite gemeinsamen Schlüssel ab\n", .{});
    return try keyexchange.deriveSharedKey(local, peer_public_key);
}

fn runServer(io: std.Io, allocator: std.mem.Allocator, port: u16, use_v6: bool, output_path: ?[]const u8) !void {
    std.debug.print("[server] Modus: {s}\n", .{if (use_v6) "IPv6 (::)" else "IPv4 (0.0.0.0)"});

    const listener = if (use_v6)
        try synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try synet.createTcpSocket();
    defer synet.close(listener);
    std.debug.print("[server] Socket erstellt (fd={d})\n", .{listener});

    if (use_v6) {
        const bind_addr = synet.buildSockaddrIn6([_]u8{0} ** 16, port); // "::"
        try synet.bind6(listener, &bind_addr);
    } else {
        const bind_addr = synet.buildSockaddrIn(.{ 0, 0, 0, 0 }, port);
        try synet.bind(listener, &bind_addr);
    }
    std.debug.print("[server] gebunden an Port {d}\n", .{port});
    try synet.listen(listener, 1);
    std.debug.print("[server] lauscht (backlog=1)\n", .{});

    std.debug.print("[server] warte auf Verbindung auf Port {d}...\n", .{port});

    const conn = try synet.accept(listener);
    defer synet.close(conn);

    std.debug.print("[server] Verbindung angenommen, starte Schlüsselaustausch...\n", .{});

    const key = try performKeyExchange(io, allocator, conn, false);
    std.debug.print("[server] Schlüsselaustausch abgeschlossen.\n", .{});

    const encrypted = try recvFramed(allocator, conn);
    defer allocator.free(encrypted);
    std.debug.print("[server] {d} verschlüsselte Bytes empfangen.\n", .{encrypted.len});

    const decrypted = translation.decryptFragment(allocator, encrypted, key) catch |err| {
        std.debug.print("[server] Entschlüsseln/Prüfen fehlgeschlagen: {}\n", .{err});
        return err;
    };
    defer allocator.free(decrypted);

    const parsed = try header.parsePacket(decrypted);

    std.debug.print(
        "[server] SIP-Paket erfolgreich entschlüsselt und geparst.\n" ++
            "[server]   magic={x} packet_type={d} conn_id={d}\n" ++
            "[server]   payload: {d} Byte\n",
        .{
            parsed.header.magic,
            parsed.header.packet_type,
            parsed.header.conn_id,
            parsed.payload.len,
        },
    );

    if (output_path) |path| {
        try writeFileBytes(io, path, parsed.payload);
        std.debug.print("[server] Payload gespeichert unter: \"{s}\"\n", .{path});
    }
}

fn runClient(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    message: []const u8,
) !void {
    const is_v6 = looksLikeIpv6(host);
    std.debug.print("[client] erkannte Adressfamilie: {s}\n", .{if (is_v6) "IPv6" else "IPv4"});

    const sock = if (is_v6)
        try synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try synet.createTcpSocket();
    defer synet.close(sock);
    std.debug.print("[client] Socket erstellt (fd={d})\n", .{sock});

    std.debug.print("[client] verbinde zu {s}:{d}...\n", .{ host, port });

    if (is_v6) {
        const ip6 = try parseIpv6(host);
        const addr6 = synet.buildSockaddrIn6(ip6, port);
        try synet.connect6(sock, &addr6);
    } else {
        const ip4 = try parseIpv4(host);
        std.debug.print("[client] geparste IPv4-Bytes: {d}.{d}.{d}.{d}\n", .{ ip4[0], ip4[1], ip4[2], ip4[3] });
        const addr4 = synet.buildSockaddrIn(ip4, port);
        try synet.connect(sock, &addr4);
    }
    std.debug.print("[client] TCP-Verbindung hergestellt\n", .{});

    std.debug.print("[client] verbunden, starte Schlüsselaustausch...\n", .{});
    const key = try performKeyExchange(io, allocator, sock, true);
    std.debug.print("[client] Schlüsselaustausch abgeschlossen.\n", .{});

    const resolved = try resolveMessage(io, allocator, message);
    defer resolved.deinit(allocator);
    const payload = resolved.bytes;

    const src = [_]u8{0xAA} ++ [_]u8{0} ** 15;
    const dst = [_]u8{0xBB} ++ [_]u8{0} ** 15;
    const buf = try allocator.alloc(u8, header.HEADER_SIZE + payload.len);
    defer allocator.free(buf);

    const packet = try header.buildPacket(buf, src, dst, 1, .data, payload);
    const encrypted = try translation.encryptFragment(io, allocator, packet, key);
    defer allocator.free(encrypted);

    std.debug.print("[client] sende {d} verschlüsselte Bytes...\n", .{encrypted.len});
    try sendFramed(sock, encrypted);
    std.debug.print("[client] gesendet. Fertig.\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const raw_args = try init.minimal.args.toSlice(init.arena.allocator());

    const args = parseArgs(gpa, raw_args) catch |err| {
        std.debug.print("Argument-Fehler: {}\n\n", .{err});
        // printUsage();
        std.process.exit(1);
    };

    switch (args.mode) {
        .server => try runServer(io, gpa, args.port, args.use_v6, args.output_path),
        .client => try runClient(io, gpa, args.host, args.port, args.message),
    }
}
