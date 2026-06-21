// main.zig — CLI-Testprogramm: SIP-Pakete ueber echtes TCP jagen.
//
// WICHTIGE DESIGN-ENTSCHEIDUNG (im Detail unten erklaert): dieses Programm
// nutzt translation.zig NUR fuer encryptFragment()/decryptFragment() - es
// nutzt NICHT translateOutbound/translateInbound/ReassemblyBuffer/
// fragmentation.zig. Grund: jene Funktionen existieren, um ein SIP-Paket in
// mehrere unabhaengige, einzeln verschickte Netzwerk-Pakete aufzuteilen
// (fuer Transporte wie rohes UDP oder Raw-IPv6, wo JEDES einzelne Paket
// unabhaengig verloren gehen oder in falscher Reihenfolge ankommen kann).
// TCP ist dagegen bereits selbst ein zuverlaessiger, geordneter Bytestream -
// der Kernel fragmentiert, sortiert und bestaetigt Daten innerhalb einer
// TCP-Verbindung schon vollstaendig selbst. Eine SIP-eigene Fragmentierung
// darueber zu legen wuerde dieselbe Arbeit doppelt machen. Es wird daher
// GENAU EIN SIP-Paket (Header+Payload aus header.zig) gebaut, EINMAL mit
// ChaCha20-Poly1305 verschluesselt (ein Auth-Tag, eine Nonce fuer das ganze
// Paket) und als zusammenhaengender Byte-Block ueber den TCP-Socket
// geschickt. TCP selbst entscheidet, in wie viele TCP-Segmente das
// unterwegs aufgeteilt wird - das ist fuer dieses Programm unsichtbar.
//
// Modularitaet: synet.zig (Syscalls) und keyexchange.zig (X25519) sind
// komplett unabhaengig voneinander und von dieser Datei austauschbar -
// main.zig verbindet sie nur. Wer z.B. spaeter IPv6 statt IPv4 will, aendert
// nur synet.zig; wer das Schluesselaustausch-Verfahren aendern will, nur
// keyexchange.zig.

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
};

fn printUsage() void {
    std.debug.print(
        \\Verwendung:
        \\  sip-tcp-test --listen [--port PORT]
        \\  sip-tcp-test --connect [--host HOST] [--port PORT] --message TEXT
        \\
        \\Optionen:
        \\  --listen          Server-Modus: wartet auf eine eingehende Verbindung
        \\  --connect         Client-Modus: verbindet sich zu einem Server
        \\  --host HOST       Ziel-Host im Client-Modus (Standard: 127.0.0.1)
        \\  --port PORT       Port (Standard: {d})
        \\  --message TEXT    SIP-Payload, der im Client-Modus geschickt wird
        \\  --help            Diese Hilfe anzeigen
        \\
    , .{DEFAULT_PORT});
}

fn parseArgs(allocator: std.mem.Allocator, raw_args: []const []const u8) !Args {
    var mode: ?Mode = null;
    var host: []const u8 = "127.0.0.1";
    var port: u16 = DEFAULT_PORT;
    var message: []const u8 = "";

    var i: usize = 1; // raw_args[0] ist der Programmname
    while (i < raw_args.len) {
        const arg = raw_args[i];

        if (std.mem.eql(u8, arg, "--help")) {
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
        } else {
            std.debug.print("Unbekanntes Argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }

    const resolved_mode = mode orelse return error.MissingMode;
    if (resolved_mode == .client and message.len == 0) {
        return error.MissingMessage;
    }

    _ = allocator; // aktuell nicht gebraucht, Signatur bleibt fuer spaetere Erweiterung offen

    return Args{ .mode = resolved_mode, .host = host, .port = port, .message = message };
}

/// Parst eine IPv4-Adresse aus einem String wie "127.0.0.1" in 4 Bytes.
/// Bewusst selbst geschrieben statt std.net.Address.parseIp4 zu nutzen, da
/// std.net in Zig 0.16 zugunsten von std.Io.net entfernt wurde und wir
/// ohnehin nur die rohen 4 Bytes fuer synet.buildSockaddrIn brauchen.
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

/// Schreibt einen Block mit einem 4-Byte-Laengenpraefix (big-endian) auf den
/// Socket - notwendig, weil TCP ein reiner Bytestream ist: der Empfaenger
/// muss wissen, wo EIN verschluesseltes SIP-Paket endet und das naechste
/// beginnt. Das ist die einzige "Framing"-Information, die wir zusaetzlich
/// zum eigentlichen translation.zig-Format brauchen, WEIL wir keine eigene
/// Fragmentierung mehr nutzen (siehe Erklaerung am Dateianfang).
fn sendFramed(sock: synet.Socket, data: []const u8) !void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try synet.sendAll(sock, &len_buf);
    try synet.sendAll(sock, data);
}

/// Liest einen mit sendFramed() geschriebenen Block wieder ein.
fn recvFramed(allocator: std.mem.Allocator, sock: synet.Socket) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try synet.recvExact(sock, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .big);

    // Defensiver Cap: ein einzelnes SIP-Paket sollte realistisch nie auch
    // nur annaehernd 16 MB gross sein. Ohne diesen Check koennte ein
    // boeswilliger oder fehlerhafter Peer ein riesiges len_buf senden und
    // den Empfaenger zu einer riesigen Allokation zwingen, bevor ueberhaupt
    // ein Byte echter Daten da ist.
    const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;
    if (len > MAX_FRAME_SIZE) return error.FrameTooLarge;

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try synet.recvExact(sock, buf);
    return buf;
}

/// Fuehrt den X25519-Schluesselaustausch ueber eine bestehende TCP-
/// Verbindung durch. is_initiator unterscheidet nur die Reihenfolge von
/// Senden/Empfangen (Client schickt zuerst, Server antwortet) - das
/// Ergebnis (der abgeleitete Schluessel) ist fuer beide Seiten identisch.
fn performKeyExchange(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: synet.Socket,
    is_initiator: bool,
) ![keyexchange.DERIVED_KEY_SIZE]u8 {
    const local = try keyexchange.generateLocalKeyPair(io);

    var peer_public_key: [keyexchange.PUBLIC_KEY_SIZE]u8 = undefined;

    if (is_initiator) {
        try sendFramed(sock, &local.public_key);
        const received = try recvFramed(allocator, sock);
        defer allocator.free(received);
        if (received.len != keyexchange.PUBLIC_KEY_SIZE) return error.InvalidPeerPublicKey;
        @memcpy(&peer_public_key, received);
    } else {
        const received = try recvFramed(allocator, sock);
        defer allocator.free(received);
        if (received.len != keyexchange.PUBLIC_KEY_SIZE) return error.InvalidPeerPublicKey;
        @memcpy(&peer_public_key, received);
        try sendFramed(sock, &local.public_key);
    }

    return try keyexchange.deriveSharedKey(local, peer_public_key);
}

fn runServer(io: std.Io, allocator: std.mem.Allocator, port: u16) !void {
    const listener = try synet.createTcpSocket();
    defer synet.close(listener);

    const bind_addr = synet.buildSockaddrIn(.{ 0, 0, 0, 0 }, port);
    try synet.bind(listener, &bind_addr);
    try synet.listen(listener, 1);

    std.debug.print("[server] warte auf Verbindung auf Port {d}...\n", .{port});

    const conn = try synet.accept(listener);
    defer synet.close(conn);

    std.debug.print("[server] Verbindung angenommen, starte Schluesselaustausch...\n", .{});

    const key = try performKeyExchange(io, allocator, conn, false);
    std.debug.print("[server] Schluesselaustausch abgeschlossen.\n", .{});

    const encrypted = try recvFramed(allocator, conn);
    defer allocator.free(encrypted);
    std.debug.print("[server] {d} verschluesselte Bytes empfangen.\n", .{encrypted.len});

    const decrypted = translation.decryptFragment(allocator, encrypted, key) catch |err| {
        std.debug.print("[server] Entschluesseln/Pruefen fehlgeschlagen: {}\n", .{err});
        return err;
    };
    defer allocator.free(decrypted);

    const parsed = try header.parsePacket(decrypted);

    std.debug.print(
        "[server] SIP-Paket erfolgreich entschluesselt und geparst.\n" ++
            "[server]   magic={x} packet_type={d} conn_id={d} total_fragments={d}\n" ++
            "[server]   payload ({d} Byte): {s}\n",
        .{
            parsed.header.magic,
            parsed.header.packet_type,
            parsed.header.conn_id,
            parsed.header.total_fragments,
            parsed.payload.len,
            parsed.payload,
        },
    );
}

fn runClient(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    message: []const u8,
) !void {
    const sock = try synet.createTcpSocket();
    defer synet.close(sock);

    const ip = try parseIpv4(host);
    const addr = synet.buildSockaddrIn(ip, port);

    std.debug.print("[client] verbinde zu {s}:{d}...\n", .{ host, port });
    try synet.connect(sock, &addr);

    std.debug.print("[client] verbunden, starte Schluesselaustausch...\n", .{});
    const key = try performKeyExchange(io, allocator, sock, true);
    std.debug.print("[client] Schluesselaustausch abgeschlossen.\n", .{});

    // EIN SIP-Paket bauen (header.zig) - KEINE Fragmentierung, siehe
    // Erklaerung am Dateianfang. total_fragments=1, da dies das einzige
    // (und einzig noetige) "Fragment" ist.
    const src = [_]u8{0xAA} ++ [_]u8{0} ** 15;
    const dst = [_]u8{0xBB} ++ [_]u8{0} ** 15;
    const buf = try allocator.alloc(u8, header.HEADER_SIZE + message.len);
    defer allocator.free(buf);

    const packet = try header.buildPacket(buf, src, dst, 1, .data, message, 1);

    const encrypted = try translation.encryptFragment(io, allocator, packet, key);
    defer allocator.free(encrypted);

    std.debug.print("[client] sende {d} verschluesselte Bytes...\n", .{encrypted.len});
    try sendFramed(sock, encrypted);
    std.debug.print("[client] gesendet. Fertig.\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const raw_args = try init.minimal.args.toSlice(init.arena.allocator());

    const args = parseArgs(gpa, raw_args) catch |err| {
        std.debug.print("Argument-Fehler: {}\n\n", .{err});
        printUsage();
        std.process.exit(1);
    };

    switch (args.mode) {
        .server => try runServer(io, gpa, args.port),
        .client => try runClient(io, gpa, args.host, args.port, args.message),
    }
}
