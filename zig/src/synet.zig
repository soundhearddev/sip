// synet.zig — duenne Schicht direkt ueber std.os.linux-Syscalls.
//
// Bewusste Designentscheidung: KEIN std.posix.socket/bind/listen/accept/...
// und KEIN std.Io.net. Diese Datei ruft die Linux-Syscalls so direkt wie es
// in Zig sinnvoll ist (std.os.linux.*), und behandelt deren rohe usize-
// Rueckgabewerte selbst. std.posix dient hier NUR noch als Quelle fuer
// Konstanten (AF.*, SOCK.*, sockaddr-Typen) - diese Typdefinitionen sind in
// Zig 0.16 weiterhin vorhanden, nur die High-Level-Funktions-Wrapper
// (posix.socket(), posix.bind(), ...) wurden im Zuge des std.Io-Umbaus
// entfernt.
//
// Diese Datei kennt NICHTS von SIP, Verschluesselung oder Fragmentierung -
// sie ist reine Transport-Mechanik (Layer 4 und runter, vom Betriebssystem
// erledigt; diese Datei ruft nur die Tueren dazu auf).

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const Socket = i32;

pub const SynetError = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    ConnectFailed,
    SendFailed,
    RecvFailed,
    ConnectionClosed,
};

/// Wandelt einen rohen std.os.linux-Syscall-Rueckgabewert (usize) in
/// entweder einen Erfolgswert (>= 0) oder einen negativen errno-Wert um.
/// std.os.linux.* gibt usize zurueck, das bei Fehlern tatsaechlich einen
/// negativen Wert traegt (als usize uminterpretiert) - ohne den Bitcast nach
/// isize wuerde jeder "Fehler" wie eine riesige positive Zahl aussehen.
fn checkSyscall(comptime what: SynetError, rc: usize) SynetError!usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        return what;
    }
    return rc;
}

/// Erstellt einen TCP-Socket (AF.INET, SOCK.STREAM).
/// IPv6 bewusst nicht hier behandelt - siehe Hinweis am Dateiende.
pub fn createTcpSocket() SynetError!Socket {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    const checked = try checkSyscall(error.SocketCreateFailed, rc);
    return @intCast(checked);
}

/// Baut eine IPv4-sockaddr-Struktur aus Adresse (4 Byte) und Port.
/// htons (Host-to-Network-Short) wird hier manuell gemacht, da wir bewusst
/// keine std.net.Address-Komfortfunktion benutzen.
///
/// Wichtig zur Byte-Reihenfolge von addr_bytes: die 4 Bytes werden GENAU SO
/// uebernommen, wie sie im Array stehen (kein zusaetzlicher Byteswap) -
/// "127.0.0.1" wird also als [127, 0, 0, 1] uebergeben, exakt in der
/// Reihenfolge, in der die IP-Adresse geschrieben wird. Das entspricht
/// bereits Network-Byte-Order (big-endian) fuer IPv4-Adressen, anders als
/// beim Port (sin_port), der explizit von Host- in Network-Byte-Order
/// konvertiert werden muss (siehe nativeToBig unten).
pub fn buildSockaddrIn(addr_bytes: [4]u8, port: u16) posix.sockaddr.in {
    return posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.bytesToValue(u32, &addr_bytes),
    };
}

pub fn bind(sock: Socket, addr: *const posix.sockaddr.in) SynetError!void {
    const rc = linux.bind(sock, @ptrCast(addr), @sizeOf(posix.sockaddr.in));
    _ = try checkSyscall(error.BindFailed, rc);
}

pub fn listen(sock: Socket, backlog: u31) SynetError!void {
    const rc = linux.listen(sock, backlog);
    _ = try checkSyscall(error.ListenFailed, rc);
}

/// accept() OHNE die Peer-Adresse auszulesen (addr=null, addrlen=null) -
/// fuer diesen Test brauchen wir nur die Verbindung selbst, nicht woher sie
/// kam. Wer das spaeter braucht, kann hier leicht ein
/// acceptWithAddr() ergaenzen, ohne diese Funktion anzufassen.
///
/// Nutzt bewusst accept4 (mit flags=0) statt des alten accept(), da
/// accept4 die syscall-Signatur ist, die std.os.linux konsistent fuer
/// alle Architekturen bereitstellt.
pub fn accept(listener: Socket) SynetError!Socket {
    const rc = linux.accept4(listener, null, null, 0);
    const checked = try checkSyscall(error.AcceptFailed, rc);
    return @intCast(checked);
}

pub fn connect(sock: Socket, addr: *const posix.sockaddr.in) SynetError!void {
    const rc = linux.connect(sock, @ptrCast(addr), @sizeOf(posix.sockaddr.in));
    _ = try checkSyscall(error.ConnectFailed, rc);
}

/// Sendet `data` vollstaendig - TCP send() kann weniger schreiben, als
/// angefordert (Teil-Writes sind normal, kein Fehler), deshalb wird in
/// einer Schleife nachgefasst, bis alles raus ist.
pub fn sendAll(sock: Socket, data: []const u8) SynetError!void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = linux.write(sock, data[sent..].ptr, data.len - sent);
        const checked = try checkSyscall(error.SendFailed, rc);
        if (checked == 0) return error.ConnectionClosed;
        sent += checked;
    }
}

/// Liest bis zu buf.len Byte. Gibt die tatsaechlich gelesene Anzahl zurueck.
/// 0 bedeutet: Verbindung wurde vom Peer geschlossen (EOF), kein Fehler.
pub fn recvSome(sock: Socket, buf: []u8) SynetError!usize {
    const rc = linux.read(sock, buf.ptr, buf.len);
    return try checkSyscall(error.RecvFailed, rc);
}

/// Liest EXAKT buf.len Byte oder gibt error.ConnectionClosed zurueck, falls
/// der Peer vorher schliesst. Wichtig fuer "lies erst den Header, dann den
/// Payload" - ein einzelner recv() Aufruf darf bei TCP weniger liefern, als
/// angefordert.
pub fn recvExact(sock: Socket, buf: []u8) SynetError!void {
    var received: usize = 0;
    while (received < buf.len) {
        const n = try recvSome(sock, buf[received..]);
        if (n == 0) return error.ConnectionClosed;
        received += n;
    }
}

pub fn close(sock: Socket) void {
    _ = linux.close(sock);
}

// ----------------------------------------------------------------------
// Hinweis IPv6 / Layer 3:
//
// Diese Datei behandelt aktuell nur AF.INET (IPv4). Der urspruengliche
// Design-Rundown von translation.zig sieht ausdruecklich vor, dass die
// Wahl des Transports (UDP, Raw-IPv6, TCP, ...) spaeter frei und ohne
// Umbau von translation.zig getroffen werden soll. Dieselbe Trennung gilt
// hier: synet.zig kennt nur "Bytes ueber einen TCP-Socket", nicht WELCHE
// SIP-Adresse zu welcher IP gehoert (das ist laut Rundown ohnehin noch
// ungeloestes Discovery-Problem). Ein AF.INET6-Pfad liesse sich als eigene
// Funktion (z.B. buildSockaddrIn6 + ein sockaddr.in6-Aequivalent von
// bind/connect) ergaenzen, ohne die bestehenden IPv4-Funktionen anzufassen.
// ----------------------------------------------------------------------
