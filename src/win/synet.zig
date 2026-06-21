const std = @import("std");
const windows = std.os.windows;
const ws2_32 = windows.ws2_32;

pub const Socket = ws2_32.SOCKET;

pub const SynetError = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    ConnectFailed,
    SendFailed,
    RecvFailed,
    ConnectionClosed,
    WsaStartupFailed,
};

// Eigene Deklaration für die Win32-Winsock-Initialisierung
const WSADATA = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?*anyopaque,
};

// In modernen Zig-Versionen nutzt man für Windows-Systemaufrufe meist die standardmäßige C-Calling-Convention
pub extern "ws2_32" fn WSAStartup(wVersionRequired: u16, lpWSAData: *WSADATA) i32;
pub extern "ws2_32" fn WSACleanup() i32;

/// Initialisiert Winsock. Muss unter Windows vor der Socket-Nutzung aufgerufen werden.
pub fn init() SynetError!void {
    var wsa_data: WSADATA = undefined;
    // 0x0202 entspricht Version 2.2
    const rc = WSAStartup(0x0202, &wsa_data);
    if (rc != 0) return error.WsaStartupFailed;
}

/// Räumt Winsock-Ressourcen auf.
pub fn deinit() void {
    // Hier absolut darauf achten, dass KEIN 'std.os.windows.' mehr davor steht!
    _ = WSACleanup();
}

fn checkSocketResult(comptime what: SynetError, rc: anytype) SynetError!void {
    if (rc == ws2_32.SOCKET_ERROR) {
        return what;
    }
}

pub fn createTcpSocket() SynetError!Socket {
    const sock = ws2_32.socket(ws2_32.AF_INET, ws2_32.SOCK_STREAM, 0);
    if (sock == ws2_32.INVALID_SOCKET) return error.SocketCreateFailed;
    return sock;
}

pub fn buildSockaddrIn(addr_bytes: [4]u8, port: u16) ws2_32.sockaddr.in {
    return ws2_32.sockaddr.in{
        .family = ws2_32.AF_INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.bytesToValue(u32, &addr_bytes),
    };
}

pub fn bind(sock: Socket, addr: *const ws2_32.sockaddr.in) SynetError!void {
    const rc = ws2_32.bind(sock, @ptrCast(addr), @sizeOf(ws2_32.sockaddr.in));
    try checkSocketResult(error.BindFailed, rc);
}

pub fn listen(sock: Socket, backlog: i32) SynetError!void {
    const rc = ws2_32.listen(sock, backlog);
    try checkSocketResult(error.ListenFailed, rc);
}

pub fn accept(listener: Socket) SynetError!Socket {
    const sock = ws2_32.accept(listener, null, null);
    if (sock == ws2_32.INVALID_SOCKET) return error.AcceptFailed;
    return sock;
}

pub fn connect(sock: Socket, addr: *const ws2_32.sockaddr.in) SynetError!void {
    const rc = ws2_32.connect(sock, @ptrCast(addr), @sizeOf(ws2_32.sockaddr.in));
    try checkSocketResult(error.ConnectFailed, rc);
}

pub fn sendAll(sock: Socket, data: []const u8) SynetError!void {
    var sent: usize = 0;
    while (sent < data.len) {
        // Windows 'send' erwartet die Länge als i32
        const to_send = @min(data.len - sent, std.math.maxInt(i32));
        const rc = ws2_32.send(sock, data[sent..].ptr, @intCast(to_send), 0);

        if (rc == ws2_32.SOCKET_ERROR) return error.SendFailed;
        if (rc == 0) return error.ConnectionClosed;
        sent += @intCast(rc);
    }
}

pub fn recvSome(sock: Socket, buf: []u8) SynetError!usize {
    // Windows 'recv' erwartet die Länge als i32
    const to_recv = @min(buf.len, std.math.maxInt(i32));
    const rc = ws2_32.recv(sock, buf.ptr, @intCast(to_recv), 0);

    if (rc == ws2_32.SOCKET_ERROR) return error.RecvFailed;
    return @intCast(rc);
}

pub fn recvExact(sock: Socket, buf: []u8) SynetError!void {
    var received: usize = 0;
    while (received < buf.len) {
        const n = try recvSome(sock, buf[received..]);
        if (n == 0) return error.ConnectionClosed;
        received += n;
    }
}

pub fn close(sock: Socket) void {
    // Unter Windows schließt man Sockets mit closesocket
    _ = ws2_32.closesocket(sock);
}

pub fn buildSockaddrIn6(addr: [16]u8, port: u16) ws2_32.sockaddr.in6 {
    var sa = ws2_32.sockaddr.in6{
        .family = ws2_32.AF_INET6,
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .scope_id = 0,
        .addr = undefined,
    };
    @memcpy(&sa.addr, &addr);
    return sa;
}

pub fn createTcpSocketFamily(family: i32) SynetError!Socket {
    const sock = ws2_32.socket(family, ws2_32.SOCK_STREAM, 0);
    if (sock == ws2_32.INVALID_SOCKET) return error.SocketCreateFailed;
    return sock;
}

pub fn bind6(sock: Socket, addr: *const ws2_32.sockaddr.in6) SynetError!void {
    const rc = ws2_32.bind(sock, @ptrCast(addr), @sizeOf(ws2_32.sockaddr.in6));
    try checkSocketResult(error.BindFailed, rc);
}

pub fn connect6(sock: Socket, addr: *const ws2_32.sockaddr.in6) SynetError!void {
    const rc = ws2_32.connect(sock, @ptrCast(addr), @sizeOf(ws2_32.sockaddr.in6));
    try checkSocketResult(error.ConnectFailed, rc);
}
