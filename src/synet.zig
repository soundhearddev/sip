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

fn checkSyscall(comptime what: SynetError, rc: usize) SynetError!usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        return what;
    }
    return rc;
}

pub fn createTcpSocket() SynetError!Socket {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    const checked = try checkSyscall(error.SocketCreateFailed, rc);
    return @intCast(checked);
}

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

pub fn accept(listener: Socket) SynetError!Socket {
    const rc = linux.accept4(listener, null, null, 0);
    const checked = try checkSyscall(error.AcceptFailed, rc);
    return @intCast(checked);
}

pub fn connect(sock: Socket, addr: *const posix.sockaddr.in) SynetError!void {
    const rc = linux.connect(sock, @ptrCast(addr), @sizeOf(posix.sockaddr.in));
    _ = try checkSyscall(error.ConnectFailed, rc);
}

pub fn sendAll(sock: Socket, data: []const u8) SynetError!void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = linux.write(sock, data[sent..].ptr, data.len - sent);
        const checked = try checkSyscall(error.SendFailed, rc);
        if (checked == 0) return error.ConnectionClosed;
        sent += checked;
    }
}

pub fn recvSome(sock: Socket, buf: []u8) SynetError!usize {
    const rc = linux.read(sock, buf.ptr, buf.len);
    return try checkSyscall(error.RecvFailed, rc);
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
    _ = linux.close(sock);
}

pub fn buildSockaddrIn6(addr: [16]u8, port: u16) std.posix.sockaddr.in6 {
    return .{
        .family = std.posix.AF.INET6,
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = addr,
        .scope_id = 0,
    };
}

pub fn createTcpSocketFamily(family: u32) SynetError!Socket {
    const rc = linux.socket(family, posix.SOCK.STREAM, 0);
    const checked = try checkSyscall(error.SocketCreateFailed, rc);
    return @intCast(checked);
}

pub fn bind6(sock: Socket, addr: *const posix.sockaddr.in6) SynetError!void {
    const rc = linux.bind(sock, @ptrCast(addr), @sizeOf(posix.sockaddr.in6));
    _ = try checkSyscall(error.BindFailed, rc);
}

pub fn connect6(sock: Socket, addr: *const posix.sockaddr.in6) SynetError!void {
    const rc = linux.connect(sock, @ptrCast(addr), @sizeOf(posix.sockaddr.in6));
    _ = try checkSyscall(error.ConnectFailed, rc);
}
