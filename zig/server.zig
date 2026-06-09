const std = @import("std");
const Thread = std.Thread;
const posix = std.posix;

pub const BOOTSTRAP_PORT = 9871;
pub const DATA_PORT = 9872;

const TrustStore = struct {
    mutex: std.Mutex = .{},

    pub fn isKnown(self: *TrustStore, _: [32]u8) bool {
        _ = self;
        return false;
    }

    pub fn addPeer(self: *TrustStore, _: [32]u8) void {
        _ = self;
    }
};

const Connection = struct {
    handle: posix.fd_t,
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var store = TrustStore{};

    std.debug.print("[Server] Start {d} / {d}\n", .{ BOOTSTRAP_PORT, DATA_PORT });

    const t1 = try Thread.spawn(.{}, listenBootstrap, .{ allocator, &store });
    const t2 = try Thread.spawn(.{}, listenData, .{ allocator, &store });

    t1.join();
    t2.join();
}

// ───────────────────────── BOOTSTRAP SERVER ─────────────────────────

fn listenBootstrap(_: std.mem.Allocator, store: *TrustStore) !void {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    defer posix.close(fd);

    var opt: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt));

    var addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, BOOTSTRAP_PORT),
        .addr = std.mem.nativeToBig(u32, posix.INADDR.ANY),
    };

    try posix.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    try posix.listen(fd, 128);

    while (true) {
        var caddr: posix.sockaddr = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const cfd = try posix.accept(fd, &caddr, &len);
        const conn = Connection{ .handle = cfd };

        const t = try Thread.spawn(.{}, handleBootstrap, .{ store, conn });
        t.detach();
    }
}

fn handleBootstrap(store: *TrustStore, conn: Connection) void {
    defer posix.close(conn.handle);

    var key: [32]u8 = undefined;
    const n = posix.read(conn.handle, &key) catch return;
    if (n < 32) return;

    store.mutex.lock();
    defer store.mutex.unlock();

    if (store.isKnown(key)) {
        _ = posix.write(conn.handle, "OK") catch return;
        return;
    }

    store.addPeer(key);
    _ = posix.write(conn.handle, "UPGRADE") catch return;
}

// ───────────────────────── DATA SERVER ─────────────────────────

fn listenData(_: std.mem.Allocator, store: *TrustStore) !void {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    defer posix.close(fd);

    var opt: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt));

    var addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, DATA_PORT),
        .addr = std.mem.nativeToBig(u32, posix.INADDR.ANY),
    };

    try posix.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    try posix.listen(fd, 128);

    while (true) {
        var caddr: posix.sockaddr = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const cfd = try posix.accept(fd, &caddr, &len);
        const conn = Connection{ .handle = cfd };

        const t = try Thread.spawn(.{}, handleData, .{ store, conn });
        t.detach();
    }
}

fn handleData(store: *TrustStore, conn: Connection) void {
    defer posix.close(conn.handle);

    var key: [32]u8 = undefined;
    const n = posix.read(conn.handle, &key) catch return;
    if (n < 32) return;

    store.mutex.lock();
    defer store.mutex.unlock();

    if (!store.isKnown(key)) return;

    var buf: [1024]u8 = undefined;
    while (true) {
        const r = posix.read(conn.handle, &buf) catch break;
        if (r == 0) break;
    }
}
