const std = @import("std");
const trust = @import("trust.zig");
const session = @import("session.zig");
const translation = @import("translation.zig");
const header = @import("header.zig");
const frag = @import("fragmentation.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const BOOTSTRAP_PORT: u16 = 9871;

// ----------------------------
// Approval Queue
// Bootstrap-Threads legen Anfragen rein,
// Hauptthread arbeitet sie ab
// ----------------------------
const ApprovalRequest = struct {
    info: trust.PeerInfo,
    result: ?bool = null,
    mutex: std.Io.Mutex = .{ .state = std.atomic.Value(std.Io.Mutex.State).init(.unlocked) },
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

const ApprovalQueue = struct {
    items: [16]?*ApprovalRequest = [_]?*ApprovalRequest{null} ** 16,
    head: usize = 0,
    tail: usize = 0,
    mutex: std.Io.Mutex = .{ .state = std.atomic.Value(std.Io.Mutex.State).init(.unlocked) },
    semaphore: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn push(self: *ApprovalQueue, io: std.Io, req: *ApprovalRequest) !void {
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);
        self.items[self.tail % 16] = req;
        self.tail += 1;
        _ = self.semaphore.fetchAdd(1, .release);
    }

    pub fn pop(self: *ApprovalQueue, io: std.Io) !*ApprovalRequest {
        while (self.semaphore.load(.acquire) == 0) std.Thread.yield() catch {};
        _ = self.semaphore.fetchSub(1, .release);
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);
        const req = self.items[self.head % 16].?;
        self.items[self.head % 16] = null;
        self.head += 1;
        return req;
    }
};

var global_approval_queue: ApprovalQueue = .{};

pub const DATA_PORT: u16 = 9872;

// ----------------------------
// Kontext der an jeden Thread übergeben wird
// ----------------------------
const ServerCtx = struct {
    io: std.Io,
    queue: *ApprovalQueue,
    allocator: std.mem.Allocator,
    store: *trust.TrustStore,
    own_ed: Ed25519.KeyPair,
};

const ConnCtx = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    store: *trust.TrustStore,
    own_ed: Ed25519.KeyPair,
    stream: std.Io.net.Stream,
    queue: *ApprovalQueue,
};

// ----------------------------
// Einstiegspunkt
// ----------------------------
pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const own_ed = Ed25519.KeyPair.generate(io);

    var store = trust.TrustStore.init(io, allocator);
    defer store.deinit();

    const ctx = ServerCtx{
        .io = io,
        .queue = &global_approval_queue,
        .allocator = allocator,
        .store = &store,
        .own_ed = own_ed,
    };

    std.debug.print("[SIP Server] Bootstrap: {d} | Data: {d}\n", .{ BOOTSTRAP_PORT, DATA_PORT });
    std.debug.print("[SIP Server] Mesh-Addr: {x}\n\n", .{session.peerMeshAddr(own_ed.public_key.toBytes())});

    const t_bootstrap = try std.Thread.spawn(.{}, listenBootstrap, .{ctx});
    const t_data = try std.Thread.spawn(.{}, listenData, .{ctx});
    t_bootstrap.detach();
    t_data.detach();

    // Hauptthread: Approval-Queue — blockiert auf stdin für j/n
    while (true) {
        const req = try global_approval_queue.pop(io);
        const approved = try trust.requestApproval(io, ctx.store, req.info);
        if (approved) {
            var invited_by: ?[32]u8 = null;
            if (req.info.invite_token) |token| {
                if (trust.verifyInvite(token, req.info.ed_pub)) {
                    if (try ctx.store.isKnown(token.inviter_ed_pub)) {
                        invited_by = token.inviter_ed_pub;
                    }
                }
            }
            try ctx.store.add(trust.TrustedPeer{
                .ed_pub = req.info.ed_pub,
                .mesh_addr = req.info.mesh_addr,
                .name = req.info.name,
                .name_len = req.info.name_len,
                .invited_by = invited_by,
            });
        }
        req.result = approved;
        req.done.store(true, .release);
    }
}

// ----------------------------
// Bootstrap Listener (Port 9871)
// ----------------------------
fn listenBootstrap(ctx: ServerCtx) !void {
    const addr = try std.Io.net.IpAddress.parse("::", BOOTSTRAP_PORT);
    var server = try addr.listen(ctx.io, .{ .reuse_address = true });
    defer server.deinit(ctx.io);

    std.debug.print("[Bootstrap] Lausche auf [::]:{d}\n", .{BOOTSTRAP_PORT});

    while (true) {
        const conn = server.accept(ctx.io) catch |err| {
            std.debug.print("[Bootstrap] Accept Fehler: {}\n", .{err});
            continue;
        };

        const conn_ctx = ConnCtx{
            .io = ctx.io,
            .allocator = ctx.allocator,
            .store = ctx.store,
            .own_ed = ctx.own_ed,
            .stream = conn,
            .queue = ctx.queue,
        };

        const t = std.Thread.spawn(.{}, handleBootstrap, .{conn_ctx}) catch |err| {
            std.debug.print("[Bootstrap] Thread-Fehler: {}\n", .{err});
            conn.close(ctx.io);
            continue;
        };
        t.detach();
    }
}

fn handleBootstrap(ctx: ConnCtx) void {
    handleBootstrapInner(ctx) catch |err| {
        std.debug.print("[Bootstrap] Fehler: {}\n", .{err});
    };
    ctx.stream.shutdown(ctx.io, .send) catch {};
    ctx.stream.close(ctx.io);
}

fn handleBootstrapInner(ctx: ConnCtx) !void {
    std.debug.print("[Bootstrap] Verbindung angenommen\n", .{});

    var read_buf: [512]u8 = undefined;
    var reader = ctx.stream.reader(ctx.io, &read_buf);

    std.debug.print("[Bootstrap] Lese ed_pub...\n", .{});
    const ep = try reader.interface.take(32);
    var ed_pub: [32]u8 = undefined;
    @memcpy(&ed_pub, ep[0..32]);
    std.debug.print("[Bootstrap] ed_pub: {x}...\n", .{ed_pub[0..8]});

    const mp = try reader.interface.take(32);
    var mesh_addr: [32]u8 = undefined;
    @memcpy(&mesh_addr, mp[0..32]);

    const nlp = try reader.interface.take(1);
    const name_len = nlp[0];
    std.debug.print("[Bootstrap] name_len={d}\n", .{name_len});

    if (name_len > trust.MAX_NAME_LEN) return error.NameTooLong;

    var name_buf = [_]u8{0} ** trust.MAX_NAME_LEN;
    if (name_len > 0) {
        const np = try reader.interface.take(name_len);
        @memcpy(name_buf[0..name_len], np[0..name_len]);
        std.debug.print("[Bootstrap] name={s}\n", .{name_buf[0..name_len]});
    }

    const hip = try reader.interface.take(1);
    const has_invite = hip[0] != 0;
    std.debug.print("[Bootstrap] has_invite={}\n", .{has_invite});

    const challenge = session.genChallenge(ctx.io);
    var chal_buf: [32]u8 = undefined;
    @memcpy(&chal_buf, &challenge);
    // direkt auf stream schreiben vor dem writer
    var tmp_wbuf: [32]u8 = undefined;
    var tmp_writer = ctx.stream.writer(ctx.io, &tmp_wbuf);
    try tmp_writer.interface.writeAll(&chal_buf);
    try tmp_writer.interface.flush();

    // Signatur lesen (64B)
    const sigp = try reader.interface.take(64);
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, sigp[0..64]);

    // Verifizieren
    if (!session.verifyChallenge(ed_pub, challenge, sig_bytes)) {
        return error.InvalidSignature;
    }
    std.debug.print("[Bootstrap] Signatur OK\n", .{});

    var invite_token: ?trust.InviteToken = null;
    if (has_invite) {
        var inviter_pub: [32]u8 = undefined;
        var invite_sig_bytes: [64]u8 = undefined;
        const ip = try reader.interface.take(32);
        @memcpy(&inviter_pub, ip[0..32]);
        const sp = try reader.interface.take(64);
        @memcpy(&invite_sig_bytes, sp[0..64]);
        invite_token = trust.InviteToken{
            .inviter_ed_pub = inviter_pub,
            .signature = invite_sig_bytes,
        };
    }

    // info ist jetzt definiert
    const info = trust.PeerInfo{
        .ed_pub = ed_pub,
        .mesh_addr = mesh_addr,
        .name = name_buf,
        .name_len = name_len,
        .invite_token = invite_token,
    };

    std.debug.print("[Bootstrap] Info bereit — prüfe ob bekannt...\n", .{});

    const approved = blk: {
        if (try ctx.store.isKnown(info.ed_pub)) {
            std.debug.print("[Bootstrap] Bereits bekannt — direkt durch\n", .{});
            break :blk true;
        }
        std.debug.print("[Bootstrap] Unbekannt — warte auf Approval...\n", .{});
        var req = ApprovalRequest{ .info = info };
        try global_approval_queue.push(ctx.io, &req);
        std.debug.print("[Bootstrap] In Queue — warte...\n", .{});
        while (!req.done.load(.acquire)) std.Thread.yield() catch {};
        std.debug.print("[Bootstrap] Approval: {?}\n", .{req.result});
        break :blk req.result orelse false;
    };

    var write_buf: [1024]u8 = undefined;
    var writer = ctx.stream.writer(ctx.io, &write_buf);

    if (!approved) {
        std.debug.print("[Bootstrap] Abgelehnt\n", .{});
        try writer.interface.writeAll("DENY\n");
        return;
    }

    const own_pub = ctx.own_ed.public_key.toBytes();
    const own_mesh = session.peerMeshAddr(own_pub);
    const own_name = "sip-node.mesh";

    try writer.interface.writeAll("OK\n");
    try writer.interface.flush();

    try writer.interface.writeAll(&own_pub);
    try writer.interface.writeAll(&own_mesh);
    try writer.interface.writeByte(@intCast(own_name.len));
    try writer.interface.writeAll(own_name);
    try writer.interface.flush();
}

// ----------------------------
// Data Listener (Port 9872)
// ----------------------------
fn listenData(ctx: ServerCtx) !void {
    const addr = try std.Io.net.IpAddress.parse("::", DATA_PORT);
    var server = try addr.listen(ctx.io, .{ .reuse_address = true });
    defer server.deinit(ctx.io);

    std.debug.print("[Data] Lausche auf [::]:{d}\n", .{DATA_PORT});

    while (true) {
        const conn = server.accept(ctx.io) catch |err| {
            std.debug.print("[Data] Accept Fehler: {}\n", .{err});
            continue;
        };

        const conn_ctx = ConnCtx{
            .io = ctx.io,
            .allocator = ctx.allocator,
            .store = ctx.store,
            .own_ed = ctx.own_ed,
            .stream = conn,
            .queue = ctx.queue,
        };

        const t = std.Thread.spawn(.{}, handleData, .{conn_ctx}) catch |err| {
            std.debug.print("[Data] Thread-Fehler: {}\n", .{err});
            conn.close(ctx.io);
            continue;
        };
        t.detach();
    }
}

fn handleData(ctx: ConnCtx) void {
    defer ctx.stream.close(ctx.io);
    handleDataInner(ctx) catch |err| {
        if (err != error.UnknownPeer and err != error.InvalidSignature) {
            std.debug.print("[Data] Fehler: {}\n", .{err});
        }
    };
}

fn handleDataInner(ctx: ConnCtx) !void {
    var read_buf: [4096]u8 = undefined;
    var reader = ctx.stream.reader(ctx.io, &read_buf);
    var write_buf: [256]u8 = undefined;
    var writer = ctx.stream.writer(ctx.io, &write_buf);

    // 1. Peer ed_pub (32B) empfangen
    const pp = try reader.interface.take(32);
    var peer_ed_pub: [32]u8 = undefined;
    @memcpy(&peer_ed_pub, pp[0..32]);

    // Unbekannte Peers: sofort schließen, kein Output
    if (!try ctx.store.isKnown(peer_ed_pub)) return error.UnknownPeer;

    // 2. Session Handshake
    //    Empfange: peer_eph_pub(32) | challenge(32) | sig(64) = 128B
    const hp = try reader.interface.take(128);

    var peer_eph_pub: [32]u8 = undefined;
    var peer_challenge: [session.CHALLENGE_LEN]u8 = undefined;
    var peer_sig: [64]u8 = undefined;

    @memcpy(&peer_eph_pub, hp[0..32]);
    @memcpy(&peer_challenge, hp[32..64]);
    @memcpy(&peer_sig, hp[64..128]);

    // Signatur prüfen
    if (!session.verifyHello(peer_ed_pub, peer_eph_pub, peer_challenge, peer_sig)) {
        return error.InvalidSignature;
    }

    // Eigenes HelloMsg generieren und senden
    const own_eph = session.genEphemeral(ctx.io);
    const own_challenge = session.genChallenge(ctx.io);
    const own_sig = try session.signHello(ctx.own_ed, own_eph.public, own_challenge);

    try writer.interface.writeAll(&own_eph.public);
    try writer.interface.writeAll(&own_challenge);
    try writer.interface.writeAll(&own_sig);

    // Session Key ableiten
    const sess_key = try session.deriveSessionKey(own_eph.secret, peer_eph_pub);
    const conn_id = session.genConnId(ctx.io);
    const peer_mesh = session.peerMeshAddr(peer_ed_pub);

    std.debug.print("[Data] Session: conn={d} peer={x}\n", .{ conn_id, peer_mesh[0..8] });

    // 3. Daten-Loop: SIP-Pakete empfangen
    var rbuf = translation.ReassemblyBuffer.init(ctx.allocator);
    defer rbuf.deinit();

    var pkt_buf: [2048]u8 = undefined;
    var pkt_reader = ctx.stream.reader(ctx.io, &pkt_buf);

    while (true) {
        // Header + Nonce lesen um payload_len zu kennen
        const MIN_HDR = header.HEADER_SIZE + translation.NONCE_SIZE;
        const hdr_peek = pkt_reader.interface.take(MIN_HDR) catch break;

        const payload_len = std.mem.readInt(u16, hdr_peek[42..44], .little);
        const total = MIN_HDR + payload_len + translation.TAG_SIZE;
        if (total > pkt_buf.len) break;

        const full = pkt_reader.interface.take(total) catch break;

        const result = translation.translateInbound(
            ctx.allocator,
            full[0..total],
            sess_key,
            &rbuf,
        ) catch |err| {
            std.debug.print("[Data] Entschlüsselung fehlgeschlagen: {}\n", .{err});
            continue;
        };

        if (result) |data| {
            defer ctx.allocator.free(data);
            std.debug.print("[Data] Empfangen ({d}B): {s}\n", .{ data.len, data[0..@min(data.len, 80)] });
        }
    }

    std.debug.print("[Data] Verbindung zu {x} getrennt\n", .{peer_mesh[0..8]});
}
