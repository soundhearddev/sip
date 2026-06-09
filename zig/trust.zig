const std = @import("std");
const crypto = std.crypto;
const Ed25519 = crypto.sign.Ed25519;

// ----------------------------
// Typen
// ----------------------------

pub const MAX_NAME_LEN: usize = 64;
pub const INVITE_TOKEN_LEN: usize = Ed25519.Signature.encoded_length; // 64 Bytes

// Infos die ein Peer beim Connect vorlegt
pub const PeerInfo = struct {
    ed_pub: [32]u8,
    mesh_addr: [32]u8,
    name: [MAX_NAME_LEN]u8,
    name_len: usize,
    invite_token: ?InviteToken,

    pub fn nameSlice(self: *const PeerInfo) []const u8 {
        return self.name[0..self.name_len];
    }
};

// Invite Token: signiert vom einladenden Peer
// Inhalt der Signatur: invited_ed_pub (32B)
// Wer hat eingeladen: inviter_ed_pub
pub const InviteToken = struct {
    inviter_ed_pub: [32]u8,
    signature: [INVITE_TOKEN_LEN]u8,
};

// Eintrag im TrustStore
pub const TrustedPeer = struct {
    ed_pub: [32]u8,
    mesh_addr: [32]u8,
    name: [MAX_NAME_LEN]u8,
    name_len: usize,

    // Wer hat diesen Peer eingeladen (null = manuell zugelassen)
    invited_by: ?[32]u8,

    pub fn nameSlice(self: *const TrustedPeer) []const u8 {
        return self.name[0..self.name_len];
    }
};

// Vertrauenskette für Anzeige (max 4 Hops)
const TrustChain = struct {
    hops: [4]?[32]u8 = [_]?[32]u8{null} ** 4,
    len: usize = 0,
};

// ----------------------------
// TrustStore
// Shared zwischen Threads → Mutex geschützt
// ----------------------------
pub const TrustStore = struct {
    peers: std.ArrayList(TrustedPeer),
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = std.Io.Mutex.init,

    pub fn init(io: std.Io, allocator: std.mem.Allocator) TrustStore {
        return .{
            .io = io,
            .peers = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TrustStore) void {
        self.peers.deinit(self.allocator);
    }

    // Ist dieser Public Key bekannt und vertrauenswürdig?
    pub fn isKnown(self: *TrustStore, ed_pub: [32]u8) !bool {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        for (self.peers.items) |peer| {
            if (std.mem.eql(u8, &peer.ed_pub, &ed_pub)) return true;
        }
        return false;
    }

    // Peer nachschlagen
    pub fn get(self: *TrustStore, ed_pub: [32]u8) !?TrustedPeer {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        for (self.peers.items) |peer| {
            if (std.mem.eql(u8, &peer.ed_pub, &ed_pub)) return peer;
        }
        return null;
    }

    // Peer hinzufügen (nach User-Bestätigung)
    pub fn add(self: *TrustStore, peer: TrustedPeer) !void {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        try self.peers.append(self.allocator, peer);
    }

    // Vertrauenskette aufbauen für Anzeige
    fn buildChain(self: *TrustStore, ed_pub: [32]u8) TrustChain {
        var chain = TrustChain{};
        var current = ed_pub;

        // Kette zurückverfolgen (max 4 Hops)
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            var found = false;
            for (self.peers.items) |peer| {
                if (std.mem.eql(u8, &peer.ed_pub, &current)) {
                    if (peer.invited_by) |inviter| {
                        chain.hops[chain.len] = inviter;
                        chain.len += 1;
                        current = inviter;
                        found = true;
                    }
                    break;
                }
            }
            if (!found) break;
        }
        return chain;
    }
};

// ----------------------------
// Invite Token generieren
// Signatur über: invited_ed_pub
// ----------------------------
pub fn generateInvite(
    inviter_keypair: Ed25519.KeyPair,
    invited_ed_pub: [32]u8,
) !InviteToken {
    const sig = try inviter_keypair.sign(&invited_ed_pub, null);
    return InviteToken{
        .inviter_ed_pub = inviter_keypair.public_key.toBytes(),
        .signature = sig.toBytes(),
    };
}

// ----------------------------
// Invite Token verifizieren
// ----------------------------
pub fn verifyInvite(
    token: InviteToken,
    invited_ed_pub: [32]u8,
) bool {
    const pub_key = Ed25519.PublicKey.fromBytes(token.inviter_ed_pub) catch return false;
    const sig = Ed25519.Signature.fromBytes(token.signature);
    sig.verify(&invited_ed_pub, pub_key) catch return false;
    return true;
}

// ----------------------------
// Vertrauenskette als lesbaren String bauen
// ----------------------------
fn formatChain(
    store: *TrustStore,
    chain: TrustChain,
    buf: []u8,
) ![]const u8 {
    if (chain.len == 0) return "(niemand — manuell)";

    var pos: usize = 0;
    var i: usize = 0;
    while (i < chain.len) : (i += 1) {
        const hop_pub = chain.hops[i] orelse break;
        if (try store.get(hop_pub)) |peer| {
            const name = peer.nameSlice();
            if (pos + name.len + 4 < buf.len) {
                @memcpy(buf[pos..][0..name.len], name);
                pos += name.len;
                if (i + 1 < chain.len) {
                    buf[pos] = ' ';
                    pos += 1;
                    buf[pos] = 226;
                    pos += 1; // →
                    buf[pos] = 134;
                    pos += 1;
                    buf[pos] = 146;
                    pos += 1;
                    buf[pos] = ' ';
                    pos += 1;
                }
            }
        }
    }
    return @as([]const u8, buf[0..pos]);
}
// ----------------------------
// User Prompt: Peer annehmen oder ablehnen
//
// Zeigt alle Infos + Invite-Kontext an.
// Wartet auf "j" oder "n" vom User.
// Gibt true zurück wenn angenommen.
// ----------------------------
pub fn requestApproval(
    io: std.Io,
    store: *TrustStore,
    info: PeerInfo,
) !bool {
    const stderr = std.Io.File.stderr();
    var buf: [256]u8 = undefined;
    var w = stderr.writer(io, &buf);
    const out = &w.interface;

    try out.writeAll("\n╔══════════════════════════════════════════════╗\n");
    try out.writeAll("║     NEUER PEER MÖCHTE SICH VERBINDEN         ║\n");
    try out.writeAll("╚══════════════════════════════════════════════╝\n");

    // Name
    try out.print("  Name      : {s}\n", .{info.nameSlice()});

    // Mesh-Adresse
    try out.print("  Mesh-Addr : {x}\n", .{info.mesh_addr});

    // Public Key (erste 16 Bytes anzeigen)
    try out.print("  Public Key: {x}...\n", .{info.ed_pub[0..16]});

    // Invite-Kontext
    if (info.invite_token) |token| {
        if (verifyInvite(token, info.ed_pub)) {
            if (try store.get(token.inviter_ed_pub)) |inviter| {
                // Vertrauenskette aufbauen
                try store.mutex.lock(store.io);
                const chain = store.buildChain(token.inviter_ed_pub);
                store.mutex.unlock(store.io);

                var chain_buf: [256]u8 = undefined;
                const chain_str = try formatChain(store, chain, &chain_buf);

                try out.print("  Eingeladen: {s}\n", .{inviter.nameSlice()});
                if (chain.len > 0) {
                    try out.print("  Kette     : {s}\n", .{chain_str});
                }
            } else {
                // Invite-Token gültig aber Einlader nicht bekannt
                try out.print("  Eingeladen von: unbekanntem Peer ({x}...)\n", .{token.inviter_ed_pub[0..8]});
            }
        } else {
            // Ungültiger Token — warnen
            try out.writeAll("  [!] Invite-Token UNGÜLTIG — Vorsicht!\n");
        }
    } else {
        try out.writeAll("  Eingeladen: (niemand — Direktverbindung)\n");
    }

    try out.writeAll("──────────────────────────────────────────────\n");
    try out.writeAll("  Annehmen? [j/n]: ");
    try w.flush();

    // User Input lesen
    const stdin = std.Io.File.stdin();
    var in_buf: [4]u8 = undefined;
    var reader = stdin.reader(io, &in_buf);

    // Auf erste nicht-whitespace Eingabe warten
    while (true) {
        const line = try reader.interface.takeDelimiter('\n');
        if (line == null) return false;
        const trimmed = std.mem.trim(u8, line.?, " \r\t");
        if (trimmed.len == 0) continue;

        if (std.mem.eql(u8, trimmed, "j") or std.mem.eql(u8, trimmed, "J") or
            std.mem.eql(u8, trimmed, "y") or std.mem.eql(u8, trimmed, "Y"))
        {
            try out.writeAll("  [+] Peer akzeptiert.\n");
            try w.flush();
            return true;
        } else {
            try out.writeAll("  [-] Peer abgelehnt.\n");
            try w.flush();
            return false;
        }
    }
}

// ----------------------------
// Eingehenden Peer verarbeiten:
// 1. Bekannt? → direkt true
// 2. Unbekannt → User fragen
// 3. Wenn ja → in TrustStore aufnehmen
// ----------------------------
pub fn evaluate(
    io: std.Io,
    store: *TrustStore,
    info: PeerInfo,
) !bool {
    // Bereits bekannt → direkt durchlassen
    if (try store.isKnown(info.ed_pub)) return true;

    // User fragen
    const approved = try requestApproval(io, store, info);
    if (!approved) return false;

    // Invite-Einlader bestimmen
    var invited_by: ?[32]u8 = null;
    if (info.invite_token) |token| {
        if (verifyInvite(token, info.ed_pub)) {
            if (try store.isKnown(token.inviter_ed_pub)) {
                invited_by = token.inviter_ed_pub;
            }
        }
    }

    // In TrustStore aufnehmen
    const trusted = TrustedPeer{
        .ed_pub = info.ed_pub,
        .mesh_addr = info.mesh_addr,
        .name = info.name,
        .name_len = info.name_len,
        .invited_by = invited_by,
    };
    try store.add(trusted);

    return true;
}

// ----------------------------
// Demo
// ----------------------------
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var store = TrustStore.init(io, allocator);
    defer store.deinit();

    // Simuliere eingehenden Peer
    const peer_kp = Ed25519.KeyPair.generate(io);
    var name_buf = [_]u8{0} ** MAX_NAME_LEN;
    const name = "laptop-a3f9.mesh";
    @memcpy(name_buf[0..name.len], name);

    const info = PeerInfo{
        .ed_pub = peer_kp.public_key.toBytes(),
        .mesh_addr = peer_kp.public_key.toBytes(),
        .name = name_buf,
        .name_len = name.len,
        .invite_token = null,
    };

    const result = try evaluate(io, &store, info);

    std.debug.print("\nErgebnis: {s}\n", .{if (result) "akzeptiert" else "abgelehnt"});

    std.debug.print("Peers im Store: {d}\n", .{store.peers.items.len});
}
