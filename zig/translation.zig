const std = @import("std");
const header = @import("header.zig");
const frag = @import("fragmentation.zig");

// ----------------------------
// ChaCha20-Poly1305 Konstanten
// ----------------------------
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

// ----------------------------
// Outbound: ein fertiges Fragment verschlüsseln
//
// Eingabe:  roher Puffer [ SIP-Header (48B) | Plaintext-Payload ]
// Ausgabe:  [ SIP-Header (48B) | Nonce (12B) | Ciphertext+Tag ]
//
// Der SIP-Header selbst wird NICHT verschlüsselt — er dient als
// AAD (Additional Authenticated Data) für Poly1305, wird also
// gegen Manipulation geschützt.
// ----------------------------
pub fn encryptFragment(
    io: std.Io,
    allocator: std.mem.Allocator,
    raw_packet: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    if (raw_packet.len < header.HEADER_SIZE) return error.PacketTooSmall;

    const hdr = raw_packet[0..header.HEADER_SIZE];
    const payload = raw_packet[header.HEADER_SIZE..];

    // Zufälliger Nonce via std.Io (0.16.0)
    var nonce: [NONCE_SIZE]u8 = undefined;
    const rng_impl: std.Random.IoSource = .{ .io = io };
    rng_impl.interface().bytes(&nonce);

    // Ausgabepuffer: Header + Nonce + Ciphertext + Tag
    const out_len = header.HEADER_SIZE + NONCE_SIZE + payload.len + TAG_SIZE;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    @memcpy(out[0..header.HEADER_SIZE], hdr);
    @memcpy(out[header.HEADER_SIZE..][0..NONCE_SIZE], &nonce);

    const ct_buf = out[header.HEADER_SIZE + NONCE_SIZE ..][0 .. payload.len + TAG_SIZE];

    // ChaCha20-Poly1305 verschlüsseln
    // ct_buf = ciphertext (payload.len Bytes) + tag (16 Bytes)
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ct_buf[0..payload.len], // ciphertext out
        ct_buf[payload.len..][0..TAG_SIZE], // tag out (*[16]u8)
        payload, // plaintext
        hdr, // AAD = SIP-Header
        nonce,
        key,
    );

    return out;
}

// ----------------------------
// Inbound: ein verschlüsseltes Fragment entschlüsseln
//
// Eingabe:  [ SIP-Header (48B) | Nonce (12B) | Ciphertext+Tag ]
// Ausgabe:  [ SIP-Header (48B) | Plaintext-Payload ]
// ----------------------------
pub fn decryptFragment(
    allocator: std.mem.Allocator,
    data: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    const min_len = header.HEADER_SIZE + NONCE_SIZE + TAG_SIZE;
    if (data.len < min_len) return error.PacketTooSmall;

    const hdr = data[0..header.HEADER_SIZE];
    const nonce = data[header.HEADER_SIZE..][0..NONCE_SIZE].*;
    const ct = data[header.HEADER_SIZE + NONCE_SIZE ..];

    if (ct.len < TAG_SIZE) return error.PacketTooSmall;

    const pt_len = ct.len - TAG_SIZE;
    const ciphertext = ct[0..pt_len];
    const tag = ct[pt_len..][0..TAG_SIZE].*;

    const out = try allocator.alloc(u8, header.HEADER_SIZE + pt_len);
    errdefer allocator.free(out);

    @memcpy(out[0..header.HEADER_SIZE], hdr);

    // Entschlüsseln + Auth-Tag prüfen
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        out[header.HEADER_SIZE..], // plaintext out
        ciphertext,
        tag,
        hdr, // AAD = SIP-Header
        nonce,
        key,
    ) catch return error.AuthFailed;

    return out;
}

// ----------------------------
// Reassembly Buffer
// Sammelt Fragmente pro conn_id bis alle da sind
// ----------------------------
pub const ReassemblyBuffer = struct {
    // conn_id (base 32-bit) → ArrayList von (seq, payload-slice)
    map: std.AutoHashMap(u32, FragmentStore),
    allocator: std.mem.Allocator,

    pub const FragmentStore = struct {
        fragments: std.AutoHashMap(u32, []u8),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) FragmentStore {
            return .{
                .fragments = std.AutoHashMap(u32, []u8).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *FragmentStore) void {
            var it = self.fragments.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
            }
            self.fragments.deinit();
        }
    };

    pub fn init(allocator: std.mem.Allocator) ReassemblyBuffer {
        return .{
            .map = std.AutoHashMap(u32, FragmentStore).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ReassemblyBuffer) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.map.deinit();
    }

    // Fragment einfügen. Gibt reassemblierten Payload zurück wenn vollständig,
    // sonst null.
    pub fn insert(
        self: *ReassemblyBuffer,
        base_id: u32,
        seq: u32,
        is_last: bool,
        payload: []const u8,
    ) !?[]u8 {
        // Store holen oder neu anlegen
        const result = try self.map.getOrPut(base_id);
        if (!result.found_existing) {
            result.value_ptr.* = FragmentStore.init(self.allocator);
        }
        const store = result.value_ptr;

        // Payload kopieren und speichern
        const owned = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(owned);
        try store.fragments.put(seq, owned);

        // Nur reassemblieren wenn letztes Fragment angekommen ist
        if (!is_last) return null;

        // Prüfen ob alle Sequenznummern 0..seq vorhanden sind
        const total = seq + 1;
        var i: u32 = 0;
        while (i < total) : (i += 1) {
            if (!store.fragments.contains(i)) return null; // noch nicht vollständig
        }

        // Reassemblieren
        var total_len: usize = 0;
        i = 0;
        while (i < total) : (i += 1) {
            total_len += store.fragments.get(i).?.len;
        }

        const assembled = try self.allocator.alloc(u8, total_len);
        var offset: usize = 0;
        i = 0;
        while (i < total) : (i += 1) {
            const piece = store.fragments.get(i).?;
            @memcpy(assembled[offset..][0..piece.len], piece);
            offset += piece.len;
        }

        // Store aufräumen
        store.deinit();
        _ = self.map.remove(base_id);

        return assembled;
    }
};

// ----------------------------
// Outbound Pipeline:
// Rohdaten → Fragmente → verschlüsselte SIP-Pakete
//
// Gibt eine Liste von verschlüsselten Paketen zurück.
// Jedes Paket ist bereit zum Senden über TCP/UDP.
//
// Multipath: aktuell nicht implementiert — path_id Platzhalter vorhanden.
// Später: src_addresses[] übergeben, derive_path_order() nutzen.
// ----------------------------
pub fn translateOutbound(
    io: std.Io,
    allocator: std.mem.Allocator,
    data: []const u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
    key: [KEY_SIZE]u8,
) ![][]u8 {
    const fragments = try frag.fragmentData(allocator, data, src, dst, conn_id);
    defer fragments.deinit();

    const out = try allocator.alloc([]u8, fragments.items.len);
    errdefer {
        for (out) |pkt| allocator.free(pkt);
        allocator.free(out);
    }

    for (fragments.items, 0..) |f, i| {
        out[i] = try encryptFragment(io, allocator, f.data, key);
    }

    return out;
}

// ----------------------------
// Inbound Pipeline:
// Verschlüsseltes Paket → entschlüsseln → Fragment buffern → ggf. Payload zurück
// ----------------------------
pub fn translateInbound(
    allocator: std.mem.Allocator,
    data: []const u8,
    key: [KEY_SIZE]u8,
    buf: *ReassemblyBuffer,
) !?[]u8 {
    // 1. Entschlüsseln
    const decrypted = try decryptFragment(allocator, data, key);
    defer allocator.free(decrypted);

    // 2. SIP-Header parsen
    const parsed = try header.parsePacket(decrypted);

    // 3. conn_id dekodieren → seq, flags
    const decoded = frag.decodeConnId(parsed.header.conn_id);
    const is_last = frag.isLastFragment(parsed.header.conn_id);

    // 4. In Reassembly-Buffer einfügen
    const result = try buf.insert(
        decoded.base_id,
        decoded.seq,
        is_last,
        parsed.payload,
    );

    return result;
}
