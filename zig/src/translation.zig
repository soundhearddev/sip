const std = @import("std");
const header = @import("header.zig");
const frag = @import("fragmentation.zig");

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

// Defensiver Cap fuer die Reassembly: kein Cleanup-Mechanismus (das ist
// Aufgabe des Servers, siehe Design-Rundown), sondern eine harte Grenze,
// damit ein einzelner base_id niemals mehr als diese Anzahl Fragmente im
// Speicher anhaeufen kann - unabhaengig davon, ob die Uebertragung jemals
// abgeschlossen wird. Wird VOR jeder Allokation geprueft, sobald total
// bekannt ist (siehe ReassemblyBuffer.insert).
//
// 4096 Fragmente * CHUNK_SIZE (1200 Byte, siehe fragmentation.zig) ~= 4.9 MB
// pro Nachricht. Anpassen, falls grosse Nachrichten legitim erwartet werden -
// total_fragments im Header ist ein u16, das technische Maximum waere 65535.
pub const MAX_FRAGMENTS_PER_MESSAGE: u32 = 4096;

pub fn encryptFragment(
    io: std.Io,
    allocator: std.mem.Allocator,
    raw_packet: []const u8,
    key: [KEY_SIZE]u8,
) ![]u8 {
    if (raw_packet.len < header.HEADER_SIZE) return error.PacketTooSmall;

    const hdr = raw_packet[0..header.HEADER_SIZE];
    const payload = raw_packet[header.HEADER_SIZE..];

    var nonce: [NONCE_SIZE]u8 = undefined;
    const rng_impl: std.Random.IoSource = .{ .io = io };
    rng_impl.interface().bytes(&nonce);

    const out_len = header.HEADER_SIZE + NONCE_SIZE + payload.len + TAG_SIZE;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    @memcpy(out[0..header.HEADER_SIZE], hdr);
    @memcpy(out[header.HEADER_SIZE..][0..NONCE_SIZE], &nonce);

    const ct_buf = out[header.HEADER_SIZE + NONCE_SIZE ..][0 .. payload.len + TAG_SIZE];

    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ct_buf[0..payload.len],
        ct_buf[payload.len..][0..TAG_SIZE],
        payload,
        hdr,
        nonce,
        key,
    );

    return out;
}

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

    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        out[header.HEADER_SIZE..],
        ciphertext,
        tag,
        hdr,
        nonce,
        key,
    ) catch return error.AuthFailed;

    return out;
}

pub const ReassemblyBuffer = struct {
    map: std.AutoHashMap(u32, FragmentStore),
    allocator: std.mem.Allocator,

    pub const FragmentStore = struct {
        fragments: std.AutoHashMap(u32, []u8),
        // total wird beim allerersten Fragment fuer diesen base_id gesetzt
        // und danach nicht mehr veraendert. Kommt ein spaeteres Fragment mit
        // widersprechendem total an, ist das ein klares Manipulations-/
        // Inkonsistenzsignal -> insert() verwirft es (siehe unten).
        total: u32,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, total: u32) FragmentStore {
            return .{
                .fragments = std.AutoHashMap(u32, []u8).init(allocator),
                .total = total,
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

    /// Fuegt ein Fragment in die Reassembly ein.
    ///
    /// `total` kommt jetzt explizit aus dem Header (parsed.header.total_fragments),
    /// nicht mehr abgeleitet aus (seq + 1) beim letzten Fragment. Das macht
    /// Vollstaendigkeit unabhaengig von der Ankunftsreihenfolge der Fragmente
    /// pruefbar UND erlaubt den Cap-Check unten, bevor irgendetwas fuer einen
    /// neuen base_id alloziert wird.
    ///
    /// Gibt zurueck:
    ///   - null, wenn die Nachricht noch nicht vollstaendig ist
    ///   - die zusammengesetzten Originaldaten, wenn alle Fragmente da sind
    ///
    /// Fehlerfaelle (Paket wird verworfen statt zu crashen):
    ///   - error.TooManyFragments: total > MAX_FRAGMENTS_PER_MESSAGE
    ///   - error.InconsistentTotal: total widerspricht einem bereits
    ///     bekannten total fuer denselben base_id
    ///   - error.InvalidSeq: seq >= total (kann nicht zu dieser Nachricht
    ///     gehoeren)
    pub fn insert(
        self: *ReassemblyBuffer,
        base_id: u32,
        seq: u32,
        total: u32,
        payload: []const u8,
    ) !?[]u8 {
        if (total == 0) return error.InvalidSeq;
        if (total > MAX_FRAGMENTS_PER_MESSAGE) return error.TooManyFragments;
        if (seq >= total) return error.InvalidSeq;

        const result = try self.map.getOrPut(base_id);
        if (!result.found_existing) {
            result.value_ptr.* = FragmentStore.init(self.allocator, total);
        }
        const store = result.value_ptr;

        if (store.total != total) {
            // Widerspruechliches total fuer einen laufenden base_id - entweder
            // Bitfehler/Manipulation oder ein base_id-Wiederverwendungsfehler
            // beim Aufrufer. Wird nicht stillschweigend uebernommen.
            return error.InconsistentTotal;
        }

        const owned = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(owned);

        // Falls fuer diese seq bereits ein Fragment vorliegt (Duplikat/Retransmit),
        // wird das alte freigegeben, statt es stillschweigend zu leaken.
        if (store.fragments.fetchRemove(seq)) |old| {
            self.allocator.free(old.value);
        }
        try store.fragments.put(seq, owned);

        if (store.fragments.count() < store.total) return null;

        // Alle `total` Fragmente sind da (0..total-1, da seq < total oben
        // bereits erzwungen und die Map keine Duplikate haelt).
        var total_len: usize = 0;
        var i: u32 = 0;
        while (i < store.total) : (i += 1) {
            total_len += store.fragments.get(i).?.len;
        }

        const assembled = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(assembled);

        var offset: usize = 0;
        i = 0;
        while (i < store.total) : (i += 1) {
            const piece = store.fragments.get(i).?;
            @memcpy(assembled[offset..][0..piece.len], piece);
            offset += piece.len;
        }

        // Erst nach erfolgreichem Zusammenbau aufraeumen, damit bei einem
        // Fehler oben (z.B. OOM beim assembled-alloc) der Store inklusive
        // aller Fragmente fuer einen erneuten Versuch erhalten bleibt,
        // statt halb aufgeraeumt und halb nicht.
        store.deinit();
        _ = self.map.remove(base_id);

        return assembled;
    }
};

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

pub fn translateInbound(
    allocator: std.mem.Allocator,
    data: []const u8,
    key: [KEY_SIZE]u8,
    buf: *ReassemblyBuffer,
) !?[]u8 {
    const decrypted = try decryptFragment(allocator, data, key);
    defer allocator.free(decrypted);

    const parsed = try header.parsePacket(decrypted);

    const decoded = frag.decodeConnId(parsed.header.conn_id);

    const result = try buf.insert(
        decoded.base_id,
        decoded.seq,
        parsed.header.total_fragments,
        parsed.payload,
    );

    return result;
}

const testing = std.testing;

test "outbound -> inbound roundtrip rekonstruiert die Originaldaten" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x42} ** KEY_SIZE;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    // Groesser als CHUNK_SIZE (1200), damit mehrere Fragmente entstehen.
    const original = "A" ** 3000;

    const packets = try translateOutbound(io, allocator, original, src, dst, 0xAABBCCDD, key);
    defer {
        for (packets) |pkt| allocator.free(pkt);
        allocator.free(packets);
    }

    try testing.expect(packets.len > 1);

    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    var assembled: ?[]u8 = null;
    for (packets) |pkt| {
        const result = try translateInbound(allocator, pkt, key, &buf);
        if (result) |r| {
            try testing.expect(assembled == null);
            assembled = r;
        }
    }

    try testing.expect(assembled != null);
    defer allocator.free(assembled.?);
    try testing.expectEqualSlices(u8, original, assembled.?);
}

test "outbound -> inbound roundtrip funktioniert auch in umgekehrter Fragment-Reihenfolge" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x7A} ** KEY_SIZE;
    const src = [_]u8{0x03} ** 16;
    const dst = [_]u8{0x04} ** 16;

    const original = "B" ** 5000;

    const packets = try translateOutbound(io, allocator, original, src, dst, 0x1122, key);
    defer {
        for (packets) |pkt| allocator.free(pkt);
        allocator.free(packets);
    }

    try testing.expect(packets.len > 1);

    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    // Fragmente in umgekehrter Reihenfolge einspielen - das letzte Fragment
    // (mit total_fragments im Header) kommt also ZUERST an. Das ist genau
    // der Fall, den die alte (seq+1)-Ableitung nicht robust handhaben konnte.
    var assembled: ?[]u8 = null;
    var i: usize = packets.len;
    while (i > 0) {
        i -= 1;
        const result = try translateInbound(allocator, packets[i], key, &buf);
        if (result) |r| {
            try testing.expect(assembled == null);
            assembled = r;
        }
    }

    try testing.expect(assembled != null);
    defer allocator.free(assembled.?);
    try testing.expectEqualSlices(u8, original, assembled.?);
}

test "insert verwirft total von 0 mit InvalidSeq" {
    const allocator = testing.allocator;
    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    try testing.expectError(error.InvalidSeq, buf.insert(1, 0, 0, "x"));
}

test "insert verwirft seq >= total mit InvalidSeq" {
    const allocator = testing.allocator;
    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    try testing.expectError(error.InvalidSeq, buf.insert(1, 5, 5, "x"));
}

test "insert verwirft total ueber MAX_FRAGMENTS_PER_MESSAGE mit TooManyFragments" {
    const allocator = testing.allocator;
    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    try testing.expectError(
        error.TooManyFragments,
        buf.insert(1, 0, MAX_FRAGMENTS_PER_MESSAGE + 1, "x"),
    );
}

test "insert verwirft widerspruechliches total fuer denselben base_id" {
    const allocator = testing.allocator;
    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    // Erstes Fragment fuer base_id=7 legt total=3 fest.
    const r1 = try buf.insert(7, 0, 3, "a");
    try testing.expect(r1 == null);

    // Zweites Fragment behauptet total=99 fuer denselben base_id -> Konflikt.
    try testing.expectError(error.InconsistentTotal, buf.insert(7, 1, 99, "b"));
}

test "insert liefert erst nach dem letzten fehlenden Fragment das Ergebnis" {
    const allocator = testing.allocator;
    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    const r1 = try buf.insert(42, 0, 3, "foo");
    try testing.expect(r1 == null);

    const r2 = try buf.insert(42, 2, 3, "baz");
    try testing.expect(r2 == null);

    const r3 = try buf.insert(42, 1, 3, "bar");
    try testing.expect(r3 != null);
    defer allocator.free(r3.?);

    try testing.expectEqualSlices(u8, "foobarbaz", r3.?);
}

test "insert ersetzt Duplikat-Fragment statt zu leaken" {
    const allocator = testing.allocator;
    var buf = ReassemblyBuffer.init(allocator);
    defer buf.deinit();

    const r1 = try buf.insert(5, 0, 2, "first");
    try testing.expect(r1 == null);

    // seq=0 kommt nochmal an (z.B. Retransmit) mit anderem Inhalt.
    const r2 = try buf.insert(5, 0, 2, "second");
    try testing.expect(r2 == null);

    const r3 = try buf.insert(5, 1, 2, "x");
    try testing.expect(r3 != null);
    defer allocator.free(r3.?);

    // Der zuletzt eingefuegte Wert fuer seq=0 gewinnt.
    try testing.expectEqualSlices(u8, "secondx", r3.?);
}

test "decryptFragment erkennt manipulierte Ciphertext-Bytes" {
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [KEY_SIZE]u8 = [_]u8{0x55} ** KEY_SIZE;
    const src = [_]u8{0x09} ** 16;
    const dst = [_]u8{0x0A} ** 16;

    const original = "manipulier mich nicht";

    const packets = try translateOutbound(io, allocator, original, src, dst, 0x9999, key);
    defer {
        for (packets) |pkt| allocator.free(pkt);
        allocator.free(packets);
    }

    // Ein Byte im Ciphertext-Bereich (nach Header+Nonce) kippen.
    const tamper_offset = header.HEADER_SIZE + NONCE_SIZE;
    packets[0][tamper_offset] ^= 0x01;

    try testing.expectError(error.AuthFailed, decryptFragment(allocator, packets[0], key));
}

test "decryptFragment lehnt zu kurze Pakete ab statt zu crashen" {
    const allocator = testing.allocator;
    const key: [KEY_SIZE]u8 = [_]u8{0x11} ** KEY_SIZE;

    const too_short = [_]u8{0} ** 10;
    try testing.expectError(error.PacketTooSmall, decryptFragment(allocator, &too_short, key));
}
