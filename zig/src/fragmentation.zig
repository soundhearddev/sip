// DEPRECATED

const std = @import("std");
const header = @import("header.zig");

pub const CHUNK_SIZE: usize = 1200;

pub const FLAG_LAST: u8 = 0x08;

// total_fragments im Header (header.zig) ist ein u16 - das ist die obere
// Grenze fuer total_chunks, die fragmentData ohne Datenverlust signalisieren
// kann. Als eigene Konstante exponiert, damit Tests die Schwelle direkt
// pruefen koennen, statt die Formel zu duplizieren.
pub const MAX_TOTAL_CHUNKS: usize = std.math.maxInt(u16);

pub const Fragment = struct {
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Fragment) void {
        self.allocator.free(self.data);
    }
};

pub const FragmentList = struct {
    items: []Fragment,
    allocator: std.mem.Allocator,

    pub fn deinit(self: FragmentList) void {
        for (self.items) |frag| {
            frag.deinit();
        }
        self.allocator.free(self.items);
    }
};

pub fn fragmentData(
    allocator: std.mem.Allocator,
    data: []const u8,
    src: [16]u8,
    dst: [16]u8,
    conn_id: u64,
) !FragmentList {
    const total_chunks = (data.len + CHUNK_SIZE - 1) / CHUNK_SIZE;

    // total_fragments im Header ist ein u16 (siehe header.zig). Eine Nachricht,
    // die mehr als 65535 Fragmente braeuchte, kann nicht mehr verlustfrei
    // signalisiert werden -> expliziter Fehler statt @intCast-Panic.
    if (total_chunks > MAX_TOTAL_CHUNKS) return error.MessageTooLarge;

    const fragments = try allocator.alloc(Fragment, total_chunks);
    errdefer allocator.free(fragments);

    for (0..total_chunks) |seq| {
        const start = seq * CHUNK_SIZE;
        const end = @min(start + CHUNK_SIZE, data.len);
        const chunk = data[start..end];

        const is_last = (seq == total_chunks - 1);
        const flags: u8 = if (is_last) FLAG_LAST else 0x00;

        const buf = try allocator.alloc(u8, header.HEADER_SIZE + chunk.len);
        errdefer allocator.free(buf);

        const pkt = try header.buildPacket(
            buf,
            src,
            dst,
            conn_id,
            .data,
            chunk,
            @intCast(total_chunks),
        );

        const encoded_conn_id: u64 =
            (conn_id & 0x00000000FFFFFFFF) |
            (@as(u64, @intCast(seq)) << 32) |
            (@as(u64, flags) << 56);

        std.mem.writeInt(u64, buf[34..42], encoded_conn_id, .little);

        _ = pkt;

        fragments[seq] = Fragment{
            .data = buf,
            .allocator = allocator,
        };
    }

    return FragmentList{
        .items = fragments,
        .allocator = allocator,
    };
}

pub const DecodedConnId = struct {
    base_id: u32,
    seq: u32,
    flags: u8,
};

pub fn decodeConnId(conn_id: u64) DecodedConnId {
    return DecodedConnId{
        .base_id = @truncate(conn_id & 0x00000000FFFFFFFF),
        .seq = @truncate((conn_id >> 32) & 0x00FFFFFF),
        .flags = @truncate((conn_id >> 56) & 0xFF),
    };
}

pub fn isLastFragment(conn_id: u64) bool {
    const decoded = decodeConnId(conn_id);
    return (decoded.flags & FLAG_LAST) != 0;
}

const testing = std.testing;

test "fragmentData erzeugt genau ein Fragment bei Daten unter CHUNK_SIZE" {
    const allocator = testing.allocator;
    const src = [_]u8{0x01} ** 16;
    const dst = [_]u8{0x02} ** 16;

    const data = "kurze nachricht";
    const list = try fragmentData(allocator, data, src, dst, 0x1234);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.items.len);

    const parsed = try header.parsePacket(list.items[0].data);
    try testing.expectEqual(@as(u16, 1), parsed.header.total_fragments);
    try testing.expectEqualSlices(u8, data, parsed.payload);

    const decoded = decodeConnId(parsed.header.conn_id);
    try testing.expectEqual(@as(u32, 0), decoded.seq);
    try testing.expect(isLastFragment(parsed.header.conn_id));
}

test "fragmentData erzeugt mehrere Fragmente bei Daten ueber CHUNK_SIZE" {
    const allocator = testing.allocator;
    const src = [_]u8{0x03} ** 16;
    const dst = [_]u8{0x04} ** 16;

    // 2 volle Chunks + ein angebrochener dritter.
    const data = [_]u8{0xAB} ** (CHUNK_SIZE * 2 + 500);
    const list = try fragmentData(allocator, &data, src, dst, 0xABCD);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 3), list.items.len);

    var total_payload_len: usize = 0;
    for (list.items, 0..) |f, i| {
        const parsed = try header.parsePacket(f.data);

        // Jedes Fragment muss denselben total_fragments-Wert tragen,
        // unabhaengig davon, an welcher Position es steht.
        try testing.expectEqual(@as(u16, 3), parsed.header.total_fragments);

        const decoded = decodeConnId(parsed.header.conn_id);
        try testing.expectEqual(@as(u32, @intCast(i)), decoded.seq);

        const expected_last = (i == list.items.len - 1);
        try testing.expectEqual(expected_last, isLastFragment(parsed.header.conn_id));

        total_payload_len += parsed.payload.len;
    }

    try testing.expectEqual(data.len, total_payload_len);
    // Alle Fragmente bis auf das letzte muessen exakt CHUNK_SIZE gross sein.
    for (list.items[0 .. list.items.len - 1]) |f| {
        const parsed = try header.parsePacket(f.data);
        try testing.expectEqual(CHUNK_SIZE, parsed.payload.len);
    }
}

test "fragmentData erzeugt exakt ein Fragment wenn Daten genau CHUNK_SIZE gross sind" {
    const allocator = testing.allocator;
    const src = [_]u8{0x05} ** 16;
    const dst = [_]u8{0x06} ** 16;

    const data = [_]u8{0xCD} ** CHUNK_SIZE;
    const list = try fragmentData(allocator, &data, src, dst, 0x1);
    defer list.deinit();

    // Off-by-one-Falle: data.len == CHUNK_SIZE darf NICHT zwei Fragmente
    // erzeugen (eines voll, eines leer).
    try testing.expectEqual(@as(usize, 1), list.items.len);

    const parsed = try header.parsePacket(list.items[0].data);
    try testing.expectEqual(@as(u16, 1), parsed.header.total_fragments);
    try testing.expectEqual(CHUNK_SIZE, parsed.payload.len);
    try testing.expect(isLastFragment(parsed.header.conn_id));
}

test "fragmentData erzeugt null Fragmente bei leeren Daten" {
    const allocator = testing.allocator;
    const src = [_]u8{0x07} ** 16;
    const dst = [_]u8{0x08} ** 16;

    const data: []const u8 = "";
    const list = try fragmentData(allocator, data, src, dst, 0x1);
    defer list.deinit();

    // Randfall: (0 + CHUNK_SIZE - 1) / CHUNK_SIZE == 0 -> kein Fragment wird
    // erzeugt. Das ist hier dokumentiert, damit es nicht als uebersehener
    // Bug erscheint - Aufrufer, die leere Nachrichten senden wollen, muessen
    // das gesondert behandeln, fragmentData allein verschickt dafuer nichts.
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "decodeConnId extrahiert base_id, seq und flags korrekt" {
    const base_id: u32 = 0xDEADBEEF;
    const seq: u32 = 0x00ABCDEF; // 24 Bit, passt in das seq-Feld
    const flags: u8 = FLAG_LAST;

    const conn_id: u64 =
        (@as(u64, base_id)) |
        (@as(u64, seq) << 32) |
        (@as(u64, flags) << 56);

    const decoded = decodeConnId(conn_id);
    try testing.expectEqual(base_id, decoded.base_id);
    try testing.expectEqual(seq, decoded.seq);
    try testing.expectEqual(flags, decoded.flags);
    try testing.expect(isLastFragment(conn_id));
}

test "decodeConnId maskiert seq korrekt auf 24 Bit" {
    // Bit 24 (0x01000000) liegt ausserhalb des 24-Bit-seq-Feldes und damit
    // bereits im flags-Bereich - decodeConnId darf es nicht in seq lesen.
    const conn_id: u64 = (@as(u64, 0x01ABCDEF) << 32);

    const decoded = decodeConnId(conn_id);
    try testing.expectEqual(@as(u32, 0x00ABCDEF), decoded.seq);
}

test "isLastFragment ist false ohne FLAG_LAST" {
    const conn_id: u64 = (@as(u64, 5) << 32); // seq=5, flags=0
    try testing.expect(!isLastFragment(conn_id));
}

test "fragmentData gibt MessageTooLarge zurueck wenn total_chunks die u16-Grenze ueberschreiten wuerde" {
    const allocator = testing.allocator;
    const src = [_]u8{0x09} ** 16;
    const dst = [_]u8{0x0A} ** 16;

    // Daten, die genau einen Chunk mehr als MAX_TOTAL_CHUNKS ergeben.
    // Das sind ~78 MB - bewusst real alloziert (statt nur die Formel
    // nachzurechnen), damit dieser Test den tatsaechlichen Code-Pfad in
    // fragmentData() ausloest und nicht nur die Arithmetik dupliziert.
    const len = (MAX_TOTAL_CHUNKS + 1) * CHUNK_SIZE;
    const data = try allocator.alloc(u8, len);
    defer allocator.free(data);

    try testing.expectError(
        error.MessageTooLarge,
        fragmentData(allocator, data, src, dst, 0x1),
    );
}

test "Grenzformel fuer total_chunks ist inklusiv bei MAX_TOTAL_CHUNKS" {
    // Direkter Nachweis, dass die Bedingung in fragmentData()
    // (total_chunks > MAX_TOTAL_CHUNKS) bei total_chunks == MAX_TOTAL_CHUNKS
    // NICHT ausgeloest wird (Grenze ist inklusiv), ohne dafuer real
    // MAX_TOTAL_CHUNKS einzelne Fragment-Allokationen zu durchlaufen.
    // Die Formel selbst ist identisch mit der in fragmentData() verwendeten;
    // der vorangehende Test "gibt MessageTooLarge zurueck" bestaetigt bereits,
    // dass der echte Code-Pfad bei +1 darueber tatsaechlich abbricht.
    const len_at_limit = MAX_TOTAL_CHUNKS * CHUNK_SIZE;
    const total_chunks_at_limit = (len_at_limit + CHUNK_SIZE - 1) / CHUNK_SIZE;

    try testing.expectEqual(MAX_TOTAL_CHUNKS, total_chunks_at_limit);
    try testing.expect(!(total_chunks_at_limit > MAX_TOTAL_CHUNKS));
}
