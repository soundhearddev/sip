const std = @import("std");
const crypto = std.crypto;

pub const PBKDF2_ITERATIONS = 600_000;

pub const ENCRYPTED_PRIVATE_LEN =
    16 + crypto.aead.aes_gcm.Aes256Gcm.nonce_length +
    crypto.aead.aes_gcm.Aes256Gcm.tag_length + 64;

pub const KeyPair = struct {
    public: [32]u8,
    secret: [64]u8,
};

pub const SipError = error{
    DecryptionFailed,
    InvalidLength,
};

pub fn formatSipAddress(buf: []u8, name: []const u8, base: [16]u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}.{x}", .{ name, base });
}

pub fn generateKeyPair(io: std.Io) KeyPair {
    const kp = crypto.sign.Ed25519.KeyPair.generate(io);
    return .{ .public = kp.public_key.toBytes(), .secret = kp.secret_key.toBytes() };
}

pub fn baseAddress(pub_bytes: [32]u8) [16]u8 {
    var out: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(&pub_bytes, &out, .{});
    return out[0..16].*;
}

pub fn genId(pub_bytes: [32]u8, nonce: [16]u8) [32]u8 {
    var h = crypto.hash.sha2.Sha256.init(.{});
    h.update(&pub_bytes);
    h.update(&nonce);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub fn encryptPrivateKey(
    out: *[ENCRYPTED_PRIVATE_LEN]u8,
    secret: [64]u8,
    password: []const u8,
    salt: [16]u8,
    nonce: [crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8,
) !void {
    var aes_key: [32]u8 = undefined;
    try crypto.pwhash.pbkdf2(&aes_key, password, &salt, PBKDF2_ITERATIONS, crypto.auth.hmac.sha2.HmacSha256);

    var tag: [crypto.aead.aes_gcm.Aes256Gcm.tag_length]u8 = undefined;
    var ciphertext: [64]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(&ciphertext, &tag, &secret, "", nonce, aes_key);

    var w: usize = 0;
    @memcpy(out[w .. w + 16], &salt);
    w += 16;
    @memcpy(out[w .. w + nonce.len], &nonce);
    w += nonce.len;
    @memcpy(out[w .. w + tag.len], &tag);
    w += tag.len;
    @memcpy(out[w .. w + ciphertext.len], &ciphertext);
}

pub fn decryptPrivateKey(blob: []const u8, password: []const u8) ![64]u8 {
    if (blob.len != ENCRYPTED_PRIVATE_LEN) return SipError.InvalidLength;

    var r: usize = 0;
    const salt: [16]u8 = blob[r .. r + 16][0..16].*;
    r += 16;
    const nonce_len = crypto.aead.aes_gcm.Aes256Gcm.nonce_length;
    const nonce: [nonce_len]u8 = blob[r .. r + nonce_len][0..nonce_len].*;
    r += nonce_len;
    const tag_len = crypto.aead.aes_gcm.Aes256Gcm.tag_length;
    const tag: [tag_len]u8 = blob[r .. r + tag_len][0..tag_len].*;
    r += tag_len;
    const ciphertext: [64]u8 = blob[r .. r + 64][0..64].*;

    var aes_key: [32]u8 = undefined;
    try crypto.pwhash.pbkdf2(&aes_key, password, &salt, PBKDF2_ITERATIONS, crypto.auth.hmac.sha2.HmacSha256);

    var secret: [64]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(&secret, &ciphertext, tag, "", nonce, aes_key) catch {
        return SipError.DecryptionFailed;
    };
    return secret;
}

pub fn parsePublicKey(bytes: []const u8) ![32]u8 {
    if (bytes.len != 32) return SipError.InvalidLength;
    return bytes[0..32].*;
}

const testing = std.testing;

test "encryptPrivateKey/decryptPrivateKey Roundtrip" {
    const io = std.testing.io;
    const kp = generateKeyPair(io);

    var salt: [16]u8 = undefined;
    io.randomSecure(&salt) catch unreachable;
    var nonce: [crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    io.randomSecure(&nonce) catch unreachable;

    var blob: [ENCRYPTED_PRIVATE_LEN]u8 = undefined;
    try encryptPrivateKey(&blob, kp.secret, "correct horse battery staple", salt, nonce);

    const decrypted = try decryptPrivateKey(&blob, "correct horse battery staple");

    try testing.expectEqualSlices(u8, &kp.secret, &decrypted);
}

test "decryptPrivateKey lehnt falsches Passwort ab" {
    const io = std.testing.io;
    const kp = generateKeyPair(io);

    var salt: [16]u8 = undefined;
    io.randomSecure(&salt) catch unreachable;
    var nonce: [crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    io.randomSecure(&nonce) catch unreachable;

    var blob: [ENCRYPTED_PRIVATE_LEN]u8 = undefined;
    try encryptPrivateKey(&blob, kp.secret, "right-password", salt, nonce);

    try testing.expectError(SipError.DecryptionFailed, decryptPrivateKey(&blob, "wrong-password"));
}

test "decryptPrivateKey lehnt falsche Länge ab" {
    const too_short = [_]u8{0} ** 10;
    try testing.expectError(SipError.InvalidLength, decryptPrivateKey(&too_short, "irrelevant"));
}

test "baseAddress ist deterministisch" {
    const pub_bytes = [_]u8{0xAB} ** 32;
    const a = baseAddress(pub_bytes);
    const b = baseAddress(pub_bytes);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "baseAddress unterscheidet verschiedene Keys" {
    const pub_a = [_]u8{0x01} ** 32;
    const pub_b = [_]u8{0x02} ** 32;
    const addr_a = baseAddress(pub_a);
    const addr_b = baseAddress(pub_b);
    try testing.expect(!std.mem.eql(u8, &addr_a, &addr_b));
}

test "genId ist deterministisch bei gleichem nonce" {
    const pub_bytes = [_]u8{0xCC} ** 32;
    const nonce = [_]u8{0x01} ** 16;
    const id_a = genId(pub_bytes, nonce);
    const id_b = genId(pub_bytes, nonce);
    try testing.expectEqualSlices(u8, &id_a, &id_b);
}

test "genId unterscheidet sich bei verschiedenem nonce" {
    const pub_bytes = [_]u8{0xCC} ** 32;
    const nonce_a = [_]u8{0x01} ** 16;
    const nonce_b = [_]u8{0x02} ** 16;
    const id_a = genId(pub_bytes, nonce_a);
    const id_b = genId(pub_bytes, nonce_b);
    try testing.expect(!std.mem.eql(u8, &id_a, &id_b));
}

test "parsePublicKey akzeptiert 32 Byte" {
    const bytes = [_]u8{0x42} ** 32;
    const pk = try parsePublicKey(&bytes);
    try testing.expectEqualSlices(u8, &bytes, &pk);
}

test "parsePublicKey lehnt falsche Länge ab" {
    const too_short = [_]u8{0} ** 10;
    try testing.expectError(SipError.InvalidLength, parsePublicKey(&too_short));
}

test "formatSipAddress formatiert Name und Hex-Adresse" {
    var buf: [80]u8 = undefined;
    const base = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ++ [_]u8{0x00} ** 12;
    const result = try formatSipAddress(&buf, "alice", base);
    try testing.expect(std.mem.startsWith(u8, result, "alice."));
    try testing.expect(std.mem.indexOf(u8, result, "deadbeef") != null);
}

test "generateKeyPair erzeugt unterschiedliche Keys" {
    const io = std.testing.io;
    const kp_a = generateKeyPair(io);
    const kp_b = generateKeyPair(io);
    try testing.expect(!std.mem.eql(u8, &kp_a.public, &kp_b.public));
}
