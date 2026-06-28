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
