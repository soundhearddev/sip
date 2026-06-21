const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const PUBLIC_KEY_SIZE: usize = X25519.public_length;
pub const SECRET_KEY_SIZE: usize = X25519.secret_length;
pub const DERIVED_KEY_SIZE: usize = 32;

pub const KeyExchangeError = error{
    InvalidPeerPublicKey,
};

pub const LocalKeyPair = struct {
    secret_key: [SECRET_KEY_SIZE]u8,
    public_key: [PUBLIC_KEY_SIZE]u8,
};

pub fn generateLocalKeyPair(io: std.Io) !LocalKeyPair {
    var secret_key: [SECRET_KEY_SIZE]u8 = undefined;
    try std.Io.randomSecure(io, &secret_key);

    const public_key = try X25519.recoverPublicKey(secret_key);

    return LocalKeyPair{
        .secret_key = secret_key,
        .public_key = public_key,
    };
}

pub fn deriveSharedKey(
    local: LocalKeyPair,
    peer_public_key: [PUBLIC_KEY_SIZE]u8,
) KeyExchangeError![DERIVED_KEY_SIZE]u8 {
    const shared_secret = X25519.scalarmult(local.secret_key, peer_public_key) catch {
        return error.InvalidPeerPublicKey;
    };

    var derived_key: [DERIVED_KEY_SIZE]u8 = undefined;
    const prk = HkdfSha256.extract(&.{}, &shared_secret);
    HkdfSha256.expand(&derived_key, "sip-tcp-test", prk);

    return derived_key;
}
