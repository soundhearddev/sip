const std = @import("std");
const identity = @import("identity.zig");

const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const PUBLIC_KEY_SIZE = X25519.public_length;
pub const SECRET_KEY_SIZE = X25519.secret_length;
pub const SIGNATURE_SIZE = Ed25519.Signature.encoded_length;
pub const IDENTITY_PUBLIC_KEY_SIZE = 32;
pub const DERIVED_KEY_SIZE = 32;
pub const SIP_ADDRESS_SIZE = 16;

pub const KeyExchangeError = error{
    InvalidPeerPublicKey,
    InvalidPeerSignature,
    IdentityMismatch,
} || identity.SipError;

pub const EphemeralKeyPair = struct {
    secret_key: [SECRET_KEY_SIZE]u8,
    public_key: [PUBLIC_KEY_SIZE]u8,

    pub fn generate(io: std.Io) !EphemeralKeyPair {
        var secret_key: [SECRET_KEY_SIZE]u8 = undefined;
        try io.randomSecure(&secret_key);
        const public_key = try X25519.recoverPublicKey(secret_key);
        return .{ .secret_key = secret_key, .public_key = public_key };
    }

    pub fn deinit(self: *EphemeralKeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key);
    }
};

pub const HandshakeMessage = struct {
    identity_public_key: [IDENTITY_PUBLIC_KEY_SIZE]u8,
    ephemeral_public_key: [PUBLIC_KEY_SIZE]u8,
    signature: [SIGNATURE_SIZE]u8,

    const Self = @This();

    pub fn create(keys: identity.KeyPair, ephemeral: EphemeralKeyPair) !Self {
        const sk = try Ed25519.SecretKey.fromBytes(keys.secret);
        const kp = try Ed25519.KeyPair.fromSecretKey(sk);
        const sig = try kp.sign(&ephemeral.public_key, null);
        return .{
            .identity_public_key = keys.public,
            .ephemeral_public_key = ephemeral.public_key,
            .signature = sig.toBytes(),
        };
    }

    pub fn verify(self: Self) KeyExchangeError!void {
        const pk = Ed25519.PublicKey.fromBytes(self.identity_public_key) catch {
            return KeyExchangeError.InvalidPeerPublicKey;
        };
        const sig = Ed25519.Signature.fromBytes(self.signature);
        sig.verify(&self.ephemeral_public_key, pk) catch {
            return KeyExchangeError.InvalidPeerSignature;
        };
    }

    pub fn peerAddress(self: Self) [SIP_ADDRESS_SIZE]u8 {
        return identity.baseAddress(self.identity_public_key);
    }
};

pub const SessionKeys = struct {
    tx: [DERIVED_KEY_SIZE]u8,
    rx: [DERIVED_KEY_SIZE]u8,
    peer_address: [SIP_ADDRESS_SIZE]u8,
    conn_id: u64,

    pub fn deinit(self: *SessionKeys) void {
        std.crypto.secureZero(u8, &self.tx);
        std.crypto.secureZero(u8, &self.rx);
    }
};

pub fn completeHandshake(
    local_keys: identity.KeyPair,
    local_address: [SIP_ADDRESS_SIZE]u8,
    local_ephemeral: EphemeralKeyPair,
    peer_message: HandshakeMessage,
    expected_peer_address: ?[SIP_ADDRESS_SIZE]u8,
) KeyExchangeError!SessionKeys {
    try peer_message.verify();

    const peer_address = peer_message.peerAddress();
    if (expected_peer_address) |expected| {
        if (!std.mem.eql(u8, &expected, &peer_address)) {
            return KeyExchangeError.IdentityMismatch;
        }
    }

    const shared_secret = X25519.scalarmult(
        local_ephemeral.secret_key,
        peer_message.ephemeral_public_key,
    ) catch {
        return KeyExchangeError.InvalidPeerPublicKey;
    };

    _ = local_keys;

    var transcript: [SIP_ADDRESS_SIZE * 2 + PUBLIC_KEY_SIZE * 2]u8 = undefined;
    const a_first = std.mem.lessThan(u8, &local_address, &peer_address);

    if (a_first) {
        @memcpy(transcript[0..16], &local_address);
        @memcpy(transcript[16..32], &peer_address);
        @memcpy(transcript[32..64], &local_ephemeral.public_key);
        @memcpy(transcript[64..96], &peer_message.ephemeral_public_key);
    } else {
        @memcpy(transcript[0..16], &peer_address);
        @memcpy(transcript[16..32], &local_address);
        @memcpy(transcript[32..64], &peer_message.ephemeral_public_key);
        @memcpy(transcript[64..96], &local_ephemeral.public_key);
    }

    const prk = HkdfSha256.extract(&transcript, &shared_secret);

    var key_a_to_b: [DERIVED_KEY_SIZE]u8 = undefined;
    var key_b_to_a: [DERIVED_KEY_SIZE]u8 = undefined;
    HkdfSha256.expand(&key_a_to_b, "sip-handshake a->b", prk);
    HkdfSha256.expand(&key_b_to_a, "sip-handshake b->a", prk);

    var conn_id_bytes: [8]u8 = undefined;
    HkdfSha256.expand(&conn_id_bytes, "sip-handshake conn-id", prk);
    const conn_id = std.mem.readInt(u64, &conn_id_bytes, .big);

    const tx = if (a_first) key_a_to_b else key_b_to_a;
    const rx = if (a_first) key_b_to_a else key_a_to_b;

    return .{
        .tx = tx,
        .rx = rx,
        .peer_address = peer_address,
        .conn_id = conn_id,
    };
}

test "handshake derives matching, opposite-direction session keys" {
    const io = std.testing.io;

    var alice_eph = try EphemeralKeyPair.generate(io);
    defer alice_eph.deinit();
    var bob_eph = try EphemeralKeyPair.generate(io);
    defer bob_eph.deinit();

    const alice_id_kp = Ed25519.KeyPair.generate(io);
    const bob_id_kp = Ed25519.KeyPair.generate(io);

    const alice_keys = identity.KeyPair{
        .public = alice_id_kp.public_key.toBytes(),
        .secret = alice_id_kp.secret_key.toBytes(),
    };
    const bob_keys = identity.KeyPair{
        .public = bob_id_kp.public_key.toBytes(),
        .secret = bob_id_kp.secret_key.toBytes(),
    };

    const alice_address = identity.baseAddress(alice_keys.public);
    const bob_address = identity.baseAddress(bob_keys.public);

    const msg_from_alice = try HandshakeMessage.create(alice_keys, alice_eph);
    const msg_from_bob = try HandshakeMessage.create(bob_keys, bob_eph);

    var alice_session = try completeHandshake(alice_keys, alice_address, alice_eph, msg_from_bob, bob_address);
    defer alice_session.deinit();
    var bob_session = try completeHandshake(bob_keys, bob_address, bob_eph, msg_from_alice, alice_address);
    defer bob_session.deinit();

    try std.testing.expectEqualSlices(u8, &alice_session.tx, &bob_session.rx);
    try std.testing.expectEqualSlices(u8, &alice_session.rx, &bob_session.tx);
    try std.testing.expectEqualSlices(u8, &alice_session.peer_address, &bob_address);
    try std.testing.expectEqualSlices(u8, &bob_session.peer_address, &alice_address);
}

test "tampered ephemeral key fails signature verification" {
    const io = std.testing.io;

    var eph = try EphemeralKeyPair.generate(io);
    defer eph.deinit();

    const id_kp = Ed25519.KeyPair.generate(io);
    const keys = identity.KeyPair{
        .public = id_kp.public_key.toBytes(),
        .secret = id_kp.secret_key.toBytes(),
    };

    var msg = try HandshakeMessage.create(keys, eph);
    msg.ephemeral_public_key[0] ^= 0xff;

    try std.testing.expectError(KeyExchangeError.InvalidPeerSignature, msg.verify());
}

test "unexpected peer identity is rejected" {
    const io = std.testing.io;

    var alice_eph = try EphemeralKeyPair.generate(io);
    defer alice_eph.deinit();
    var mallory_eph = try EphemeralKeyPair.generate(io);
    defer mallory_eph.deinit();

    const alice_id_kp = Ed25519.KeyPair.generate(io);
    const mallory_id_kp = Ed25519.KeyPair.generate(io);

    const alice_keys = identity.KeyPair{
        .public = alice_id_kp.public_key.toBytes(),
        .secret = alice_id_kp.secret_key.toBytes(),
    };
    const mallory_keys = identity.KeyPair{
        .public = mallory_id_kp.public_key.toBytes(),
        .secret = mallory_id_kp.secret_key.toBytes(),
    };

    const alice_address = identity.baseAddress(alice_keys.public);
    const msg_from_mallory = try HandshakeMessage.create(mallory_keys, mallory_eph);

    const bob_id_kp = Ed25519.KeyPair.generate(io);
    const expected_bob_address = identity.baseAddress(bob_id_kp.public_key.toBytes());

    try std.testing.expectError(
        KeyExchangeError.IdentityMismatch,
        completeHandshake(alice_keys, alice_address, alice_eph, msg_from_mallory, expected_bob_address),
    );
}
