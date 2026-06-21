const std = @import("std");
const crypto = std.crypto;

const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

pub const CHALLENGE_LEN: usize = 32;
pub const SESSION_KEY_LEN: usize = 32;

pub const EphemeralKeyPair = struct {
    secret: [X25519.secret_length]u8,
    public: [X25519.public_length]u8,
};

pub const HelloMsg = struct {
    ephemeral_pub: [X25519.public_length]u8,
    ed_pub: [32]u8,
    challenge: [CHALLENGE_LEN]u8,
    signature: [Ed25519.Signature.encoded_length]u8,
};

pub const Session = struct {
    conn_id: u64,
    session_key: [SESSION_KEY_LEN]u8,
    peer_mesh: [32]u8,
};

pub fn genEphemeral(io: std.Io) EphemeralKeyPair {
    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();

    var secret: [X25519.secret_length]u8 = undefined;
    rand.bytes(&secret);

    const public = X25519.recoverPublicKey(secret) catch unreachable;

    return EphemeralKeyPair{ .secret = secret, .public = public };
}

pub fn deriveSessionKey(
    own_secret: [X25519.secret_length]u8,
    peer_public: [X25519.public_length]u8,
) ![SESSION_KEY_LEN]u8 {
    const shared = try X25519.scalarmult(own_secret, peer_public);

    const prk = HkdfSha256.extract("", &shared);
    var session_key: [SESSION_KEY_LEN]u8 = undefined;
    HkdfSha256.expand(&session_key, "SIP-session-v1", prk);

    return session_key;
}

pub fn genChallenge(io: std.Io) [CHALLENGE_LEN]u8 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    var challenge: [CHALLENGE_LEN]u8 = undefined;
    rng_src.interface().bytes(&challenge);
    return challenge;
}

pub fn signChallenge(
    ed_keypair: Ed25519.KeyPair,
    challenge: [CHALLENGE_LEN]u8,
) ![Ed25519.Signature.encoded_length]u8 {
    const sig = try ed_keypair.sign(&challenge, null);
    return sig.toBytes();
}

pub fn verifyChallenge(
    ed_pub_bytes: [32]u8,
    challenge: [CHALLENGE_LEN]u8,
    sig_bytes: [Ed25519.Signature.encoded_length]u8,
) bool {
    const pub_key = Ed25519.PublicKey.fromBytes(ed_pub_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(&challenge, pub_key) catch return false;
    return true;
}

pub fn genConnId(io: std.Io) u64 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    return rng_src.interface().int(u64);
}

pub fn signHello(
    ed_keypair: Ed25519.KeyPair,
    ephemeral_pub: [X25519.public_length]u8,
    challenge: [CHALLENGE_LEN]u8,
) ![Ed25519.Signature.encoded_length]u8 {
    var msg: [X25519.public_length + CHALLENGE_LEN]u8 = undefined;
    @memcpy(msg[0..X25519.public_length], &ephemeral_pub);
    @memcpy(msg[X25519.public_length..], &challenge);

    const sig = try ed_keypair.sign(&msg, null);
    return sig.toBytes();
}

pub fn verifyHello(
    ed_pub_bytes: [32]u8,
    ephemeral_pub: [X25519.public_length]u8,
    challenge: [CHALLENGE_LEN]u8,
    sig_bytes: [Ed25519.Signature.encoded_length]u8,
) bool {
    var msg: [X25519.public_length + CHALLENGE_LEN]u8 = undefined;
    @memcpy(msg[0..X25519.public_length], &ephemeral_pub);
    @memcpy(msg[X25519.public_length..], &challenge);

    const pub_key = Ed25519.PublicKey.fromBytes(ed_pub_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(&msg, pub_key) catch return false;
    return true;
}

pub fn peerMeshAddr(ed_pub_bytes: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(&ed_pub_bytes, &out, .{});
    return out;
}

pub fn handshake(
    io: std.Io,
    initiator_ed: Ed25519.KeyPair,
    responder_ed: Ed25519.KeyPair,
) !Session {
    const init_eph = genEphemeral(io);
    const resp_eph = genEphemeral(io);

    const challenge = genChallenge(io);
    const init_pub_bytes = initiator_ed.public_key.toBytes();
    const sig = try signHello(initiator_ed, init_eph.public, challenge);

    const valid = verifyHello(init_pub_bytes, init_eph.public, challenge, sig);
    if (!valid) return error.InvalidSignature;

    const init_key = try deriveSessionKey(init_eph.secret, resp_eph.public);
    const resp_key = try deriveSessionKey(resp_eph.secret, init_eph.public);

    std.debug.assert(std.mem.eql(u8, &init_key, &resp_key));

    const conn_id = genConnId(io);
    const peer_mesh = peerMeshAddr(responder_ed.public_key.toBytes());

    return Session{
        .conn_id = conn_id,
        .session_key = init_key,
        .peer_mesh = peer_mesh,
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    const initiator_ed = Ed25519.KeyPair.generate(io);
    const responder_ed = Ed25519.KeyPair.generate(io);

    std.debug.print("[*] Initiator pub : {x}\n", .{initiator_ed.public_key.toBytes()});
    std.debug.print("[*] Responder pub : {x}\n", .{responder_ed.public_key.toBytes()});

    const session = try handshake(io, initiator_ed, responder_ed);

    std.debug.print("\n[+] Handshake erfolgreich!\n", .{});
    std.debug.print("    conn_id     : {d}\n", .{session.conn_id});
    std.debug.print("    session_key : {x}\n", .{session.session_key});
    std.debug.print("    peer_mesh   : {x}\n", .{session.peer_mesh});
}
