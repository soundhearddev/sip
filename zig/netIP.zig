const std = @import("std");
const Io = std.Io;
const crypto = std.crypto;

const KEY_DIR = "./keys";
const PRIVATE_FILE = "keys/private.key";
const PUBLIC_FILE = "keys/public.key";
const PBKDF2_ITERATIONS = 600_000;

const KeyPair = struct {
    public: [32]u8,
    secret: [64]u8,
};

const KeyError = error{
    DecryptionFailed,
};

pub fn loadOrCreateKeys(io: std.Io, password: []const u8) !KeyPair {
    const cwd = Io.Dir.cwd();
    cwd.createDirPath(io, KEY_DIR) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const priv_exists = if (cwd.openFile(io, PRIVATE_FILE, .{})) |f| blk: {
        f.close(io);
        break :blk true;
    } else |_| false;
    const pub_exists = if (cwd.openFile(io, PUBLIC_FILE, .{})) |f| blk: {
        f.close(io);
        break :blk true;
    } else |_| false;
    if (priv_exists and pub_exists) {
        return loadKeys(io, password);
    } else {
        return createKeys(io, password);
    }
}

fn createKeys(io: std.Io, password: []const u8) !KeyPair {
    std.debug.print("[*] Erzeuge neue Schlüssel...\n", .{});

    const kp = crypto.sign.Ed25519.KeyPair.generate(io);
    const pub_bytes = kp.public_key.toBytes();
    const sec_bytes = kp.secret_key.toBytes();

    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();

    var salt: [16]u8 = undefined;
    var nonce: [crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    rand.bytes(&salt);
    rand.bytes(&nonce);

    var aes_key: [32]u8 = undefined;
    try crypto.pwhash.pbkdf2(&aes_key, password, &salt, PBKDF2_ITERATIONS, crypto.auth.hmac.sha2.HmacSha256);

    var encrypted_priv: [64]u8 = undefined;
    var tag: [crypto.aead.aes_gcm.Aes256Gcm.tag_length]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(&encrypted_priv, &tag, &sec_bytes, "", nonce, aes_key);

    const cwd = Io.Dir.cwd();
    {
        const f = try cwd.createFile(io, PRIVATE_FILE, .{});
        defer f.close(io);
        const rc = std.os.linux.syscall2(.fchmod, @intCast(f.handle), 0o600);
        if (rc != 0) return error.ChmodFailed;
        var buf: [256]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&salt);
        try w.interface.writeAll(&nonce);
        try w.interface.writeAll(&tag);
        try w.interface.writeAll(&encrypted_priv);
        try w.flush();
    }
    {
        // FIX: createFile statt openFile — public key schreiben nicht lesen
        const f = try cwd.createFile(io, PUBLIC_FILE, .{});
        defer f.close(io);
        const rc = std.os.linux.syscall2(.fchmod, @intCast(f.handle), 0o644);
        if (rc != 0) return error.ChmodFailed;
        var buf: [64]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&pub_bytes);
        try w.flush();
    }

    std.debug.print("[+] Keys gespeichert\n", .{});
    return KeyPair{ .public = pub_bytes, .secret = sec_bytes };
}

fn loadKeys(io: std.Io, password: []const u8) !KeyPair {
    std.debug.print("[*] Lade bestehende Schlüssel...\n", .{});

    var salt: [16]u8 = undefined;
    var nonce: [crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    var tag: [crypto.aead.aes_gcm.Aes256Gcm.tag_length]u8 = undefined;
    var encrypted_priv: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;

    const cwd = Io.Dir.cwd();
    {
        const f = try cwd.openFile(io, PRIVATE_FILE, .{});
        defer f.close(io);
        var raw: [108]u8 = undefined;
        _ = try f.readPositionalAll(io, &raw, 0);
        salt = raw[0..16].*;
        nonce = raw[16..28].*;
        tag = raw[28..44].*;
        encrypted_priv = raw[44..108].*;
    }
    {
        const f = try cwd.openFile(io, PUBLIC_FILE, .{});
        defer f.close(io);
        _ = try f.readPositionalAll(io, &pub_bytes, 0);
    }

    var aes_key: [32]u8 = undefined;
    try crypto.pwhash.pbkdf2(&aes_key, password, &salt, PBKDF2_ITERATIONS, crypto.auth.hmac.sha2.HmacSha256);

    var sec_bytes: [64]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(&sec_bytes, &encrypted_priv, tag, "", nonce, aes_key) catch {
        std.debug.print("[!] Falsches Passwort oder beschädigte Keys\n", .{});
        return KeyError.DecryptionFailed;
    };

    return KeyPair{ .public = pub_bytes, .secret = sec_bytes };
}

pub fn baseAddress(pub_bytes: [32]u8) [32]u8 {
    var out: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(&pub_bytes, &out, .{});
    return out;
}

pub fn genId(io: std.Io, pub_bytes: [32]u8) [32]u8 {
    var nonce: [16]u8 = undefined;
    const rng_src: std.Random.IoSource = .{ .io = io };
    rng_src.interface().bytes(&nonce);

    var h = crypto.hash.sha2.Sha256.init(.{});
    h.update(&pub_bytes);
    h.update(&nonce);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const password = "MeinSuperSicheresMeshPasswort!";
    const kp = try loadOrCreateKeys(io, password);
    const addr = baseAddress(kp.public);
    std.debug.print("Public Key   : {x}\n", .{kp.public});
    std.debug.print("Basis-Addr   : {x}\n", .{addr});
    const id = genId(io, kp.public);
    std.debug.print("Generierte ID: {x}\n", .{id});
}
