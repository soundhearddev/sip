const std = @import("std");
pub const Io = std.Io;
const crypto = std.crypto;

pub const KEY_ROOT = "keys";
pub const PBKDF2_ITERATIONS = 600_000;

pub const KeyPair = struct {
    public: [32]u8,
    secret: [64]u8,
};

pub const SipError = error{
    DecryptionFailed,
    IdentityNotFound,
    IdentityAlreadyExists,
    InvalidName,
    PasswordMismatch,
    ChmodFailed,
};

pub const IdentityEntry = struct {
    name_buf: [64]u8,
    name_len: usize,
    public: [32]u8,
    valid: bool,

    pub fn name(self: *const IdentityEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub fn identityDir(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ KEY_ROOT, name });
}

pub fn privatePath(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/private.key", .{ KEY_ROOT, name });
}

pub fn publicPath(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/public.key", .{ KEY_ROOT, name });
}

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        if (!ok) return false;
    }
    return true;
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

pub fn formatSipAddress(buf: []u8, base: [32]u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "sip1{x}", .{base[0..20]});
}

// ---------------------------------------------------------------------
// Key creation / loading / deletion
// ---------------------------------------------------------------------

pub fn createIdentity(io: std.Io, name: []const u8, password: []const u8) !KeyPair {
    if (identityExists(io, name)) return SipError.IdentityAlreadyExists;

    const kp = crypto.sign.Ed25519.KeyPair.generate(io);
    const pub_bytes = kp.public_key.toBytes();
    const sec_bytes = kp.secret_key.toBytes();

    return try storeIdentity(io, name, .{ .public = pub_bytes, .secret = sec_bytes }, password);
}

pub fn loadIdentity(io: std.Io, name: []const u8, password: []const u8) !KeyPair {
    var priv_path_buf: [300]u8 = undefined;
    var pub_path_buf: [300]u8 = undefined;
    const priv_path = try privatePath(&priv_path_buf, name);
    const pub_path = try publicPath(&pub_path_buf, name);

    const cwd = Io.Dir.cwd();

    var salt: [16]u8 = undefined;
    var nonce: [crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    var tag: [crypto.aead.aes_gcm.Aes256Gcm.tag_length]u8 = undefined;
    var encrypted_priv: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;

    {
        const f = cwd.openFile(io, priv_path, .{}) catch return SipError.IdentityNotFound;
        defer f.close(io);
        var raw: [108]u8 = undefined;
        _ = try f.readPositionalAll(io, &raw, 0);
        salt = raw[0..16].*;
        nonce = raw[16..28].*;
        tag = raw[28..44].*;
        encrypted_priv = raw[44..108].*;
    }
    {
        const f = cwd.openFile(io, pub_path, .{}) catch return SipError.IdentityNotFound;
        defer f.close(io);
        _ = try f.readPositionalAll(io, &pub_bytes, 0);
    }

    var aes_key: [32]u8 = undefined;
    try crypto.pwhash.pbkdf2(&aes_key, password, &salt, PBKDF2_ITERATIONS, crypto.auth.hmac.sha2.HmacSha256);

    var sec_bytes: [64]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(&sec_bytes, &encrypted_priv, tag, "", nonce, aes_key) catch {
        return SipError.DecryptionFailed;
    };

    return KeyPair{ .public = pub_bytes, .secret = sec_bytes };
}

pub fn loadPublicOnly(io: std.Io, name: []const u8) ![32]u8 {
    var pub_path_buf: [300]u8 = undefined;
    const pub_path = try publicPath(&pub_path_buf, name);
    const cwd = Io.Dir.cwd();
    const f = cwd.openFile(io, pub_path, .{}) catch return SipError.IdentityNotFound;
    defer f.close(io);
    var pub_bytes: [32]u8 = undefined;
    _ = try f.readPositionalAll(io, &pub_bytes, 0);
    return pub_bytes;
}

pub fn identityExists(io: std.Io, name: []const u8) bool {
    var dir_buf: [300]u8 = undefined;
    const dpath = identityDir(&dir_buf, name) catch return false;
    const cwd = Io.Dir.cwd();
    var d = cwd.openDir(io, dpath, .{}) catch return false;
    d.close(io);
    return true;
}

pub fn deleteIdentity(io: std.Io, name: []const u8) !void {
    if (!identityExists(io, name)) return SipError.IdentityNotFound;
    var dir_buf: [300]u8 = undefined;
    const dpath = try identityDir(&dir_buf, name);
    const cwd = Io.Dir.cwd();
    try cwd.deleteTree(io, dpath);
}

/// Ändert das Passwort einer Identität (entschlüsselt mit old_password,
/// verschlüsselt denselben Private Key neu mit new_password). Der Public
/// Key und damit die SIP-Adresse bleiben dabei garantiert unverändert.
pub fn changePassword(io: std.Io, name: []const u8, old_password: []const u8, new_password: []const u8) !KeyPair {
    const kp = try loadIdentity(io, name, old_password);

    var dir_buf: [300]u8 = undefined;
    const dpath = try identityDir(&dir_buf, name);
    const cwd = Io.Dir.cwd();
    try cwd.deleteTree(io, dpath);

    return try storeIdentity(io, name, kp, new_password);
}

/// Verschlüsselt ein bereits vorhandenes KeyPair mit `password` und
/// schreibt es nach keys/<name>/. Wird von createIdentity (neuer Key)
/// und changePassword (bestehender Key, neues Passwort) gemeinsam genutzt.
fn storeIdentity(io: std.Io, name: []const u8, kp: KeyPair, password: []const u8) !KeyPair {
    var dir_buf: [300]u8 = undefined;
    const dir = try identityDir(&dir_buf, name);

    const cwd = Io.Dir.cwd();
    cwd.createDirPath(io, KEY_ROOT) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    cwd.createDirPath(io, dir) catch |err| switch (err) {
        error.PathAlreadyExists => return SipError.IdentityAlreadyExists,
        else => return err,
    };

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
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(&encrypted_priv, &tag, &kp.secret, "", nonce, aes_key);

    var priv_path_buf: [300]u8 = undefined;
    var pub_path_buf: [300]u8 = undefined;
    const priv_path = try privatePath(&priv_path_buf, name);
    const pub_path = try publicPath(&pub_path_buf, name);

    {
        const f = try cwd.createFile(io, priv_path, .{});
        defer f.close(io);
        const rc = std.os.linux.syscall2(.fchmod, @intCast(f.handle), 0o600);
        if (rc != 0) return SipError.ChmodFailed;
        var buf: [256]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&salt);
        try w.interface.writeAll(&nonce);
        try w.interface.writeAll(&tag);
        try w.interface.writeAll(&encrypted_priv);
        try w.flush();
    }
    {
        const f = try cwd.createFile(io, pub_path, .{});
        defer f.close(io);
        const rc = std.os.linux.syscall2(.fchmod, @intCast(f.handle), 0o644);
        if (rc != 0) return SipError.ChmodFailed;
        var buf: [64]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&kp.public);
        try w.flush();
    }

    return kp;
}

// ---------------------------------------------------------------------
// Listing identities
// ---------------------------------------------------------------------

pub const ListError = error{KeyRootMissing} || anyerror;

/// Ruft `callback(entry)` für jede gefundene Identität in keys/ auf.
/// Gibt ListError.KeyRootMissing zurück falls der keys/-Ordner nicht existiert.
pub fn forEachIdentity(
    io: std.Io,
    comptime Context: type,
    ctx: Context,
    comptime callback: fn (ctx: Context, entry: IdentityEntry) anyerror!void,
) !void {
    const cwd = Io.Dir.cwd();
    var dir = cwd.openDir(io, KEY_ROOT, .{ .iterate = true }) catch {
        return ListError.KeyRootMissing;
    };
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;

        var ie: IdentityEntry = undefined;
        ie.name_len = @min(entry.name.len, ie.name_buf.len);
        @memcpy(ie.name_buf[0..ie.name_len], entry.name[0..ie.name_len]);

        if (loadPublicOnly(io, entry.name)) |pub_bytes| {
            ie.public = pub_bytes;
            ie.valid = true;
        } else |_| {
            ie.public = [_]u8{0} ** 32;
            ie.valid = false;
        }

        try callback(ctx, ie);
    }
}
