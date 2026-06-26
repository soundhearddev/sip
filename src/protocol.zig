const std = @import("std");

/// 256 values
pub const Command = enum(u8) {
    discovery = 0x01,

    /// ReadFile: request to read a file from the remote side
    /// Payload: path (null-terminated string, max 256 bytes)
    ReadFile = 0x02,

    /// WriteFile: request to write/update a file on the remote side
    /// Payload: [path_len:u16][path:[]u8][data_len:u32][data:[]u8]
    WriteFile = 0x03,

    /// ListDir: request to list directory contents
    /// Payload: path (null-terminated string, max 256 bytes)
    ListDir = 0x04,

    /// Execute: request to execute a command/script on the remote side
    /// Payload: [cmd_len:u16][cmd:[]u8]
    Execute = 0x05,

    /// Data: generic data transfer (user-defined content)
    /// Payload: arbitrary bytes, application-specific interpretation
    Data = 0x06,

    /// Flush: signal to flush/commit any pending operations
    /// Payload: empty (or optional metadata)
    Flush = 0x07,

    /// Close: signal to close connection/stream gracefully
    /// Payload: empty (or optional reason/code)
    Close = 0x08,

    /// Keepalive: heartbeat to prevent timeout
    /// Payload: empty (or optional timestamp)
    Keepalive = 0x09,

    /// DataChunk: Teil eines mehrteiligen Datentransfers (nicht der letzte Chunk)
    /// Payload: arbitrary bytes
    DataChunk = 0x0A,
    /// DataEnd: letzter Chunk eines mehrteiligen Datentransfers
    /// Payload: arbitrary bytes (kann auch leer sein, falls vorheriger Chunk exakt aufging)
    DataEnd = 0x0B,

    /// Unknown: used for graceful handling of unrecognized commands
    _,
};

pub const ProtocolError = error{
    InvalidCommand,
    MalformedPayload,
    PayloadTooLarge,
    BufferOverflow,
    InvalidUtf8,
};

pub fn parseCommand(byte: u8) Command {
    return @enumFromInt(byte);
}

pub fn validatePayload(allocator: std.mem.Allocator, cmd: Command, payload: []const u8) ProtocolError!void {
    const MAX_PAYLOAD_SIZE = 1024 * 1024;

    if (payload.len > MAX_PAYLOAD_SIZE) {
        return ProtocolError.PayloadTooLarge;
    }

    switch (cmd) {
        .ReadFile => {
            if (payload.len == 0 or payload.len > 256) {
                return ProtocolError.MalformedPayload;
            }
            if (payload[payload.len - 1] != 0) {
                return ProtocolError.MalformedPayload;
            }
        },

        .WriteFile => {
            if (payload.len < 6) {
                return ProtocolError.MalformedPayload;
            }
            const path_len = std.mem.readInt(u16, payload[0..2][0..2], .big);
            if (2 + path_len > payload.len) {
                return ProtocolError.MalformedPayload;
            }
            if (2 + path_len + 4 > payload.len) {
                return ProtocolError.MalformedPayload;
            }
            const data_len = std.mem.readInt(u32, payload[2 + path_len .. 6 + path_len][0..4], .big);
            if (2 + path_len + 4 + data_len != payload.len) {
                return ProtocolError.MalformedPayload;
            }
        },

        .ListDir => {
            if (payload.len == 0 or payload.len > 256) {
                return ProtocolError.MalformedPayload;
            }
            if (payload[payload.len - 1] != 0) {
                return ProtocolError.MalformedPayload;
            }
        },

        .Execute => {
            if (payload.len < 2) {
                return ProtocolError.MalformedPayload;
            }
            const cmd_len = std.mem.readInt(u16, payload[0..2], .big);
            if (2 + cmd_len != payload.len) {
                return ProtocolError.MalformedPayload;
            }
        },

        .discovery, .Data, .DataChunk, .DataEnd => {
            // No specific validation
        },

        .Flush => {
            if (payload.len > 16) {
                return ProtocolError.MalformedPayload;
            }
        },

        .Close => {
            if (payload.len > 16) {
                return ProtocolError.MalformedPayload;
            }
        },

        .Keepalive => {
            if (payload.len > 16) {
                return ProtocolError.MalformedPayload;
            }
        },

        _ => {
            // Unknown command
        },
    }

    _ = allocator;
}

pub fn extractPath(allocator: std.mem.Allocator, payload: []const u8) ProtocolError![]u8 {
    if (payload.len == 0 or payload[payload.len - 1] != 0) {
        return ProtocolError.MalformedPayload;
    }

    const path_cstr = payload[0 .. payload.len - 1 :0];
    const path = try allocator.dupe(u8, path_cstr);
    return path;
}

pub const WriteFilePayload = struct {
    path: []u8,
    data: []u8,
};

pub fn extractWriteFilePayload(allocator: std.mem.Allocator, payload: []const u8) ProtocolError!WriteFilePayload {
    if (payload.len < 6) {
        return ProtocolError.MalformedPayload;
    }

    const path_len = std.mem.readInt(u16, payload[0..2][0..2], .big);
    const path_bytes = payload[2 .. 2 + path_len];
    const data_len = std.mem.readInt(u32, payload[2 + path_len .. 6 + path_len][0..4], .big);
    const data_bytes = payload[6 + path_len .. 6 + path_len + data_len];

    const path = try allocator.dupe(u8, path_bytes);
    errdefer allocator.free(path);

    const data = try allocator.dupe(u8, data_bytes);
    errdefer allocator.free(data);

    return WriteFilePayload{ .path = path, .data = data };
}

pub fn extractExecuteCommand(allocator: std.mem.Allocator, payload: []const u8) ProtocolError![]u8 {
    if (payload.len < 2) {
        return ProtocolError.MalformedPayload;
    }

    const cmd_len = std.mem.readInt(u16, payload[0..2][0..2], .big);
    const cmd_bytes = payload[2 .. 2 + cmd_len];

    const cmd = try allocator.dupe(u8, cmd_bytes);
    return cmd;
}

test "validate ReadFile payload" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const valid_payload = "test.txt\x00";
    try validatePayload(arena.allocator(), .ReadFile, valid_payload);

    const invalid_payload = "test.txt";
    try std.testing.expectError(ProtocolError.MalformedPayload, validatePayload(arena.allocator(), .ReadFile, invalid_payload));
}

test "validate WriteFile payload" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var buf: [256]u8 = undefined;
    var i: usize = 0;

    std.mem.writeInt(u16, buf[i..][0..2], 5, .big);
    i += 2;
    @memcpy(buf[i .. i + 5], "hello");
    i += 5;
    std.mem.writeInt(u32, buf[i..][0..4], 5, .big);
    i += 4;
    @memcpy(buf[i .. i + 5], "world");
    i += 5;

    try validatePayload(arena.allocator(), .WriteFile, buf[0..i]);
}

test "parse command" {
    const cmd1 = parseCommand(0x01);
    try std.testing.expectEqual(Command.discovery, cmd1);

    const cmd_readfile = parseCommand(0x02);
    try std.testing.expectEqual(Command.ReadFile, cmd_readfile);

    const cmd2 = parseCommand(0x09);
    try std.testing.expectEqual(Command.Keepalive, cmd2);

    const cmd_unknown = parseCommand(0xFF);
    try std.testing.expectEqual(@as(u8, 0xFF), @intFromEnum(cmd_unknown));
}
