const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sip_mod = b.addModule("sip", .{
        .root_source_file = b.path("src/root.zig"),
    });

    _ = sip_mod;

    // ── Tests ───────────────────────────────────────────────────────────────
    const translation_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/translation.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_translation_tests = b.addRunArtifact(translation_tests);
    b.step("test-translation", "Run translation tests").dependOn(&run_translation_tests.step);

    const fragmentation_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fragmentation.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_fragmentation_tests = b.addRunArtifact(fragmentation_tests);
    b.step("test-fragmentation", "Run fragmentation tests").dependOn(&run_fragmentation_tests.step);

    const protocol_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/protocol.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_protocol_tests = b.addRunArtifact(protocol_tests);
    b.step("test-protocol", "Run protocol tests").dependOn(&run_protocol_tests.step);

    const header_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/header.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_header_tests = b.addRunArtifact(header_tests);
    b.step("test-header", "Run header tests").dependOn(&run_header_tests.step);

    const handshake_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/handshake.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_handshake_tests = b.addRunArtifact(handshake_tests);
    b.step("test-handshake", "Run handshake tests").dependOn(&run_handshake_tests.step);

    const test_all = b.step("test", "Run all tests");
    test_all.dependOn(&run_translation_tests.step);
    test_all.dependOn(&run_header_tests.step);
    test_all.dependOn(&run_fragmentation_tests.step);
    test_all.dependOn(&run_handshake_tests.step);
}
