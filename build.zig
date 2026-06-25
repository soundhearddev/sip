const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Module ────────────────────────────────────────────────────────────
    const protocol_mod = b.addModule("protocol", .{
        .root_source_file = b.path("src/protocol.zig"),
    });

    const synet_mod = b.addModule("synet", .{
        .root_source_file = b.path("src/synet.zig"),
    });

    const header_mod = b.addModule("header", .{
        .root_source_file = b.path("src/header.zig"),
    });
    header_mod.addImport("protocol", protocol_mod);

    const translation_mod = b.addModule("translation", .{
        .root_source_file = b.path("src/translation.zig"),
    });
    translation_mod.addImport("header", header_mod);
    translation_mod.addImport("protocol", protocol_mod);
    translation_mod.addImport("synet", synet_mod);

    const sip_mod = b.addModule("sip", .{
        .root_source_file = b.path("src/sip.zig"),
    });
    sip_mod.addImport("protocol", protocol_mod);
    sip_mod.addImport("synet", synet_mod);
    sip_mod.addImport("header", header_mod);
    sip_mod.addImport("translation", translation_mod);

    // ── Tests ───────────────────────────────────────────────────────────────
    const translation_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/translation.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    translation_tests.root_module.addImport("header", header_mod);
    translation_tests.root_module.addImport("protocol", protocol_mod);
    translation_tests.root_module.addImport("synet", synet_mod);

    const run_translation_tests = b.addRunArtifact(translation_tests);
    b.step("test-translation", "Run translation tests").dependOn(&run_translation_tests.step);

    const header_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/header.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    header_tests.root_module.addImport("protocol", protocol_mod);

    const run_header_tests = b.addRunArtifact(header_tests);
    b.step("test-header", "Run header tests").dependOn(&run_header_tests.step);

    const test_all = b.step("test", "Run all tests");
    test_all.dependOn(&run_translation_tests.step);
    test_all.dependOn(&run_header_tests.step);
}
