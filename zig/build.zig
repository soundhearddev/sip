const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Haupt-Binary ---
    const exe = b.addExecutable(.{
        .name = "SIP",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/SIP.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.addCSourceFile(.{
        .file = b.path("src/time.c"),
        .flags = &.{"-std=c11"},
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run SIP");
    run_step.dependOn(&run_cmd.step);

    // --- Debug Runner ---
    const debug_exe = b.addExecutable(.{
        .name = "debug",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/debug.zig"),
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        }),
    });
    debug_exe.root_module.addCSourceFile(.{
        .file = b.path("src/time.c"),
        .flags = &.{"-std=c11"},
    });
    b.installArtifact(debug_exe);

    const debug_run = b.addRunArtifact(debug_exe);
    debug_run.step.dependOn(b.getInstallStep());
    const debug_step = b.step("debug", "Interaktiver Debug Runner");
    debug_step.dependOn(&debug_run.step);
}
