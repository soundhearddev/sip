const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================
    // Common Modul (optional)
    // =========================
    const base_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    base_module.addCSourceFile(.{
        .file = b.path("src/time.c"),
        .flags = &.{"-std=c11"},
    });

    // =========================
    // sipctl binary
    // =========================
    const sipctl = b.addExecutable(.{
        .name = "sipctl",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sipctl.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    sipctl.root_module.addCSourceFile(.{
        .file = b.path("src/time.c"),
        .flags = &.{"-std=c11"},
    });

    b.installArtifact(sipctl);

    // =========================
    // server_cli binary
    // =========================
    const server_cli = b.addExecutable(.{
        .name = "server_cli",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/server_cli.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    server_cli.root_module.addCSourceFile(.{
        .file = b.path("src/time.c"),
        .flags = &.{"-std=c11"},
    });

    b.installArtifact(server_cli);

    // =========================
    // run sipctl
    // =========================
    const run_sipctl = b.addRunArtifact(sipctl);
    run_sipctl.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_sipctl.addArgs(args);

    const run_sipctl_step = b.step("run-sipctl", "Run sipctl");
    run_sipctl_step.dependOn(&run_sipctl.step);

    // =========================
    // run server_cli
    // =========================
    const run_server = b.addRunArtifact(server_cli);
    run_server.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_server.addArgs(args);

    const run_server_step = b.step("run-server", "Run server_cli");
    run_server_step.dependOn(&run_server.step);
}
