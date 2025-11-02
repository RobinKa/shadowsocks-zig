const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard options for target and optimization according to Zig 0.16 API.
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create a module for the main executable so we can attach package paths.
    const main_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Expose the in-repo network package to the module.
    main_mod.addAnonymousImport("network", .{ .root_source_file = b.path("libs/zig-network/network.zig") });

    const exe = b.addExecutable(.{
        .name = "main",
        .root_module = main_mod,
    });

    b.installArtifact(exe);

    // Convenience run step for the main executable.
    const run_exe = b.addRunArtifact(exe);
    // If the build was invoked with extra args, forward them to the run step.
    if (b.args) |args| run_exe.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_exe.step);

    // Unit tests for src/main.zig
    const main_test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_test_mod.addAnonymousImport("network", .{ .root_source_file = b.path("libs/zig-network/network.zig") });
    const main_tests = b.addTest(.{ .root_module = main_test_mod });
    const run_main_tests = b.addRunArtifact(main_tests);

    // Unit tests for src/shadowsocks.zig (named test executable)
    const ss_mod = b.createModule(.{
        .root_source_file = b.path("src/shadowsocks.zig"),
        .target = target,
        .optimize = optimize,
    });
    ss_mod.addAnonymousImport("network", .{ .root_source_file = b.path("libs/zig-network/network.zig") });
    const ss_tests = b.addTest(.{ .name = "shadowsocks-test", .root_module = ss_mod });
    const run_ss_tests = b.addRunArtifact(ss_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_ss_tests.step);
}
