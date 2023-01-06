const std = @import("std");

fn pkgPath(comptime out: []const u8) std.build.FileSource {
    if (comptime std.fs.path.dirname(@src().file)) |base| {
        const outpath = comptime base ++ std.fs.path.sep_str ++ out;
        return .{ .path = outpath };
    } else {
        return .{ .path = out };
    }
}

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("main", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackagePath("network", "libs/zig-network/network.zig");
    exe.install();

    var io_darwin: std.build.Pkg = .{
        .name = "async_io",
        .source = pkgPath("libs/io/io_darwin.zig"),
    };
    var io_linux: std.build.Pkg = .{
        .name = "async_io",
        .source = pkgPath("libs/io/io_linux.zig"),
    };
    var io_windows: std.build.Pkg = .{
        .name = "async_io",
        .source = pkgPath("libs/io/io_windows.zig"),
    };
    var io_stub: std.build.Pkg = .{
        .name = "async_io",
        .source = pkgPath("libs/io/io_stub.zig"),
    };

    var io = if (target.isDarwin())
        io_darwin
    else if (target.isLinux())
        io_linux
    else if (target.isWindows())
        io_windows
    else
        io_stub;

    exe.addPackage(io);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);
    exe_tests.addPackagePath("network", "libs/zig-network/network.zig");
    exe_tests.addPackage(io);

    const shadowsocks_tests = b.addTestExe("shadowsocks-test", "src/shadowsocks.zig");
    shadowsocks_tests.setTarget(target);
    shadowsocks_tests.setBuildMode(mode);
    shadowsocks_tests.addPackagePath("network", "libs/zig-network/network.zig");
    shadowsocks_tests.addPackage(io);
    shadowsocks_tests.install();

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
    test_step.dependOn(&shadowsocks_tests.step);
}
