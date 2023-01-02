const std = @import("std");
const network = @import("network");
const shadowsocks = @import("shadowsocks.zig");
const config = @import("config.zig");

fn getConfig(allocator: std.mem.Allocator) !config.Config {
    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();

    _ = arg_it.skip(); // executable name

    const config_path = arg_it.next();

    if (config_path != null) {
        return try config.configFromJsonFile(config_path.?, allocator);
    } else {
        var cfg: config.Config = undefined;

        const env_port: []u8 = try std.process.getEnvVarOwned(allocator, "SHADOWSOCKS_PORT");
        defer allocator.free(env_port);

        const env_key: []u8 = try std.process.getEnvVarOwned(allocator, "SHADOWSOCKS_KEY");

        cfg.port = try std.fmt.parseUnsigned(u16, env_port, 10);
        cfg.key = env_key;

        return cfg;
    }
}

pub fn main() !void {
    try network.init();
    defer network.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const cfg: config.Config = try getConfig(allocator);

    std.debug.print("Starting with port {d}\n", .{cfg.port});

    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, cfg.key);

    shadowsocks.Server.start(cfg.port, key, allocator) catch |err| {
        std.debug.print("Server failed, error: {s}\n", .{@errorName(err)});
    };
}

test {
    _ = @import("shadowsocks.zig");
}
