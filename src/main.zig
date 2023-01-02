const std = @import("std");
const network = @import("network");
const shadowsocks = @import("shadowsocks.zig");
const config = @import("config.zig");

const logger = std.log.scoped(.main);

fn getConfig(allocator: std.mem.Allocator) !config.Config {
    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();

    _ = arg_it.skip(); // executable name

    const config_path = arg_it.next();

    if (config_path != null) {
        return try config.configFromJsonFile(config_path.?, allocator);
    } else {
        const env_port: []u8 = try std.process.getEnvVarOwned(allocator, "SHADOWSOCKS_PORT");
        defer allocator.free(env_port);

        const env_key: []u8 = try std.process.getEnvVarOwned(allocator, "SHADOWSOCKS_KEY");
        defer allocator.free(env_key);

        const env_method: []u8 = try std.process.getEnvVarOwned(allocator, "SHADOWSOCKS_METHOD");
        defer allocator.free(env_method);

        return .{
            .port = try std.fmt.parseUnsigned(u16, env_port, 10),
            .key = env_key,
            .method = env_method,
        };
    }
}

fn startServerFromConfig(cfg: config.Config, allocator: std.mem.Allocator) !void {
    inline for (shadowsocks.crypto.Methods) |TCrypto| {
        if (std.mem.eql(u8, cfg.method, TCrypto.name)) {
            var key: [TCrypto.key_length]u8 = undefined;
            try std.base64.standard.Decoder.decode(&key, cfg.key);
            try shadowsocks.server.Server(TCrypto).start_blocking(cfg.port, key, allocator);
        }
    }

    unreachable;
}

pub fn main() !void {
    try network.init();
    defer network.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const cfg: config.Config = try getConfig(allocator);

    logger.info("Starting with port {d} and encryption method {s}", .{ cfg.port, cfg.method });

    try startServerFromConfig(cfg, allocator);
}
