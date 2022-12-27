const std = @import("std");
const network = @import("network");
const shadowsocks = @import("shadowsocks.zig");
const config = @import("config.zig");

fn getConfigPath(allocator: std.mem.Allocator) ![]const u8 {
    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();

    _ = arg_it.skip(); // executable name

    const config_path = arg_it.next() orelse "configs/config.json";

    var out_config_path: []u8 = try allocator.alloc(u8, config_path.len);
    std.mem.copy(u8, out_config_path, config_path);

    return out_config_path;
}

pub fn main() !void {
    try network.init();
    defer network.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const cfg = cfg: {
        const config_path = try getConfigPath(allocator);
        defer allocator.free(config_path);

        break :cfg try config.configFromJsonFile(config_path, allocator);
    };

    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, cfg.key);

    try shadowsocks.Server.start(cfg.port, &key, allocator);
}

test {
    _ = @import("shadowsocks.zig");
}
