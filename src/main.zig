const std = @import("std");
const network = @import("network");
const shadowsocks = @import("shadowsocks.zig");
const config = @import("config.zig");

pub fn main() !void {
    try network.init();
    defer network.deinit();

    const cfg = try config.configFromJsonFile("config.json");

    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, cfg.key);

    try shadowsocks.Server.start(cfg.port, &key);
}
