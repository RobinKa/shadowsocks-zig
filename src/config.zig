const std = @import("std");

pub const Config = struct {
    port: u16,
    key: []u8,
};

pub fn configFromJsonString(input_data: []const u8, allocator: std.mem.Allocator) !Config {
    var stream = std.json.TokenStream.init(input_data);
    return try std.json.parse(Config, &stream, .{
        .allocator = allocator,
    });
}

pub fn configFromJsonFile(path: []const u8, allocator: std.mem.Allocator) !Config {
    const config_string = try std.fs.cwd().readFileAlloc(allocator, path, 8192);
    defer allocator.free(config_string);
    return try configFromJsonString(config_string, allocator);
}
