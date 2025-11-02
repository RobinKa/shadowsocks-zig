const std = @import("std");

pub const Config = struct {
    port: u16,
    key: []u8,
    method: []u8,
};

pub fn configFromJsonString(input_data: []const u8, allocator: std.mem.Allocator) !Config {
    const parsed = try std.json.parseFromSlice(Config, allocator, input_data, .{});
    return parsed.value;
}

pub fn configFromJsonFile(path: []const u8, allocator: std.mem.Allocator) !Config {
    const config_string = try std.fs.cwd().readFileAlloc(path, allocator, std.Io.Limit.limited(4096));
    defer allocator.free(config_string);
    return try configFromJsonString(config_string, allocator);
}
