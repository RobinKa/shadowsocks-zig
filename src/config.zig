const std = @import("std");

pub const Config = struct {
    port: u16,
    key: []u8,
};

pub fn configFromJsonString(input_data: []const u8) !Config {
    var stream = std.json.TokenStream.init(input_data);
    return try std.json.parse(Config, &stream, .{
        .allocator = std.heap.page_allocator,
    });
}

pub fn configFromJsonFile(path: []const u8) !Config {
    const config_string = try std.fs.cwd().readFileAlloc(std.heap.page_allocator, path, 8192);
    defer std.heap.page_allocator.free(config_string);
    return try configFromJsonString(config_string);
}
