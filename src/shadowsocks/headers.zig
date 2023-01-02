const std = @import("std");

fn DecodeResult(comptime T: type) type {
    return struct {
        bytes_read: usize,
        result: T,
    };
}

fn DecodeResultWithDeinit(comptime T: type) type {
    return struct {
        bytes_read: usize,
        result: T,

        pub fn deinit(self: @This()) void {
            self.result.deinit();
        }
    };
}

pub const FixedLengthRequestHeader = struct {
    pub const size: usize = 11;
    type: u8,
    timestamp: u64,
    length: u16,

    pub fn decode(encoded: []u8) !DecodeResult(@This()) {
        var stream = std.io.fixedBufferStream(encoded);
        var reader = stream.reader();

        return .{
            .result = .{
                .type = try reader.readIntBig(u8),
                .timestamp = try reader.readIntBig(u64),
                .length = try reader.readIntBig(u16),
            },
            .bytes_read = stream.pos,
        };
    }

    pub fn encode(self: @This(), encoded: []u8) !usize {
        var stream = std.io.fixedBufferStream(encoded);
        var writer = stream.writer();

        try writer.writeIntBig(u8, self.type);
        try writer.writeIntBig(u64, self.timestamp);
        try writer.writeIntBig(u16, self.length);

        return stream.pos;
    }
};

pub const VariableLengthRequestHeader = struct {
    address_type: u8,
    address: []const u8,
    port: u16,
    padding_length: u16,
    initial_payload: []const u8,

    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: @This()) void {
        if (self.allocator != null) {
            self.allocator.?.free(self.address);
            self.allocator.?.free(self.initial_payload);
        }
    }

    pub fn decode(encoded: []u8, length: u16, allocator: std.mem.Allocator) !DecodeResultWithDeinit(@This()) {
        var stream = std.io.fixedBufferStream(encoded);
        var reader = stream.reader();

        const start_pos = reader.context.pos;

        const address_type = try reader.readIntBig(u8);
        var address: []u8 = add: {
            switch (address_type) {
                1 => {
                    var addr: []u8 = try allocator.alloc(u8, 4);
                    errdefer allocator.free(addr);
                    try reader.readNoEof(addr);
                    break :add addr;
                },
                3 => {
                    const address_length = try reader.readIntBig(u8);
                    var addr: []u8 = try allocator.alloc(u8, address_length);
                    errdefer allocator.free(addr);
                    try reader.readNoEof(addr);
                    break :add addr;
                },
                4 => {
                    var addr: []u8 = try allocator.alloc(u8, 16);
                    errdefer allocator.free(addr);
                    try reader.readNoEof(addr);
                    break :add addr;
                },
                else => unreachable,
            }
        };

        const port = try reader.readIntBig(u16);

        const padding_length = try reader.readIntBig(u16);
        try reader.skipBytes(padding_length, .{});

        const remaining_length = length - (reader.context.pos - start_pos);
        var initial_payload = try allocator.alloc(u8, remaining_length);
        errdefer allocator.free(initial_payload);
        try reader.readNoEof(initial_payload[0..remaining_length]);

        return .{
            .result = .{
                .address_type = address_type,
                .address = address,
                .port = port,
                .padding_length = padding_length,
                .initial_payload = initial_payload,
                .allocator = allocator,
            },
            .bytes_read = stream.pos,
        };
    }

    pub fn encode(self: @This(), encoded: []u8) !usize {
        var stream = std.io.fixedBufferStream(encoded);
        var writer = stream.writer();

        try writer.writeIntBig(u8, self.address_type);

        if (self.address_type == 3) {
            try writer.writeIntBig(u8, @intCast(u8, self.address.len));
        }

        _ = try writer.write(self.address);
        try writer.writeIntBig(u16, self.port);
        try writer.writeIntBig(u16, self.padding_length);
        try writer.writeByteNTimes(0, self.padding_length);
        _ = try writer.write(self.initial_payload);

        return stream.pos;
    }
};

pub fn FixedLengthResponseHeader(comptime salt_length: usize) type {
    return struct {
        pub const size: usize = 1 + 8 + salt_length + 2;

        type: u8,
        timestamp: u64,
        salt: [salt_length]u8,
        length: u16,

        pub fn decode(encoded: []u8) !DecodeResult(@This()) {
            var stream = std.io.fixedBufferStream(encoded);
            var reader = stream.reader();

            const t = try reader.readIntBig(u8);
            const timestamp = try reader.readIntBig(u64);
            var salt: [salt_length]u8 = undefined;
            try reader.readNoEof(&salt);
            const length = try reader.readIntBig(u16);

            return .{
                .result = .{
                    .type = t,
                    .timestamp = timestamp,
                    .salt = salt,
                    .length = length,
                },
                .bytes_read = stream.pos,
            };
        }

        pub fn encode(self: @This(), encoded: []u8) !usize {
            var stream = std.io.fixedBufferStream(encoded);
            var writer = stream.writer();

            try writer.writeIntBig(u8, self.type);
            try writer.writeIntBig(u64, self.timestamp);
            _ = try writer.write(&self.salt);
            try writer.writeIntBig(u16, self.length);

            return stream.pos;
        }
    };
}

test "encode FixedLengthRequestHeader" {
    const header = FixedLengthRequestHeader{
        .type = 0,
        .timestamp = 123,
        .length = 33,
    };

    var buffer: [100]u8 = undefined;
    const bytes_written = try header.encode(&buffer);

    try std.testing.expectEqual(FixedLengthRequestHeader.size, bytes_written);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 33 }, buffer[0..FixedLengthRequestHeader.size]);
}

test "decode FixedLengthRequestHeader" {
    var buffer = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 33, 7, 8, 9, 10 };

    const decoded = try FixedLengthRequestHeader.decode(&buffer);

    try std.testing.expectEqual(@as(usize, FixedLengthRequestHeader.size), decoded.bytes_read);
    try std.testing.expectEqual(@as(u8, 0), decoded.result.type);
    try std.testing.expectEqual(@as(u64, 123), decoded.result.timestamp);
    try std.testing.expectEqual(@as(u16, 33), decoded.result.length);
}

test "encode VariableLengthRequestHeader" {
    var address = [_]u8{ 1, 2, 3, 4 };
    var initial_payload = [_]u8{ 5, 6, 7 };

    const header = VariableLengthRequestHeader{
        .address_type = 1,
        .address = &address,
        .port = 56,
        .padding_length = 4,
        .initial_payload = &initial_payload,
    };
    defer header.deinit();

    var buffer: [100]u8 = undefined;
    const bytes_written = try header.encode(&buffer);

    const correct = [_]u8{ 1, 1, 2, 3, 4, 0, 56, 0, 4, 0, 0, 0, 0, 5, 6, 7 };
    try std.testing.expectEqual(correct.len, bytes_written);
    try std.testing.expectEqualSlices(u8, &correct, buffer[0..correct.len]);
}

test "decode VariableLengthRequestHeader" {
    var buffer = [_]u8{ 1, 1, 2, 3, 4, 0, 56, 0, 4, 0, 0, 0, 0, 5, 6, 7, 9, 9, 9 };

    const decoded = try VariableLengthRequestHeader.decode(&buffer, buffer.len - 3, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expectEqual(@as(usize, 16), decoded.bytes_read);
    try std.testing.expectEqual(@as(u8, 1), decoded.result.address_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, decoded.result.address);
    try std.testing.expectEqual(@as(u16, 56), decoded.result.port);
    try std.testing.expectEqual(@as(u16, 4), decoded.result.padding_length);
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7 }, decoded.result.initial_payload);
}

test "decode VariableLengthRequestHeader IPv6" {
    var buffer = [_]u8{ 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 56, 0, 4, 0, 0, 0, 0, 5, 6, 7, 9, 9, 9 };

    const decoded = try VariableLengthRequestHeader.decode(&buffer, buffer.len - 3, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expectEqual(@as(usize, 28), decoded.bytes_read);
    try std.testing.expectEqual(@as(u8, 4), decoded.result.address_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, decoded.result.address);
    try std.testing.expectEqual(@as(u16, 56), decoded.result.port);
    try std.testing.expectEqual(@as(u16, 4), decoded.result.padding_length);
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7 }, decoded.result.initial_payload);
}

test "encode FixedLengthResponseHeader" {
    const header = FixedLengthResponseHeader(32){
        .type = 0,
        .timestamp = 123,
        .salt = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
        .length = 33,
    };

    var buffer: [100]u8 = undefined;
    const bytes_written = try header.encode(&buffer);

    try std.testing.expectEqual(@as(usize, FixedLengthResponseHeader(32).size), bytes_written);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 33 },
        buffer[0..FixedLengthResponseHeader(32).size],
    );
}

test "decode FixedLengthResponseHeader" {
    var buffer = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 33, 7, 8, 9, 10 };

    const decoded = try FixedLengthResponseHeader(32).decode(&buffer);

    try std.testing.expectEqual(@as(usize, FixedLengthResponseHeader(32).size), decoded.bytes_read);
    try std.testing.expectEqual(@as(u8, 0), decoded.result.type);
    try std.testing.expectEqual(@as(u64, 123), decoded.result.timestamp);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
        &decoded.result.salt,
    );
    try std.testing.expectEqual(@as(u16, 33), decoded.result.length);
}
