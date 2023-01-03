const network = @import("network");
const std = @import("std");
const headers = @import("headers.zig");

const SeparateHeader = struct {
    session_id: [8]u8,
    packet_id: [8]u8,

    pub fn decode(data: [16]u8) @This() {
        return .{
            .session_id = data[0..8].*,
            .packet_id = data[8..16].*,
        };
    }

    pub fn encode(self: @This()) [16]u8 {
        return self.session_id ++ self.packet_id;
    }
};

const RequestHeader = struct {
    type: u8,
    timestamp: u64,
    padding_length: u16,
    address_type: u8,
    address: []u8,
    port: u16,

    allocator: ?std.mem.Allocator,

    pub fn decode(encoded: []const u8, allocator: std.mem.Allocator) !headers.DecodeResultWithDeinit(@This()) {
        var stream = std.io.fixedBufferStream(encoded);
        var reader = stream.reader();

        const t = try reader.readIntBig(u8);
        const timestamp = try reader.readIntBig(u64);
        const padding_length = try reader.readIntBig(u16);
        try reader.skipBytes(padding_length, .{});
        const address_type = try reader.readIntBig(u8);
        const address = try headers.readSocksAddress(address_type, reader, allocator);
        errdefer allocator.free(address);

        const port = try reader.readIntBig(u16);

        return .{
            .bytes_read = stream.pos,
            .result = .{
                .type = t,
                .timestamp = timestamp,
                .padding_length = padding_length,
                .address_type = address_type,
                .address = address,
                .port = port,
                .allocator = allocator,
            },
        };
    }

    pub fn encode(self: @This(), encoded: []u8) !usize {
        var stream = std.io.fixedBufferStream(encoded);
        var writer = stream.writer();

        try writer.writeIntBig(u8, self.type);
        try writer.writeIntBig(u64, self.timestamp);

        try writer.writeIntBig(u16, self.padding_length);
        try writer.writeByteNTimes(0, self.padding_length);

        try writer.writeIntBig(u8, self.address_type);
        if (self.address_type == 3) {
            try writer.writeIntBig(u8, @intCast(u8, self.address.len));
        }
        _ = try writer.write(self.address);

        try writer.writeIntBig(u16, self.port);

        return stream.pos;
    }

    pub fn deinit(self: @This()) void {
        if (self.allocator != null) {
            self.allocator.?.free(self.address);
        }
    }
};

const ResponseHeader = struct {
    type: u8,
    timestamp: u64,
    client_session_id: u16,
    padding_length: u16,
    address_type: u8,
    address: []u8,
    port: u16,
};

pub fn UdpServer(comptime TCrypto: type) type {
    const Error = error{
        NotEnoughData,
    };

    return struct {
        socket: network.Socket,
        session_id_to_end_point: std.StringHashMap(network.EndPoint),
        key: [TCrypto.key_length]u8,
        block_decryptor: TCrypto.BlockDecryptor,

        fn readContent(nonce: [12]u8, key: [TCrypto.key_length]u8, buffer: []const u8, content: []u8) !void {
            const encrypted = buffer[0 .. buffer.len - TCrypto.tag_length];

            var tag: [TCrypto.tag_length]u8 = undefined;
            std.mem.copy(u8, &tag, buffer[buffer.len - TCrypto.tag_length .. buffer.len]);

            try TCrypto.algorithm.decrypt(content, encrypted, tag, "", nonce, key);
        }

        fn handleReceive(self: *@This(), should_stop: *bool, data: []const u8, end_point: network.EndPoint, allocator: std.mem.Allocator) !void {
            if (data.len < 32) {
                return Error.NotEnoughData;
            }

            var encoded_separate_header: [16]u8 = undefined;
            self.block_decryptor.decrypt(&encoded_separate_header, data[0..16]);

            const separate_header = SeparateHeader.decode(encoded_separate_header);

            const nonce = encoded_separate_header[4..16];

            var decrypted: [4096]u8 = undefined;

            const session_subkey = TCrypto.deriveSessionSubkeyWithSaltUdp(self.key, separate_header.session_id);
            try readContent(nonce.*, session_subkey, data[16..], decrypted[0 .. data.len - 32]);

            const decode_request_header_result = try RequestHeader.decode(&decrypted, allocator);
            const request_header = decode_request_header_result.result;

            const payload = decrypted[decode_request_header_result.bytes_read..data.len];

            try self.session_id_to_end_point.put(&separate_header.session_id, end_point);

            // TODO: non-ipv4 addresses
            var send_socket = try network.Socket.create(.ipv4, .udp);
            defer send_socket.close();

            std.debug.print("Server s->r {d}\n", .{payload.len});
            _ = try send_socket.sendTo(
                .{
                    .address = .{
                        .ipv4 = .{
                            .value = request_header.address[0..4].*,
                        },
                    },
                    .port = request_header.port,
                },
                payload,
            );

            _ = should_stop;
            // TODO: start receive stream
        }

        fn loop(self: *@This(), should_stop: *bool, allocator: std.mem.Allocator) !void {
            var buffer: [4096]u8 = undefined;
            while (!should_stop.*) {
                const result = self.socket.receiveFrom(&buffer) catch null;
                if (result != null and result.?.numberOfBytes > 0) {
                    std.debug.print("Server c->s {d}\n", .{result.?.numberOfBytes});
                    try self.handleReceive(should_stop, buffer[0..result.?.numberOfBytes], result.?.sender, allocator);
                }
            }
        }

        fn startInternal(should_stop: *bool, port: u16, key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !void {
            var socket = try network.Socket.create(.ipv4, .udp);
            defer socket.close();
            try socket.bindToPort(port);
            try socket.setReadTimeout(std.time.us_per_ms);

            var server: @This() = .{
                .socket = socket,
                .session_id_to_end_point = std.StringHashMap(network.EndPoint).init(allocator),
                .key = key,
                .block_decryptor = TCrypto.BlockDecryptor.init(key),
            };

            try server.loop(should_stop, allocator);
        }

        const Running = struct {
            thread: std.Thread,
            should_stop: *bool,
            allocator: std.mem.Allocator,

            pub fn stop(self: @This()) void {
                self.should_stop.* = true;
                self.thread.join();
                self.allocator.destroy(self.should_stop);
            }
        };

        pub fn start(port: u16, key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !Running {
            var should_stop = try allocator.create(bool);
            var thread = try std.Thread.spawn(.{}, startInternal, .{ should_stop, port, key, allocator });

            return .{
                .thread = thread,
                .should_stop = should_stop,
                .allocator = allocator,
            };
        }

        pub fn startBlocking(port: u16, key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !void {
            var should_stop = false;
            try startInternal(&should_stop, port, key, allocator);
        }

        pub fn deinit(self: @This()) void {
            self.socket.close();
            self.session_id_to_end_point.deinit();
        }
    };
}

const UdpEchoServer = struct {
    fn startInternal(should_stop: *bool, port: u16, allocator: std.mem.Allocator) !void {
        var socket = try network.Socket.create(.ipv4, .udp);
        defer socket.close();
        try socket.bindToPort(port);

        var buffer: [4096]u8 = undefined;

        var socket_set = try network.SocketSet.init(allocator);
        defer socket_set.deinit();

        try socket_set.add(socket, .{ .read = true, .write = false });

        while (!should_stop.*) {
            _ = try network.waitForSocketEvent(&socket_set, std.time.ns_per_ms);

            if (socket_set.isReadyRead(socket)) {
                const result = try socket.receiveFrom(&buffer);
                _ = try socket.sendTo(result.sender, buffer[0..result.numberOfBytes]);
            }
        }
    }

    const Running = struct {
        thread: std.Thread,
        should_stop: *bool,
        allocator: std.mem.Allocator,

        pub fn stop(self: @This()) void {
            self.should_stop.* = true;
            self.thread.join();
            self.allocator.destroy(self.should_stop);
        }
    };

    pub fn start(port: u16, allocator: std.mem.Allocator) !Running {
        var should_stop = try allocator.create(bool);
        var thread = try std.Thread.spawn(.{}, startInternal, .{ should_stop, port, allocator });

        return .{
            .thread = thread,
            .should_stop = should_stop,
            .allocator = allocator,
        };
    }
};

test "test udp echo server" {
    const echo_port = 10_101;

    const echo_server = try UdpEchoServer.start(echo_port, std.testing.allocator);
    defer echo_server.stop();

    std.time.sleep(std.time.ns_per_s);

    var socket = try network.Socket.create(.ipv4, .udp);
    defer socket.close();

    const test_data = [_]u8{ 1, 2, 3, 4 };
    _ = try socket.sendTo(
        .{
            .address = .{
                .ipv4 = .{
                    .value = .{ 127, 0, 0, 1 },
                },
            },
            .port = echo_port,
        },
        &test_data,
    );
    var buffer: [4096]u8 = undefined;
    const receive_info = try socket.receiveFrom(&buffer);

    try std.testing.expectEqual(@as(usize, 4), receive_info.numberOfBytes);
    try std.testing.expectEqualSlices(u8, &test_data, buffer[0..receive_info.numberOfBytes]);
}

test "udp request header encode decode" {
    var address = [_]u8{ 127, 0, 0, 1 };

    const request_header: RequestHeader = .{
        .type = 0,
        .timestamp = @intCast(u64, std.time.timestamp()),
        .padding_length = 10,
        .address_type = 1,
        .address = &address,
        .port = 123,
        .allocator = null,
    };

    var encoded_request_header: [1024]u8 = undefined;
    const encoded_request_header_length = try request_header.encode(&encoded_request_header);

    const decoded = try RequestHeader.decode(
        encoded_request_header[0..encoded_request_header_length],
        std.testing.allocator,
    );

    try std.testing.expectEqual(encoded_request_header_length, decoded.bytes_read);
    try std.testing.expectEqual(std.testing.allocator, decoded.result.allocator.?);

    try std.testing.expectEqual(request_header.type, decoded.result.type);
    try std.testing.expectEqual(request_header.timestamp, decoded.result.timestamp);
    try std.testing.expectEqual(request_header.padding_length, decoded.result.padding_length);
    try std.testing.expectEqual(request_header.address_type, decoded.result.address_type);
    try std.testing.expectEqualSlices(u8, request_header.address, decoded.result.address);
    try std.testing.expectEqual(request_header.port, decoded.result.port);
}

test "test udp server" {
    const crypto = @import("crypto.zig");

    const TCrypto = crypto.Blake3Aes256Gcm;
    const key = [_]u8{1} ** TCrypto.key_length;

    const echo_port = 10_102;
    const proxy_port = 10_103;

    const echo_server = try UdpEchoServer.start(echo_port, std.testing.allocator);
    defer echo_server.stop();

    const server = try UdpServer(TCrypto).start(proxy_port, key, std.testing.allocator);
    defer server.stop();

    std.time.sleep(std.time.ns_per_s);

    var buffer: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();

    const separate_header: SeparateHeader = .{
        .session_id = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .packet_id = .{ 9, 10, 11, 12, 13, 14, 15, 16 },
    };

    std.debug.print("Client separate header: {d} {d} {d} {d}", .{
        separate_header.session_id[0],
        separate_header.session_id[7],
        separate_header.packet_id[0],
        separate_header.packet_id[7],
    });

    var address = [_]u8{ 127, 0, 0, 1 };

    const request_header: RequestHeader = .{
        .type = 0,
        .timestamp = @intCast(u64, std.time.timestamp()),
        .padding_length = 10,
        .address_type = 1,
        .address = &address,
        .port = echo_port,
        .allocator = null,
    };

    const session_subkey = TCrypto.deriveSessionSubkeyWithSaltUdp(key, separate_header.session_id);

    const block_encryptor = TCrypto.BlockEncryptor.init(key);
    const encoded_separate_header = separate_header.encode();
    var encrypted_separate_header: [16]u8 = undefined;
    block_encryptor.encrypt(&encoded_separate_header, &encrypted_separate_header);

    var encoded_request_header: [1024]u8 = undefined;
    const encoded_request_header_length = try request_header.encode(&encoded_request_header);
    const payload = [_]u8{ 1, 2, 3, 4 };

    var encoded_request = try std.ArrayList(u8).initCapacity(
        std.testing.allocator,
        encoded_request_header_length + payload.len,
    );

    try encoded_request.appendSlice(encoded_request_header[0..encoded_request_header_length]);
    try encoded_request.appendSlice(&payload);

    const nonce = separate_header.session_id[4..8] ++ separate_header.packet_id;
    std.debug.print("Client nonce: {d} {d}", .{ nonce[0], nonce[11] });
    var encrypted_request: [1024]u8 = undefined;
    var encrypted_request_tag: [TCrypto.tag_length]u8 = undefined;
    TCrypto.algorithm.encrypt(
        encrypted_request[0..encoded_request.items.len],
        &encrypted_request_tag,
        encoded_request.items,
        "",
        nonce.*,
        session_subkey,
    );

    _ = try writer.write(&encrypted_separate_header);
    _ = try writer.write(encrypted_request[0..encoded_request.items.len]);
    _ = try writer.write(&encrypted_request_tag);

    var socket = try network.Socket.create(.ipv4, .udp);
    defer socket.close();

    _ = try socket.sendTo(
        .{
            .address = .{
                .ipv4 = .{
                    .value = .{ 127, 0, 0, 1 },
                },
            },
            .port = proxy_port,
        },
        buffer[0..stream.pos],
    );
    // const receive_info = try socket.receiveFrom(&buffer);

    // _ = receive_info;

    std.time.sleep(std.time.ns_per_s);
}
