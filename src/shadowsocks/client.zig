const std = @import("std");
const network = @import("network");
const headers = @import("headers.zig");
const crypto = @import("crypto.zig");

const logger = std.log.scoped(.shadowsocks_client);

pub fn Client(comptime TCrypto: type) type {
    const State = enum {
        wait_header,
        wait_length,
        wait_payload,
    };

    const Error = error{
        SaltDoesNotMatch,
        TimestampTooOld,
    };

    return struct {
        socket: network.Socket,
        request_salt: [TCrypto.salt_length]u8 = undefined,
        response_salt: [TCrypto.salt_length]u8 = undefined,
        initial_response_received: bool = false,
        recv_buffer: std.ArrayList(u8),
        request_encryptor: TCrypto.Encryptor = undefined,
        response_decryptor: TCrypto.Encryptor = undefined,
        key: [TCrypto.key_length]u8,
        next_length: u16 = undefined,
        state: State = .wait_header,
        received_payload: std.ArrayList(u8),

        pub fn deinit(self: @This()) void {
            self.received_payload.deinit();
            self.recv_buffer.deinit();
        }

        pub fn connect(
            address: [4]u8,
            port: u16,
            remote_name: []const u8,
            remote_port: u16,
            key: [TCrypto.key_length]u8,
            initial_payload: []const u8,
            allocator: std.mem.Allocator,
        ) !@This() {
            var socket = try network.Socket.create(.ipv4, .tcp);

            try socket.connect(.{
                .address = .{ .ipv4 = .{ .value = address } },
                .port = port,
            });

            var seed: [std.rand.DefaultCsprng.secret_seed_length]u8 = undefined;
            try std.os.getrandom(&seed);
            var prng = std.rand.DefaultCsprng.init(seed);

            var request_salt: [TCrypto.salt_length]u8 = undefined;
            prng.fill(&request_salt);

            var request_encryptor = TCrypto.Encryptor{
                .key = TCrypto.deriveSessionSubkeyWithSalt(key, request_salt),
            };

            const padding_length = if (initial_payload.len == 0) std.rand.Random.intRangeLessThan(prng.random(), u16, 1, 901) else 0;

            const variable_header = headers.VariableLengthRequestHeader{
                .address_type = 3,
                .address = remote_name,
                .port = remote_port,
                .padding_length = padding_length,
                .initial_payload = initial_payload,
            };

            var encoded_variable_header: [1024]u8 = undefined;
            const encoded_variable_header_size = try variable_header.encode(&encoded_variable_header);

            const fixed_header = headers.FixedLengthRequestHeader{
                .type = 0,
                .timestamp = @intCast(u64, std.time.timestamp()),
                .length = @intCast(u16, encoded_variable_header_size),
            };

            var encoded_fixed_header: [headers.FixedLengthRequestHeader.size]u8 = undefined;
            _ = try fixed_header.encode(&encoded_fixed_header);

            var encrypted_fixed_header: [headers.FixedLengthRequestHeader.size]u8 = undefined;
            var encrypted_fixed_header_tag: [TCrypto.tag_length]u8 = undefined;
            request_encryptor.encrypt(&encoded_fixed_header, &encrypted_fixed_header, &encrypted_fixed_header_tag);

            var encrypted_variable_header: [1024]u8 = undefined;
            var encrypted_variable_header_tag: [TCrypto.tag_length]u8 = undefined;
            request_encryptor.encrypt(
                encoded_variable_header[0..encoded_variable_header_size],
                encrypted_variable_header[0..encoded_variable_header_size],
                &encrypted_variable_header_tag,
            );

            var send_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
            defer send_buffer.deinit();

            try send_buffer.appendSlice(&request_salt);
            try send_buffer.appendSlice(&encrypted_fixed_header);
            try send_buffer.appendSlice(&encrypted_fixed_header_tag);
            try send_buffer.appendSlice(encrypted_variable_header[0..encoded_variable_header_size]);
            try send_buffer.appendSlice(&encrypted_variable_header_tag);

            var total_sent: usize = 0;
            while (total_sent < send_buffer.items.len) {
                const sent = try socket.send(send_buffer.items);
                logger.debug("c->s {d}", .{sent});
                total_sent += sent;
            }

            return .{
                .socket = socket,
                .key = key,
                .request_salt = request_salt,
                .request_encryptor = request_encryptor,
                .received_payload = std.ArrayList(u8).init(allocator),
                .recv_buffer = std.ArrayList(u8).init(allocator),
            };
        }

        fn waitHeader(self: *@This()) !bool {
            const THeader = headers.FixedLengthResponseHeader(TCrypto.salt_length);

            if (self.recv_buffer.items.len < TCrypto.salt_length + THeader.size + TCrypto.tag_length) {
                return false;
            }

            std.mem.copy(u8, &self.response_salt, self.recv_buffer.items[0..TCrypto.salt_length]);

            self.response_decryptor = .{
                .key = TCrypto.deriveSessionSubkeyWithSalt(self.key, self.response_salt),
            };

            const encrypted_response_header = self.recv_buffer.items[TCrypto.salt_length .. TCrypto.salt_length + THeader.size];
            var encrypted_response_header_tag: [TCrypto.tag_length]u8 = undefined;
            std.mem.copy(
                u8,
                &encrypted_response_header_tag,
                self.recv_buffer.items[TCrypto.salt_length + THeader.size .. TCrypto.salt_length + THeader.size + TCrypto.tag_length],
            );
            var encoded_response_header: [THeader.size]u8 = undefined;
            try self.response_decryptor.decrypt(&encoded_response_header, encrypted_response_header, encrypted_response_header_tag);

            const decoded = try THeader.decode(&encoded_response_header);

            if (!std.mem.eql(u8, &decoded.result.salt, &self.request_salt)) {
                return Error.SaltDoesNotMatch;
            }

            // TODO: is this check really needed, since we already matched the request salt?
            if (@intCast(u64, std.time.timestamp()) > decoded.result.timestamp + 30) {
                return Error.TimestampTooOld;
            }

            self.next_length = decoded.result.length;
            try self.recv_buffer.replaceRange(0, TCrypto.salt_length + THeader.size + TCrypto.tag_length, &.{});

            self.state = .wait_payload;

            return true;
        }

        fn waitLength(self: *@This()) !bool {
            if (self.recv_buffer.items.len < 2 + TCrypto.tag_length) {
                return false;
            }

            const encrypted_length = self.recv_buffer.items[0..2];
            var tag: [TCrypto.tag_length]u8 = undefined;
            std.mem.copy(u8, &tag, self.recv_buffer.items[2 .. 2 + TCrypto.tag_length]);
            var encoded_length: [2]u8 = undefined;
            try self.response_decryptor.decrypt(&encoded_length, encrypted_length, tag);

            self.next_length = std.mem.readIntBig(u16, encoded_length[0..2]);
            try self.recv_buffer.replaceRange(0, 2 + TCrypto.tag_length, &.{});

            self.state = .wait_payload;

            return true;
        }

        fn waitPayload(self: *@This(), allocator: std.mem.Allocator) !bool {
            if (self.recv_buffer.items.len < self.next_length + TCrypto.tag_length) {
                return false;
            }

            const encrypted_payload = self.recv_buffer.items[0..self.next_length];
            var encrypted_payload_tag: [TCrypto.tag_length]u8 = undefined;
            std.mem.copy(u8, &encrypted_payload_tag, self.recv_buffer.items[self.next_length .. self.next_length + TCrypto.tag_length]);
            var payload = try allocator.alloc(u8, encrypted_payload.len);
            defer allocator.free(payload);

            try self.response_decryptor.decrypt(payload, encrypted_payload, encrypted_payload_tag);

            try self.recv_buffer.replaceRange(0, self.next_length + TCrypto.tag_length, &.{});
            try self.received_payload.appendSlice(payload);

            self.state = .wait_length;

            return true;
        }

        fn getPacket(self: *@This(), data: []u8, allocator: std.mem.Allocator) !usize {
            while (true) {
                if (self.received_payload.items.len > 0) {
                    const count = std.math.min(self.received_payload.items.len, data.len);
                    std.mem.copy(u8, data, self.received_payload.items[0..count]);
                    try self.received_payload.replaceRange(0, count, &.{});
                    return count;
                }

                switch (self.state) {
                    .wait_header => {
                        if (!try self.waitHeader()) {
                            return 0;
                        }
                    },
                    .wait_length => {
                        if (!try self.waitLength()) {
                            return 0;
                        }
                    },
                    .wait_payload => {
                        if (!try self.waitPayload(allocator)) {
                            return 0;
                        }
                    },
                }
            }
        }

        pub fn receive(self: *@This(), data: []u8, allocator: std.mem.Allocator) !usize {
            var payload_size = try self.getPacket(data, allocator);
            if (payload_size > 0) {
                return payload_size;
            }

            while (true) {
                var buffer: [1024]u8 = undefined;
                var received = try self.socket.receive(&buffer);
                logger.debug("s->c {d}", .{received});
                try self.recv_buffer.appendSlice(buffer[0..received]);

                payload_size = try self.getPacket(data, allocator);
                if (payload_size > 0) {
                    return payload_size;
                }
            }
        }

        pub fn send(self: *@This(), data: []const u8, allocator: std.mem.Allocator) !usize {
            var send_buffer = try std.ArrayList(u8).initCapacity(allocator, 2 + TCrypto.tag_length + data.len + TCrypto.tag_length);
            defer send_buffer.deinit();

            {
                var encoded_length: [2]u8 = undefined;
                std.mem.writeIntBig(u16, &encoded_length, @intCast(u16, data.len));

                var encrypted_length: [2]u8 = undefined;
                var tag: [TCrypto.tag_length]u8 = undefined;

                self.request_encryptor.encrypt(&encoded_length, &encrypted_length, &tag);

                try send_buffer.appendSlice(&encrypted_length);
                try send_buffer.appendSlice(&tag);
            }

            {
                var encrypted_data: []u8 = try allocator.alloc(u8, data.len);
                defer allocator.free(encrypted_data);

                var tag: [TCrypto.tag_length]u8 = undefined;
                self.request_encryptor.encrypt(data, encrypted_data, &tag);

                try send_buffer.appendSlice(encrypted_data);
                try send_buffer.appendSlice(&tag);
            }

            var total_sent: usize = 0;
            while (total_sent < send_buffer.items.len) {
                const sent = try self.socket.send(send_buffer.items[total_sent..]);
                logger.debug("c->s {d}", .{sent});
                total_sent += sent;
            }

            return data.len;
        }
    };
}
