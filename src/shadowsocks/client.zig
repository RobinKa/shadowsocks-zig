const std = @import("std");
const network = @import("network");
const headers = @import("headers.zig");
const crypto = @import("crypto.zig");

const ClientState = enum {
    wait_header,
    wait_length,
    wait_payload,
};

pub const Client = struct {
    socket: network.Socket,
    response_salt: [32]u8 = undefined,
    initial_response_received: bool = false,
    recv_buffer: std.ArrayList(u8),
    request_encryptor: crypto.Encryptor = undefined,
    response_decryptor: crypto.Encryptor = undefined,
    key: [32]u8,
    next_length: u16 = undefined,
    state: ClientState = .wait_header,
    received_payload: std.ArrayList(u8),

    pub fn connect(address: [4]u8, port: u16, remote_name: []const u8, remote_port: u16, key: [32]u8, initial_payload: []const u8) !@This() {
        var socket = try network.Socket.create(.ipv4, .tcp);

        try socket.connect(.{
            .address = .{ .ipv4 = .{ .value = address } },
            .port = port,
        });

        var seed: [std.rand.DefaultCsprng.secret_seed_length]u8 = undefined;
        try std.os.getrandom(&seed);
        var prng = std.rand.DefaultCsprng.init(seed);

        var request_salt: [32]u8 = undefined;
        prng.fill(&request_salt);
        var request_session_subkey: [32]u8 = undefined;

        {
            var key_and_request_salt = std.ArrayList(u8).init(std.heap.page_allocator);
            defer key_and_request_salt.deinit();
            try key_and_request_salt.appendSlice(&key);
            try key_and_request_salt.appendSlice(&request_salt);
            crypto.deriveSessionSubkey(key_and_request_salt.items, &request_session_subkey);
        }

        var request_encryptor = crypto.Encryptor{
            .key = request_session_subkey,
        };

        const padding_length = if (initial_payload.len == 0) std.rand.Random.intRangeLessThan(prng.random(), u16, 1, 901) else 0;
        var padding = try std.heap.page_allocator.alloc(u8, padding_length);
        defer std.heap.page_allocator.free(padding);
        if (padding_length > 0) {
            prng.fill(padding);
        }

        var remote_name_mutable = try std.heap.page_allocator.alloc(u8, remote_name.len);
        defer std.heap.page_allocator.free(remote_name_mutable);
        std.mem.copy(u8, remote_name_mutable, remote_name);

        var initial_payload_mutable = try std.heap.page_allocator.alloc(u8, initial_payload.len);
        defer std.heap.page_allocator.free(initial_payload_mutable);
        std.mem.copy(u8, initial_payload_mutable, initial_payload);

        const variable_header = headers.VariableLengthRequestHeader{
            .address_type = 3,
            .address = remote_name_mutable,
            .port = remote_port,
            .padding_length = padding_length,
            .padding = padding,
            .initial_payload = initial_payload_mutable,
        };

        var encoded_variable_header: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&encoded_variable_header);
        var writer = stream.writer();
        try variable_header.encode(writer);
        const encoded_variable_header_size = stream.pos;

        const fixed_header = headers.FixedLengthRequestHeader{
            .type = 0,
            .timestamp = @intCast(u64, std.time.timestamp()),
            .length = @intCast(u16, encoded_variable_header_size),
        };

        var encoded_fixed_header: [11]u8 = undefined;
        stream = std.io.fixedBufferStream(&encoded_fixed_header);
        writer = stream.writer();
        try fixed_header.encode(writer);

        var encrypted_fixed_header: [11]u8 = undefined;
        var encrypted_fixed_header_tag: [16]u8 = undefined;
        request_encryptor.encrypt(&encoded_fixed_header, &encrypted_fixed_header, &encrypted_fixed_header_tag);

        var encrypted_variable_header: [1024]u8 = undefined;
        var encrypted_variable_header_tag: [16]u8 = undefined;
        request_encryptor.encrypt(encoded_variable_header[0..encoded_variable_header_size], encrypted_variable_header[0..encoded_variable_header_size], &encrypted_variable_header_tag);

        var send_buffer = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 1024);
        try send_buffer.appendSlice(&request_salt);
        try send_buffer.appendSlice(&encrypted_fixed_header);
        try send_buffer.appendSlice(&encrypted_fixed_header_tag);
        try send_buffer.appendSlice(encrypted_variable_header[0..encoded_variable_header_size]);
        try send_buffer.appendSlice(&encrypted_variable_header_tag);

        var total_sent: usize = 0;
        while (total_sent < send_buffer.items.len) {
            const sent = try socket.send(send_buffer.items);
            std.debug.print("c->s {d}\n", .{sent});
            total_sent += sent;
        }

        return .{
            .socket = socket,
            .key = key,
            .request_encryptor = request_encryptor,
            .received_payload = std.ArrayList(u8).init(std.heap.page_allocator),
            .recv_buffer = std.ArrayList(u8).init(std.heap.page_allocator),
        };
    }

    fn waitHeader(self: *@This()) !bool {
        if (self.recv_buffer.items.len < 32 + 43 + 16) {
            return false;
        }

        std.mem.copy(u8, &self.response_salt, self.recv_buffer.items[0..32]);

        {
            var key_and_response_salt = std.ArrayList(u8).init(std.heap.page_allocator);
            defer key_and_response_salt.deinit();
            try key_and_response_salt.appendSlice(&self.key);
            try key_and_response_salt.appendSlice(&self.response_salt);

            var response_session_subkey: [32]u8 = undefined;
            crypto.deriveSessionSubkey(key_and_response_salt.items, &response_session_subkey);

            self.response_decryptor = .{
                .key = response_session_subkey,
            };
        }

        const encrypted_response_header = self.recv_buffer.items[32 .. 32 + 43];
        var encrypted_response_header_tag: [16]u8 = undefined;
        std.mem.copy(u8, &encrypted_response_header_tag, self.recv_buffer.items[32 + 43 .. 32 + 43 + 16]);
        var encoded_response_header: [43]u8 = undefined;
        try self.response_decryptor.decrypt(&encoded_response_header, encrypted_response_header, encrypted_response_header_tag);

        var stream = std.io.fixedBufferStream(&encoded_response_header);
        var reader = stream.reader();
        const response_header = try headers.FixedLengthResponseHeader.decode(reader);

        // TODO: check response_header.request_salt == self.request_salt
        // TODO: check timestamp

        self.next_length = response_header.length;
        try self.recv_buffer.replaceRange(0, 32 + 43 + 16, &.{});

        self.state = .wait_payload;

        return true;
    }

    fn waitLength(self: *@This()) !bool {
        if (self.recv_buffer.items.len < 2 + 16) {
            return false;
        }

        const encrypted_length = self.recv_buffer.items[0..2];
        var tag: [16]u8 = undefined;
        std.mem.copy(u8, &tag, self.recv_buffer.items[2 .. 2 + 16]);
        var encoded_length: [2]u8 = undefined;
        try self.response_decryptor.decrypt(&encoded_length, encrypted_length, tag);

        self.next_length = std.mem.readIntBig(u16, encoded_length[0..2]);
        try self.recv_buffer.replaceRange(0, 18, &.{});

        self.state = .wait_payload;

        return true;
    }

    fn waitPayload(self: *@This()) !bool {
        if (self.recv_buffer.items.len < self.next_length + 16) {
            return false;
        }

        const encrypted_payload = self.recv_buffer.items[0..self.next_length];
        var encrypted_payload_tag: [16]u8 = undefined;
        std.mem.copy(u8, &encrypted_payload_tag, self.recv_buffer.items[self.next_length .. self.next_length + 16]);
        var payload = try std.heap.page_allocator.alloc(u8, encrypted_payload.len);
        defer std.heap.page_allocator.free(payload);

        try self.response_decryptor.decrypt(payload, encrypted_payload, encrypted_payload_tag);

        try self.recv_buffer.replaceRange(0, self.next_length + 16, &.{});
        try self.received_payload.appendSlice(payload);

        self.state = .wait_length;

        return true;
    }

    fn getPacket(self: *@This(), data: []u8) !usize {
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
                    if (!try self.waitPayload()) {
                        return 0;
                    }
                },
            }
        }
    }

    pub fn receive(self: *@This(), data: []u8) !usize {
        var payload_size = try self.getPacket(data);
        if (payload_size > 0) {
            return payload_size;
        }

        while (true) {
            var buffer: [1024]u8 = undefined;
            var received = try self.socket.receive(&buffer);
            std.debug.print("s->c {d}\n", .{received});
            try self.recv_buffer.appendSlice(buffer[0..received]);

            payload_size = try self.getPacket(data);
            if (payload_size > 0) {
                return payload_size;
            }
        }
    }

    pub fn send(self: *@This(), data: []const u8) !usize {
        var send_buffer = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 2 + 16 + data.len + 16);
        defer send_buffer.deinit();

        {
            var encoded_length: [2]u8 = undefined;
            std.mem.writeIntBig(u16, &encoded_length, @intCast(u16, data.len));

            var encrypted_length: [2]u8 = undefined;
            var tag: [16]u8 = undefined;

            self.request_encryptor.encrypt(&encoded_length, &encrypted_length, &tag);

            try send_buffer.appendSlice(&encrypted_length);
            try send_buffer.appendSlice(&tag);
        }

        {
            var encrypted_data: []u8 = try std.heap.page_allocator.alloc(u8, data.len);
            defer std.heap.page_allocator.free(encrypted_data);

            var tag: [16]u8 = undefined;
            self.request_encryptor.encrypt(data, encrypted_data, &tag);

            try send_buffer.appendSlice(encrypted_data);
            try send_buffer.appendSlice(&tag);
        }

        var total_sent: usize = 0;
        while (total_sent < send_buffer.items.len) {
            const sent = try self.socket.send(send_buffer.items[total_sent..]);
            std.debug.print("c->s {d}\n", .{sent});
            total_sent += sent;
        }

        return data.len;
    }
};
