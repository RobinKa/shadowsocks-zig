const std = @import("std");
const async_io = @import("async_io");
const headers = @import("headers.zig");
const salts = @import("salts.zig");

test {
    _ = @import("async_tests.zig");
}

pub fn Server(comptime TCrypto: type) type {
    const ClientStatus = enum {
        wait_for_fixed,
        wait_for_variable,
        wait_for_length,
        wait_for_payload,
    };

    const ServerState = struct {
        key: [TCrypto.key_length]u8,
        request_salt_cache: salts.SaltCache,

        fn init(key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) @This() {
            return .{
                .key = key,
                .request_salt_cache = salts.SaltCache.init(allocator),
            };
        }

        fn deinit(self: *@This()) void {
            self.request_salt_cache.deinit();
        }
    };

    const ConnectedClient = struct {
        const Self = @This();

        io: *async_io.IO,

        client_socket: std.os.socket_t,
        client_receive_buffer: [1024]u8 = undefined,
        client_send_completion: async_io.IO.Completion = undefined,
        client_receive_completion: async_io.IO.Completion = undefined,
        client_close_completion: async_io.IO.Completion = undefined,

        remote_receive_buffer: [1024]u8 = undefined,
        remote_receive_buffer_sent: usize = 0,
        remote_receive_buffer_received: usize = 0,
        remote_send_completion: async_io.IO.Completion = undefined,
        remote_receive_completion: async_io.IO.Completion = undefined,
        remote_close_completion: async_io.IO.Completion = undefined,

        status: ClientStatus = .wait_for_fixed,

        client_to_server_buffer: std.ArrayList(u8),
        server_to_remote_buffer: std.ArrayList(u8),
        remote_to_client_buffer: std.ArrayList(u8),

        request_salt: [TCrypto.salt_length]u8 = undefined,
        response_salt: [TCrypto.salt_length]u8 = undefined,
        key: [TCrypto.key_length]u8,

        sent_initial_response: bool = false,
        response_encryptor: TCrypto.Encryptor,

        length: u16 = undefined,
        request_decryptor: TCrypto.Encryptor = undefined,
        session_subkey: [TCrypto.key_length]u8 = undefined,

        remote_socket: std.os.socket_t = undefined,
        remote_connected: bool = false,

        server_state: *ServerState,

        allocator: std.mem.Allocator,

        client_closed: bool = false,
        remote_closed: bool = false,

        fn init(
            socket: std.os.socket_t,
            state: *ServerState,
            io: *async_io.IO,
            allocator: std.mem.Allocator,
        ) !Self {
            var response_salt = try TCrypto.generateRandomSalt();

            var client_to_server_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
            errdefer client_to_server_buffer.deinit();

            var server_to_remote_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
            errdefer server_to_remote_buffer.deinit();

            var remote_to_client_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
            errdefer remote_to_client_buffer.deinit();

            return .{
                .client_socket = socket,
                .io = io,
                .server_state = state,
                .allocator = allocator,
                .key = state.key,
                .response_salt = response_salt,
                .response_encryptor = .{
                    .key = TCrypto.deriveSessionSubkeyWithSalt(state.key, response_salt),
                },
                .client_to_server_buffer = client_to_server_buffer,
                .server_to_remote_buffer = server_to_remote_buffer,
                .remote_to_client_buffer = remote_to_client_buffer,
            };
        }

        fn start(self: *Self) void {
            std.debug.print("[{d}] start\n", .{self.client_socket});
            self.clientReceive();
        }

        fn deinit(self: *Self) void {
            self.closeClient();
            self.client_to_server_buffer.deinit();
            self.server_to_remote_buffer.deinit();
            self.remote_to_client_buffer.deinit();
        }

        fn clientReceive(self: *Self) void {
            std.debug.print("[{d}] clientReceive\n", .{self.client_socket});
            self.io.recv(
                *Self,
                self,
                Self.onClientReceive,
                &self.client_receive_completion,
                self.client_socket,
                &self.client_receive_buffer,
            );
        }

        fn onClientReceive(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.RecvError!usize,
        ) void {
            std.debug.print("[{d}] onClientReceive\n", .{self.client_socket});

            if (self.client_closed) {
                std.debug.print("[{d}] onClientReceive - returning because client closed\n", .{self.client_socket});
                return;
            }

            _ = completion;
            const received = result catch |err| std.debug.panic("[{d}] onClientReceive error: {s}", .{ self.client_socket, @errorName(err) });
            std.debug.print("[{d}] onClientReceive - success {d}\n", .{ self.client_socket, received });

            if (received == 0) {
                self.closeClient();
                std.debug.print("[{d}] onClientReceive - returning because closed\n", .{self.client_socket});
                return;
            }

            self.client_to_server_buffer.appendSlice(self.client_receive_buffer[0..received]) catch @panic("client recv buffer append error");

            handleReceivedData(self) catch @panic("handle client data error");

            if (self.status != .wait_for_fixed and self.status != .wait_for_variable) {
                if (self.server_to_remote_buffer.items.len > 0 and self.remote_connected) {
                    self.remoteSend();
                }
            } else {
                self.clientReceive();
            }
        }

        fn anyClosed(self: Self) bool {
            return self.client_closed or self.remote_closed;
        }

        fn closeClient(self: *Self) void {
            if (!self.client_closed) {
                self.client_closed = true;
                std.debug.print("[{d}] closeClient\n", .{self.client_socket});
                self.io.close(*Self, self, onCloseClient, &self.client_close_completion, self.client_socket);
            }

            self.closeRemote();
        }

        fn onCloseClient(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.CloseError!void,
        ) void {
            std.debug.print("[{d}] onCloseClient\n", .{self.client_socket});
            _ = completion;
            _ = result catch |err| std.debug.panic("[{d}] onCloseClient error: {s}", .{ self.client_socket, @errorName(err) });
        }

        fn closeRemote(self: *Self) void {
            if (!self.remote_closed) {
                self.remote_closed = true;
                std.debug.print("[{d}] closeRemote\n", .{self.client_socket});
                if (self.remote_connected) {
                    self.io.close(*Self, self, onCloseRemote, &self.remote_close_completion, self.remote_socket);
                }
            }
        }

        fn onCloseRemote(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.CloseError!void,
        ) void {
            std.debug.print("[{d}] onCloseRemote\n", .{self.client_socket});
            _ = completion;
            _ = result catch |err| std.debug.panic("[{d}] onCloseRemote error: {s}", .{ self.client_socket, @errorName(err) });
        }

        fn readContent(buffer: []const u8, content: []u8, encryptor: *TCrypto.Encryptor) !void {
            const encrypted = buffer[0 .. buffer.len - TCrypto.tag_length];
            var tag: [TCrypto.tag_length]u8 = undefined;
            std.mem.copy(u8, &tag, buffer[buffer.len - TCrypto.tag_length .. buffer.len]);
            try encryptor.decrypt(content, encrypted, tag);
        }

        fn handleWaitForFixed(self: *Self) !bool {
            std.debug.print("[{d}] handleWaitForFixed\n", .{self.client_socket});
            // Initial request needs to have at least the fixed length header
            if (self.client_to_server_buffer.items.len < TCrypto.salt_length + headers.FixedLengthRequestHeader.size + TCrypto.tag_length) {
                return error.InitialRequestTooSmall;
            }

            std.mem.copy(
                u8,
                &self.request_salt,
                self.client_to_server_buffer.items[0..TCrypto.salt_length],
            );

            // Detect replay attacks with duplicate salts
            const time: u64 = @intCast(u64, std.time.milliTimestamp());
            self.server_state.request_salt_cache.removeAfterTime(time + 60 * std.time.ms_per_s);

            if (!try self.server_state.request_salt_cache.maybeAdd(&self.request_salt, time)) {
                return error.DuplicateSalt;
            }

            self.request_decryptor = .{
                .key = TCrypto.deriveSessionSubkeyWithSalt(self.key, self.request_salt),
            };

            var decrypted: [headers.FixedLengthRequestHeader.size]u8 = undefined;
            try readContent(
                self.client_to_server_buffer.items[TCrypto.salt_length .. TCrypto.salt_length + headers.FixedLengthRequestHeader.size + TCrypto.tag_length],
                &decrypted,
                &self.request_decryptor,
            );

            const decoded = try headers.FixedLengthRequestHeader.decode(&decrypted);

            // Detect replay attacks by checking for old timestamps
            if (@intCast(u64, std.time.timestamp()) > decoded.result.timestamp + 30) {
                return error.TimestampTooOld;
            }

            self.length = decoded.result.length;
            self.status = .wait_for_variable;

            try self.client_to_server_buffer.replaceRange(0, TCrypto.salt_length + headers.FixedLengthRequestHeader.size + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForVariable(self: *Self) !bool {
            std.debug.print("[{d}] handleWaitForVariable\n", .{self.client_socket});
            if (self.client_to_server_buffer.items.len < self.length + TCrypto.tag_length) {
                return false;
            }

            var decrypted: []u8 = try self.allocator.alloc(u8, self.length);
            defer self.allocator.free(decrypted);

            try readContent(
                self.client_to_server_buffer.items[0 .. self.length + TCrypto.tag_length],
                decrypted,
                &self.request_decryptor,
            );

            const decoded = try headers.VariableLengthRequestHeader.decode(decrypted, self.length, self.allocator);
            defer decoded.deinit();

            if (decoded.result.padding_length == 0 and decoded.result.initial_payload.len == 0) {
                return error.NoInitialPayloadOrPadding;
            }

            try self.server_to_remote_buffer.appendSlice(decoded.result.initial_payload);

            std.debug.print("[{d}] handleWaitForVariable - connect {s}:{d}\n", .{ self.client_socket, decoded.result.address, decoded.result.port });

            switch (decoded.result.address_type) {
                1 => {
                    const address = std.net.Address.initIp4(
                        decoded.result.address[0..4].*,
                        decoded.result.port,
                    );

                    self.remote_socket = try self.io.open_socket(
                        address.any.family,
                        std.os.SOCK.STREAM,
                        std.os.IPPROTO.TCP,
                    );

                    self.io.connect(
                        *Self,
                        self,
                        Self.onRemoteConnect,
                        &self.remote_receive_completion,
                        self.remote_socket,
                        address,
                    );
                },
                3 => {
                    const address_list = try std.net.getAddressList(
                        self.allocator,
                        decoded.result.address,
                        decoded.result.port,
                    );
                    defer address_list.deinit();

                    if (address_list.addrs.len == 0) {
                        return error.UnknownHostName;
                    }

                    for (address_list.addrs) |address| {
                        std.debug.print(
                            "[{d}] handleWaitForVariable - connect - name family: {d}\n",
                            .{ self.client_socket, address.any.family },
                        );

                        // if (address.any.family != std.os.AF.INET) {
                        //     continue;
                        // }

                        self.remote_socket = try self.io.open_socket(
                            address.any.family,
                            std.os.SOCK.STREAM,
                            std.os.IPPROTO.TCP,
                        );

                        self.io.connect(
                            *Self,
                            self,
                            Self.onRemoteConnect,
                            &self.remote_receive_completion,
                            self.remote_socket,
                            address,
                        );
                        break;
                    }
                },
                else => {
                    return error.UnknownAddressType;
                },
            }

            self.status = .wait_for_length;

            try self.client_to_server_buffer.replaceRange(0, self.length + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForLength(self: *Self) !bool {
            std.debug.print("[{d}] handleWaitForLength\n", .{self.client_socket});
            if (self.client_to_server_buffer.items.len < 2 + TCrypto.tag_length) {
                std.debug.print("[{d}] handleWaitForLength - too short\n", .{self.client_socket});
                return false;
            }

            var decrypted: [2]u8 = undefined;
            try readContent(
                self.client_to_server_buffer.items[0 .. 2 + TCrypto.tag_length],
                &decrypted,
                &self.request_decryptor,
            );

            self.length = std.mem.readIntBig(u16, &decrypted);
            self.status = .wait_for_payload;

            try self.client_to_server_buffer.replaceRange(0, 2 + TCrypto.tag_length, &.{});

            std.debug.print("[{d}] handleWaitForLength - success\n", .{self.client_socket});
            return true;
        }

        fn handleWaitForPayload(self: *Self) !bool {
            std.debug.print("[{d}] handleWaitForPayload\n", .{self.client_socket});
            if (self.client_to_server_buffer.items.len < self.length + TCrypto.tag_length) {
                return false;
            }

            var decrypted: []u8 = try self.allocator.alloc(u8, self.length);
            defer self.allocator.free(decrypted);

            try readContent(
                self.client_to_server_buffer.items[0 .. self.length + TCrypto.tag_length],
                decrypted,
                &self.request_decryptor,
            );

            try self.server_to_remote_buffer.appendSlice(decrypted);

            self.status = .wait_for_length;

            try self.client_to_server_buffer.replaceRange(
                0,
                self.length + TCrypto.tag_length,
                &.{},
            );

            return true;
        }

        fn onRemoteConnect(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.ConnectError!void,
        ) void {
            std.debug.print("[{d}] onRemoteConnect\n", .{self.client_socket});

            if (self.anyClosed()) {
                std.debug.print("[{d}] onRemoteConnect - returning because closed\n", .{self.client_socket});
                return;
            }

            if (result == error.ConnectionTimedOut) {
                std.debug.print("[{d}] onRemoteConnect - connection timed out\n", .{self.client_socket});
                self.closeClient();
                return;
            }

            _ = completion;
            _ = result catch |err| std.debug.panic("[{d}] connect error: {s}", .{ self.client_socket, @errorName(err) });
            self.remote_connected = true;
            std.debug.print("[{d}] onRemoteConnect - success\n", .{self.client_socket});

            self.remoteReceive();

            if (self.server_to_remote_buffer.items.len > 0) {
                self.remoteSend();
            } else {
                self.clientReceive();
            }
        }

        fn remoteReceive(self: *Self) void {
            std.debug.print("[{d}] remoteReceive\n", .{self.client_socket});
            self.io.recv(
                *Self,
                self,
                Self.onRemoteReceive,
                &self.remote_receive_completion,
                self.remote_socket,
                &self.remote_receive_buffer,
            );
        }

        fn onRemoteReceive(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.RecvError!usize,
        ) void {
            std.debug.print("[{d}] onRemoteReceive\n", .{self.client_socket});

            if (self.anyClosed()) {
                std.debug.print("[{d}] onRemoteReceive - returning because closed\n", .{self.client_socket});
                return;
            }

            _ = completion;
            const num_received = result catch @panic("remote recv error");

            std.debug.print("[{d}] onRemoteReceive - success {d}\n", .{ self.client_socket, num_received });

            if (num_received == 0) {
                std.debug.print("[{d}] onRemoteReceive - closing because num_received = 0\n", .{self.client_socket});
                self.closeRemote();
                return;
            }

            self.handleRemoteReceive(self.remote_receive_buffer[0..num_received]) catch |err| std.debug.panic("[{d}] handleRemoteReceive error: {s}", .{ self.client_socket, @errorName(err) });

            self.clientSend();
        }

        fn handleRemoteReceive(self: *Self, received: []const u8) !void {
            std.debug.print("[{d}] handleRemoteReceive {d}\n", .{ self.client_socket, received.len });
            if (!self.sent_initial_response) {
                try self.remote_to_client_buffer.appendSlice(&self.response_salt);

                const THeader = headers.FixedLengthResponseHeader(TCrypto.salt_length);

                const header: THeader = .{
                    .type = 1,
                    .timestamp = @intCast(u64, std.time.timestamp()),
                    .salt = self.request_salt,
                    .length = @intCast(u16, received.len),
                };

                var encoded: [THeader.size]u8 = undefined;
                _ = try header.encode(&encoded);

                var encrypted: [encoded.len]u8 = undefined;
                var tag: [TCrypto.tag_length]u8 = undefined;
                self.response_encryptor.encrypt(&encoded, &encrypted, &tag);

                try self.remote_to_client_buffer.appendSlice(&encrypted);
                try self.remote_to_client_buffer.appendSlice(&tag);

                self.sent_initial_response = true;
            } else {
                var encoded: [2]u8 = undefined;
                std.mem.writeIntBig(u16, &encoded, @intCast(u16, received.len));

                var encrypted_and_tag: [2 + TCrypto.tag_length]u8 = undefined;
                self.response_encryptor.encrypt(&encoded, encrypted_and_tag[0..2], encrypted_and_tag[2 .. 2 + TCrypto.tag_length]);

                try self.remote_to_client_buffer.appendSlice(&encrypted_and_tag);
            }

            var encrypted: []u8 = try self.allocator.alloc(u8, received.len);
            defer self.allocator.free(encrypted);

            var tag: [TCrypto.tag_length]u8 = undefined;
            self.response_encryptor.encrypt(received, encrypted, &tag);
            try self.remote_to_client_buffer.appendSlice(encrypted);
            try self.remote_to_client_buffer.appendSlice(&tag);
        }

        fn clientSend(self: *Self) void {
            std.debug.print("[{d}] clientSend\n", .{self.client_socket});

            self.io.send(
                *Self,
                self,
                Self.onClientSend,
                &self.client_send_completion,
                self.client_socket,
                self.remote_to_client_buffer.items,
            );
        }

        fn onClientSend(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.SendError!usize,
        ) void {
            std.debug.print("[{d}] onClientSend\n", .{self.client_socket});

            if (self.client_closed) {
                std.debug.print("[{d}] onClientSend - returning because client closed\n", .{self.client_socket});
                return;
            }

            _ = completion;

            const sent = result catch |err| std.debug.panic("[{d}] onClientSend error: {s}", .{ self.client_socket, @errorName(err) });

            std.debug.print("[{d}] onClientSend - success {d}\n", .{ self.client_socket, sent });

            if (sent == 0) {
                self.closeClient();
                std.debug.print("[{d}] onClientSend - returning because closed\n", .{self.client_socket});
                return;
            }

            self.remote_to_client_buffer.replaceRange(0, sent, &.{}) catch @panic("remote_to_client_buffer replace error");

            if (self.remote_to_client_buffer.items.len > 0) {
                self.clientSend();
            } else {
                self.remoteReceive();
            }
        }

        fn remoteSend(self: *Self) void {
            std.debug.print("[{d}] remoteSend\n", .{self.client_socket});

            if (self.remote_connected and
                self.server_to_remote_buffer.items.len > 0)
            {
                std.debug.print("[{d}] remoteSend - sending {d}\n", .{ self.client_socket, self.server_to_remote_buffer.items.len });
                self.io.send(
                    *Self,
                    self,
                    Self.onRemoteSend,
                    &self.remote_send_completion,
                    self.remote_socket,
                    self.server_to_remote_buffer.items,
                );
            } else {
                std.debug.print("[{d}] remoteSend - not sending\n", .{self.client_socket});
            }
        }

        fn onRemoteSend(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.SendError!usize,
        ) void {
            std.debug.print("[{d}] onRemoteSend\n", .{self.client_socket});

            if (self.anyClosed()) {
                std.debug.print("[{d}] onRemoteSend - returning because closed\n", .{self.client_socket});
                return;
            }

            _ = completion;

            const sent = result catch |err| std.debug.panic("send error: {s}", .{@errorName(err)});
            std.debug.print("[{d}] onRemoteSend - success {d}\n", .{ self.client_socket, sent });

            if (sent == 0) {
                self.closeClient();
                std.debug.print("[{d}] onRemoteSend - returning and closing because remote sent was 0\n", .{self.client_socket});
                return;
            }

            self.server_to_remote_buffer.replaceRange(0, sent, &.{}) catch @panic("shrink send buffer error");

            if (self.server_to_remote_buffer.items.len > 0) {
                self.remoteSend();
            } else {
                self.clientReceive();
            }
        }

        fn handleReceivedData(self: *Self) !void {
            std.debug.print("[{d}] handleReceivedData\n", .{self.client_socket});
            // Handle buffered data received from the client
            while (true) {
                switch (self.status) {
                    .wait_for_fixed => {
                        if (!try self.handleWaitForFixed()) break;
                    },
                    .wait_for_variable => {
                        if (!try self.handleWaitForVariable()) break;
                    },
                    .wait_for_length => {
                        if (!try self.handleWaitForLength()) break;
                    },
                    .wait_for_payload => {
                        if (!try self.handleWaitForPayload()) break;
                    },
                }
            }
        }
    };

    return struct {
        const Self = @This();

        io: async_io.IO,
        server_completion: async_io.IO.Completion = undefined,
        server_socket: std.os.socket_t = undefined,

        clients: std.ArrayList(*ConnectedClient),

        allocator: std.mem.Allocator,

        server_state: ServerState,

        pub fn init(key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !Self {
            var io = try async_io.IO.init(32, 0);
            errdefer io.deinit();

            var clients = std.ArrayList(*ConnectedClient).init(allocator);
            errdefer clients.deinit();

            return .{
                .io = io,
                .clients = clients,
                .allocator = allocator,
                .server_state = ServerState.init(key, allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.clients.items) |client| {
                client.deinit();
                self.allocator.destroy(client);
            }
            self.clients.deinit();

            std.os.closeSocket(self.server_socket);

            self.io.deinit();

            self.server_state.deinit();
        }

        pub fn start(self: *Self, address: std.net.Address) !void {
            self.server_socket = try self.io.open_socket(address.any.family, std.os.SOCK.STREAM, std.os.IPPROTO.TCP);
            std.debug.print("[{d}] start\n", .{self.server_socket});

            try std.os.bind(self.server_socket, &address.any, address.getOsSockLen());
            try std.os.listen(self.server_socket, 64);

            self.acceptNext();
        }

        pub fn tick(self: *Self) !void {
            try self.io.tick();
        }

        fn acceptNext(self: *Self) void {
            std.debug.print("[{d}] acceptNext\n", .{self.server_socket});
            self.io.accept(*Self, self, Self.onAccept, &self.server_completion, self.server_socket);
        }

        fn onAccept(
            self: *Self,
            completion: *async_io.IO.Completion,
            result: async_io.IO.AcceptError!std.os.socket_t,
        ) void {
            std.debug.print("[{d}] onAccept\n", .{self.server_socket});
            _ = completion;

            var client_socket = result catch |err| std.debug.panic("Accept error: {s}", .{@errorName(err)});

            var client = self.allocator.create(ConnectedClient) catch @panic("error allocating client");
            client.* = ConnectedClient.init(
                client_socket,
                &self.server_state,
                &self.io,
                self.allocator,
            ) catch @panic("create client error");
            client.start();
            self.clients.append(client) catch @panic("error appending client");

            self.acceptNext();
        }
    };
}

// test "async shadowsocks server" {
//     const crypto = @import("crypto.zig");
//     const key = [_]u8{1} ** 32;

//     var server = try Server(crypto.Blake3Aes256Gcm).init(key, std.testing.allocator);

//     try server.start(try std.net.Address.parseIp("127.0.0.1", 11_001));

//     const start_time = std.time.milliTimestamp();
//     while (std.time.milliTimestamp() - start_time < 3 * std.time.ms_per_s) {
//         try server.io.tick();
//     }

//     std.debug.print("done async", .{});
// }
