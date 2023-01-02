const std = @import("std");
const network = @import("network");
const crypto = @import("crypto.zig");
const headers = @import("headers.zig");
const salts = @import("salts.zig");

pub fn Server(comptime TCrypto: type) type {
    return struct {
        fn readContent(buffer: []const u8, content: []u8, encryptor: *TCrypto.Encryptor) !void {
            const encrypted = buffer[0 .. buffer.len - TCrypto.tag_length];
            var tag: [TCrypto.tag_length]u8 = undefined;
            std.mem.copy(u8, &tag, buffer[buffer.len - TCrypto.tag_length .. buffer.len]);
            try encryptor.decrypt(content, encrypted, tag);
        }

        const ClientStatus = enum {
            wait_for_fixed,
            wait_for_variable,
            wait_for_length,
            wait_for_payload,
        };

        const ClientState = struct {
            status: ClientStatus = .wait_for_fixed,

            socket: network.Socket,
            remote_socket: network.Socket,
            socket_set: *network.SocketSet,
            recv_buffer: std.ArrayList(u8),

            request_salt: [TCrypto.salt_length]u8 = undefined,
            response_salt: [TCrypto.salt_length]u8 = undefined,
            key: [TCrypto.key_length]u8,

            sent_initial_response: bool = false,
            response_encryptor: TCrypto.Encryptor,

            length: u16 = undefined,
            request_decryptor: TCrypto.Encryptor = undefined,
            session_subkey: [TCrypto.key_length]u8 = undefined,

            fn init(socket: network.Socket, key: [TCrypto.key_length]u8, socket_set: *network.SocketSet, allocator: std.mem.Allocator) !@This() {
                var response_salt = try TCrypto.generateRandomSalt();

                var remote_socket = try network.Socket.create(.ipv4, .tcp);
                errdefer remote_socket.close();

                var recv_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
                errdefer recv_buffer.deinit();

                return .{
                    .socket = socket,
                    .remote_socket = remote_socket,
                    .socket_set = socket_set,
                    .key = key,
                    .response_salt = response_salt,
                    .response_encryptor = .{
                        .key = TCrypto.deriveSessionSubkeyWithSalt(key, response_salt),
                    },
                    .recv_buffer = recv_buffer,
                };
            }

            fn deinit(self: @This()) void {
                self.remote_socket.close();
            }
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

        const ShadowsocksError = error{
            InitialRequestTooSmall,
            UnknownAddressType,
            Unsupported,
            CantConnectToRemote,
            RemoteDisconnected,
            ClientDisconnected,
            DuplicateSalt,
            NoInitialPayloadOrPadding,
            TimestampTooOld,
        };

        fn handleWaitForFixed(state: *ClientState, server_state: *ServerState) !bool {
            // Initial request needs to have at least the fixed length header
            if (state.recv_buffer.items.len < TCrypto.salt_length + 11 + TCrypto.tag_length) {
                return ShadowsocksError.InitialRequestTooSmall;
            }

            std.mem.copy(u8, &state.request_salt, state.recv_buffer.items[0..TCrypto.salt_length]);

            // Detect replay attacks with duplicate salts
            const time: u64 = @intCast(u64, std.time.milliTimestamp());
            server_state.request_salt_cache.removeAfterTime(time + 60 * std.time.ms_per_s);

            if (!try server_state.request_salt_cache.maybeAdd(&state.request_salt, time)) {
                return ShadowsocksError.DuplicateSalt;
            }

            state.request_decryptor = .{
                .key = TCrypto.deriveSessionSubkeyWithSalt(state.key, state.request_salt),
            };

            var decrypted: [11]u8 = undefined;
            try readContent(
                state.recv_buffer.items[TCrypto.salt_length .. TCrypto.salt_length + 11 + TCrypto.tag_length],
                &decrypted,
                &state.request_decryptor,
            );

            const decoded_header = (try headers.FixedLengthRequestHeader.decode(&decrypted)).result;

            // Detect replay attacks by checking for old timestamps
            if (@intCast(u64, std.time.timestamp()) > decoded_header.timestamp + 30) {
                return ShadowsocksError.TimestampTooOld;
            }

            state.length = decoded_header.length;
            state.status = .wait_for_variable;

            try state.recv_buffer.replaceRange(0, TCrypto.salt_length + 11 + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForVariable(state: *ClientState, allocator: std.mem.Allocator) !bool {
            if (state.recv_buffer.items.len < state.length + TCrypto.tag_length) {
                return false;
            }

            var decrypted: []u8 = try allocator.alloc(u8, state.length);
            defer allocator.free(decrypted);

            try readContent(state.recv_buffer.items[0 .. state.length + TCrypto.tag_length], decrypted, &state.request_decryptor);

            const decoded_header = (try headers.VariableLengthRequestHeader.decode(decrypted, state.length, allocator)).result;

            if (decoded_header.padding.len == 0 and decoded_header.initial_payload.len == 0) {
                return ShadowsocksError.NoInitialPayloadOrPadding;
            }

            switch (decoded_header.address_type) {
                1 => {
                    const address = decoded_header.address[0..4];

                    try state.remote_socket.connect(.{
                        .address = .{ .ipv4 = .{ .value = address.* } },
                        .port = decoded_header.port,
                    });
                },
                3 => {
                    const name = decoded_header.address;
                    const endpoint_list = try network.getEndpointList(allocator, name, decoded_header.port);
                    defer endpoint_list.deinit();

                    state.remote_socket.close();

                    var connected: bool = false;
                    for (endpoint_list.endpoints) |endpt| {
                        var sock = try network.Socket.create(@as(network.AddressFamily, endpt.address), .tcp);
                        sock.connect(endpt) catch {
                            sock.close();
                            continue;
                        };

                        state.remote_socket = sock;
                        connected = true;
                        break;
                    }

                    if (!connected) {
                        return ShadowsocksError.CantConnectToRemote;
                    }
                },
                4 => {
                    const address = decoded_header.address[0..16];

                    try state.remote_socket.connect(.{
                        .address = .{ .ipv6 = network.Address.IPv6.init(address.*, 0) },
                        .port = decoded_header.port,
                    });
                },
                else => {
                    return ShadowsocksError.UnknownAddressType;
                },
            }

            try state.socket_set.add(state.remote_socket, .{
                .read = true,
                .write = false,
            });

            var total_sent: usize = 0;
            while (total_sent < decoded_header.initial_payload.len) {
                const sent = try state.remote_socket.send(decoded_header.initial_payload[total_sent..]);
                std.debug.print("s->r {d}\n", .{sent});

                if (sent == 0) {
                    return ShadowsocksError.ClientDisconnected;
                }

                total_sent += sent;
            }

            state.status = .wait_for_length;

            try state.recv_buffer.replaceRange(0, state.length + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForLength(state: *ClientState) !bool {
            if (state.recv_buffer.items.len < 2 + TCrypto.tag_length) {
                return false;
            }

            var decrypted: [2]u8 = undefined;
            try readContent(state.recv_buffer.items[0 .. 2 + TCrypto.tag_length], &decrypted, &state.request_decryptor);

            state.length = std.mem.readIntBig(u16, &decrypted);
            state.status = .wait_for_payload;

            try state.recv_buffer.replaceRange(0, 2 + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForPayload(state: *ClientState, allocator: std.mem.Allocator) !bool {
            if (state.recv_buffer.items.len < state.length + TCrypto.tag_length) {
                return false;
            }

            var decrypted: []u8 = try allocator.alloc(u8, state.length);
            defer allocator.free(decrypted);

            try readContent(state.recv_buffer.items[0 .. state.length + TCrypto.tag_length], decrypted, &state.request_decryptor);

            var total_sent: usize = 0;
            while (total_sent < decrypted.len) {
                const sent = try state.remote_socket.send(decrypted[total_sent..]);
                std.debug.print("s->r {d}\n", .{sent});

                if (sent == 0) {
                    return ShadowsocksError.ClientDisconnected;
                }

                total_sent += sent;
            }

            state.status = .wait_for_length;

            try state.recv_buffer.replaceRange(0, state.length + TCrypto.tag_length, &.{});

            return true;
        }

        fn forwardToClient(state: *ClientState, received: []const u8, allocator: std.mem.Allocator) !void {
            var send_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
            defer send_buffer.deinit();

            if (!state.sent_initial_response) {
                try send_buffer.appendSlice(&state.response_salt);

                const THeader = headers.FixedLengthResponseHeader(TCrypto.salt_length);

                const header: THeader = .{
                    .type = 1,
                    .timestamp = @intCast(u64, std.time.timestamp()),
                    .salt = state.request_salt,
                    .length = @intCast(u16, received.len),
                };

                var encoded: [THeader.size]u8 = undefined;
                _ = try header.encode(&encoded);

                var encrypted: [encoded.len]u8 = undefined;
                var tag: [TCrypto.tag_length]u8 = undefined;
                state.response_encryptor.encrypt(&encoded, &encrypted, &tag);

                try send_buffer.appendSlice(&encrypted);
                try send_buffer.appendSlice(&tag);

                state.sent_initial_response = true;
            } else {
                var encoded: [2]u8 = undefined;
                std.mem.writeIntBig(u16, &encoded, @intCast(u16, received.len));

                var encrypted_and_tag: [2 + TCrypto.tag_length]u8 = undefined;
                state.response_encryptor.encrypt(&encoded, encrypted_and_tag[0..2], encrypted_and_tag[2 .. 2 + TCrypto.tag_length]);

                try send_buffer.appendSlice(&encrypted_and_tag);
            }

            var encrypted: []u8 = try allocator.alloc(u8, received.len);
            defer allocator.free(encrypted);

            var tag: [TCrypto.tag_length]u8 = undefined;
            state.response_encryptor.encrypt(received, encrypted, &tag);
            try send_buffer.appendSlice(encrypted);
            try send_buffer.appendSlice(&tag);

            var total_sent: usize = 0;
            while (total_sent < send_buffer.items.len) {
                const sent = try state.socket.send(send_buffer.items[total_sent..]);
                std.debug.print("s->r {d}\n", .{sent});

                if (sent == 0) {
                    return ShadowsocksError.RemoteDisconnected;
                }

                total_sent += sent;
            }
        }

        fn closeSocketWithRst(socket: network.Socket) void {
            const Linger = extern struct {
                l_onoff: c_int,
                l_linger: c_int,
            };

            const value: Linger = .{
                .l_onoff = 1,
                .l_linger = 0,
            };

            std.os.setsockopt(socket.internal, std.os.SOL.SOCKET, std.os.SO.LINGER, std.mem.asBytes(&value)) catch |err| {
                std.debug.print("Failed to set SO_LINGER: {s}", .{@errorName(err)});
            };

            socket.close();
        }

        fn handleClient(socket: network.Socket, server_state: *ServerState, allocator: std.mem.Allocator) !void {
            var socket_set = try network.SocketSet.init(allocator);
            defer socket_set.deinit();

            var state = try ClientState.init(socket, server_state.key, &socket_set, allocator);
            defer state.deinit();

            try state.socket_set.add(state.socket, .{
                .read = true,
                .write = false,
            });

            var buffer: [1024]u8 = undefined;
            while (true) {
                _ = try network.waitForSocketEvent(state.socket_set, null);

                // Buffer data sent from client to server
                if (state.socket_set.isReadyRead(state.socket)) {
                    const count = try state.socket.receive(&buffer);
                    std.debug.print("c->s {d}\n", .{count});

                    if (count == 0) {
                        return ShadowsocksError.ClientDisconnected;
                    }

                    try state.recv_buffer.appendSlice(buffer[0..count]);
                }

                // Forward data sent from remote to server to client
                if (state.socket_set.isReadyRead(state.remote_socket)) {
                    const count = try state.remote_socket.receive(&buffer);
                    std.debug.print("r->s {d}\n", .{count});

                    if (count == 0) {
                        return ShadowsocksError.RemoteDisconnected;
                    }

                    try forwardToClient(&state, buffer[0..count], allocator);
                }

                // Handle buffered data received from the client
                while (true) {
                    switch (state.status) {
                        .wait_for_fixed => {
                            if (!try handleWaitForFixed(&state, server_state)) break;
                        },
                        .wait_for_variable => {
                            if (!try handleWaitForVariable(&state, allocator)) break;
                        },
                        .wait_for_length => {
                            if (!try handleWaitForLength(&state)) break;
                        },
                        .wait_for_payload => {
                            if (!try handleWaitForPayload(&state, allocator)) break;
                        },
                    }
                }
            }
        }

        fn handleClientCatchAll(socket: network.Socket, server_state: *ServerState, on_error: anytype, allocator: std.mem.Allocator) void {
            handleClient(socket, server_state, allocator) catch |err| {
                if (err != ShadowsocksError.ClientDisconnected and err != ShadowsocksError.RemoteDisconnected) {
                    closeSocketWithRst(socket);
                } else {
                    socket.close();
                }

                on_error(err);
            };
        }

        fn onClientError(err: anytype) void {
            std.debug.print("client terminated: {s}\n", .{@errorName(err)});
        }

        pub fn start(port: u16, key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !void {
            var socket = try network.Socket.create(.ipv4, .tcp);
            defer socket.close();
            try socket.bindToPort(port);
            try socket.listen();

            var server_state = ServerState.init(key, allocator);
            defer server_state.deinit();

            std.debug.print("Listening on port {d}\n", .{port});

            while (true) {
                var client = try socket.accept();
                std.debug.print("Accepted new client\n", .{});

                (try std.Thread.spawn(.{}, handleClientCatchAll, .{ client, &server_state, onClientError, allocator })).detach();
            }

            std.debug.print("Done", .{});
        }
    };
}
