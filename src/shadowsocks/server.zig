const std = @import("std");
const network = @import("network");
const crypto = @import("crypto.zig");
const headers = @import("headers.zig");
const salts = @import("salts.zig");

const logger = std.log.scoped(.@"shadowsocks.server");

pub fn Server(comptime TCrypto: type) type {
    return struct {
        should_stop: *bool,
        thread: std.Thread,
        allocator: std.mem.Allocator,

        const Error = error{
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

        fn readContent(buffer: []const u8, content: []u8, encryptor: *TCrypto.Encryptor) !void {
            const encrypted = buffer[0 .. buffer.len - TCrypto.tag_length];
            var tag: [TCrypto.tag_length]u8 = undefined;
            @memcpy(&tag, buffer[buffer.len - TCrypto.tag_length .. buffer.len]);
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
                const response_salt = try TCrypto.generateRandomSalt();

                var remote_socket = try network.Socket.create(.ipv4, .tcp);
                errdefer remote_socket.close();

                var recv_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
                errdefer recv_buffer.deinit(allocator);

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

            fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                self.remote_socket.close();
                self.recv_buffer.deinit(allocator);
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

        fn handleWaitForFixed(state: *ClientState, allocator: std.mem.Allocator, server_state: *ServerState) !bool {
            // Initial request needs to have at least the fixed length header
            if (state.recv_buffer.items.len < TCrypto.salt_length + headers.FixedLengthRequestHeader.size + TCrypto.tag_length) {
                return Error.InitialRequestTooSmall;
            }

            @memcpy(&state.request_salt, state.recv_buffer.items[0..TCrypto.salt_length]);

            // Detect replay attacks with duplicate salts
            const now = std.time.Instant.now() catch unreachable;
            const time: u64 = @intCast(@divFloor(now.timestamp.nsec, std.time.ns_per_ms));
            server_state.request_salt_cache.removeAfterTime(time + 60 * std.time.ms_per_s);

            if (!try server_state.request_salt_cache.maybeAdd(&state.request_salt, time)) {
                return Error.DuplicateSalt;
            }

            state.request_decryptor = .{
                .key = TCrypto.deriveSessionSubkeyWithSalt(state.key, state.request_salt),
            };

            var decrypted: [headers.FixedLengthRequestHeader.size]u8 = undefined;
            try readContent(
                state.recv_buffer.items[TCrypto.salt_length .. TCrypto.salt_length + headers.FixedLengthRequestHeader.size + TCrypto.tag_length],
                &decrypted,
                &state.request_decryptor,
            );

            const decoded = try headers.FixedLengthRequestHeader.decode(&decrypted);

            // Detect replay attacks by checking for old timestamps
            if (@divFloor(now.timestamp.nsec, std.time.ns_per_s) > decoded.result.timestamp + 30) {
                return Error.TimestampTooOld;
            }

            state.length = decoded.result.length;
            state.status = .wait_for_variable;

            try state.recv_buffer.replaceRange(allocator, 0, TCrypto.salt_length + headers.FixedLengthRequestHeader.size + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForVariable(state: *ClientState, allocator: std.mem.Allocator) !bool {
            if (state.recv_buffer.items.len < state.length + TCrypto.tag_length) {
                return false;
            }

            const decrypted: []u8 = try allocator.alloc(u8, state.length);
            defer allocator.free(decrypted);

            try readContent(state.recv_buffer.items[0 .. state.length + TCrypto.tag_length], decrypted, &state.request_decryptor);

            const decoded = try headers.VariableLengthRequestHeader.decode(decrypted, state.length, allocator);
            defer decoded.deinit();

            if (decoded.result.padding_length == 0 and decoded.result.initial_payload.len == 0) {
                return Error.NoInitialPayloadOrPadding;
            }

            switch (decoded.result.address_type) {
                1 => {
                    const address = decoded.result.address[0..4];

                    try state.remote_socket.connect(.{
                        .address = .{ .ipv4 = .{ .value = address.* } },
                        .port = decoded.result.port,
                    });
                },
                3 => {
                    const name = decoded.result.address;
                    const endpoint_list = try network.getEndpointList(allocator, name, decoded.result.port);
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
                        return Error.CantConnectToRemote;
                    }
                },
                4 => {
                    const address = decoded.result.address[0..16];

                    try state.remote_socket.connect(.{
                        .address = .{ .ipv6 = network.Address.IPv6.init(address.*, 0) },
                        .port = decoded.result.port,
                    });
                },
                else => {
                    return Error.UnknownAddressType;
                },
            }

            try state.socket_set.add(state.remote_socket, .{
                .read = true,
                .write = false,
            });

            var total_sent: usize = 0;
            while (total_sent < decoded.result.initial_payload.len) {
                const sent = try state.remote_socket.send(decoded.result.initial_payload[total_sent..]);
                logger.debug("s->r {d}", .{sent});

                if (sent == 0) {
                    return Error.ClientDisconnected;
                }

                total_sent += sent;
            }

            state.status = .wait_for_length;

            try state.recv_buffer.replaceRange(allocator, 0, state.length + TCrypto.tag_length, &.{});

            return true;
        }

        fn handleWaitForLength(state: *ClientState) !bool {
            if (state.recv_buffer.items.len < 2 + TCrypto.tag_length) {
                return false;
            }

            var decrypted: [2]u8 = undefined;
            try readContent(state.recv_buffer.items[0 .. 2 + TCrypto.tag_length], &decrypted, &state.request_decryptor);

            state.length = std.mem.readInt(u16, &decrypted, .big);
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
                logger.debug("s->r {d}", .{sent});

                if (sent == 0) {
                    return Error.ClientDisconnected;
                }

                total_sent += sent;
            }

            state.status = .wait_for_length;

            try state.recv_buffer.replaceRange(0, state.length + TCrypto.tag_length, &.{});

            return true;
        }

        fn forwardToClient(state: *ClientState, received: []const u8, allocator: std.mem.Allocator) !void {
            var send_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
            defer send_buffer.deinit(allocator);

            if (!state.sent_initial_response) {
                try send_buffer.appendSlice(allocator, &state.response_salt);

                const THeader = headers.FixedLengthResponseHeader(TCrypto.salt_length);

                const now = std.time.Instant.now() catch unreachable;

                const header: THeader = .{
                    .type = 1,
                    .timestamp = @intCast(@divFloor(now.timestamp.nsec, std.time.ns_per_ms)),
                    .salt = state.request_salt,
                    .length = @intCast(received.len),
                };

                var encoded: [THeader.size]u8 = undefined;
                _ = try header.encode(&encoded);

                var encrypted: [encoded.len]u8 = undefined;
                var tag: [TCrypto.tag_length]u8 = undefined;
                state.response_encryptor.encrypt(&encoded, &encrypted, &tag);

                try send_buffer.appendSlice(allocator, &encrypted);
                try send_buffer.appendSlice(allocator, &tag);

                state.sent_initial_response = true;
            } else {
                var encoded: [2]u8 = undefined;
                const len16: u16 = @intCast(received.len);
                encoded[0] = @truncate(len16 >> 8);
                encoded[1] = @truncate(len16);

                var encrypted_and_tag: [2 + TCrypto.tag_length]u8 = undefined;
                state.response_encryptor.encrypt(&encoded, encrypted_and_tag[0..2], encrypted_and_tag[2 .. 2 + TCrypto.tag_length]);

                try send_buffer.appendSlice(allocator, &encrypted_and_tag);
            }

            const encrypted: []u8 = try allocator.alloc(u8, received.len);
            defer allocator.free(encrypted);

            var tag: [TCrypto.tag_length]u8 = undefined;
            state.response_encryptor.encrypt(received, encrypted, &tag);
            try send_buffer.appendSlice(allocator, encrypted);
            try send_buffer.appendSlice(allocator, &tag);

            var total_sent: usize = 0;
            while (total_sent < send_buffer.items.len) {
                const sent = try state.socket.send(send_buffer.items[total_sent..]);
                logger.debug("s->r {d}", .{sent});

                if (sent == 0) {
                    return Error.RemoteDisconnected;
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
                logger.err("Failed to set SO_LINGER: {s}", .{@errorName(err)});
            };

            socket.close();
        }

        fn handleClient(should_stop: *bool, socket: network.Socket, server_state: *ServerState, allocator: std.mem.Allocator) !void {
            var socket_set = try network.SocketSet.init(allocator);
            defer socket_set.deinit();

            var state = try ClientState.init(socket, server_state.key, &socket_set, allocator);
            defer state.deinit(allocator);

            try state.socket_set.add(state.socket, .{
                .read = true,
                .write = false,
            });

            var buffer: [1024]u8 = undefined;
            while (!should_stop.*) {
                _ = try network.waitForSocketEvent(state.socket_set, std.time.ns_per_ms);

                // Buffer data sent from client to server
                if (state.socket_set.isReadyRead(state.socket)) {
                    const count = try state.socket.receive(&buffer);
                    logger.debug("c->s {d}", .{count});

                    if (count == 0) {
                        return Error.ClientDisconnected;
                    }

                    try state.recv_buffer.appendSlice(allocator, buffer[0..count]);
                }

                // Forward data sent from remote to server to client
                if (state.socket_set.isReadyRead(state.remote_socket)) {
                    const count = try state.remote_socket.receive(&buffer);
                    logger.debug("r->s {d}", .{count});

                    if (count == 0) {
                        return Error.RemoteDisconnected;
                    }

                    try forwardToClient(&state, buffer[0..count], allocator);
                }

                // Handle buffered data received from the client
                while (true) {
                    switch (state.status) {
                        .wait_for_fixed => {
                            if (!try handleWaitForFixed(&state, allocator, server_state)) break;
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

        fn handleClientCatchAll(should_stop: *bool, socket: network.Socket, server_state: *ServerState, on_error: anytype, allocator: std.mem.Allocator) void {
            handleClient(should_stop, socket, server_state, allocator) catch |err| {
                if (err != Error.ClientDisconnected and err != Error.RemoteDisconnected) {
                    closeSocketWithRst(socket);
                } else {
                    socket.close();
                }

                on_error(err);
            };
        }

        fn onClientError(err: anytype) void {
            logger.info("client terminated: {s}", .{@errorName(err)});
        }

        fn startInternal(should_stop: *bool, port: u16, key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !void {
            var socket = try network.Socket.create(.ipv4, .tcp);
            defer socket.close();
            try socket.bindToPort(port);
            try socket.listen();

            var server_state = ServerState.init(key, allocator);
            defer server_state.deinit();

            var socket_set = try network.SocketSet.init(allocator);
            defer socket_set.deinit();

            try socket_set.add(socket, .{ .read = true, .write = false });

            logger.info("Listening on port {d}", .{port});

            var client_threads = try std.ArrayList(std.Thread).initCapacity(allocator, 0);
            defer client_threads.deinit(allocator);

            while (!should_stop.*) {
                _ = try network.waitForSocketEvent(&socket_set, std.time.ns_per_ms);

                if (socket_set.isReadyRead(socket)) {
                    const client = try socket.accept();
                    logger.info("Accepted new client", .{});

                    try client_threads.append(allocator, try std.Thread.spawn(
                        .{},
                        handleClientCatchAll,
                        .{ should_stop, client, &server_state, onClientError, allocator },
                    ));
                }
            }

            for (client_threads.items) |client_thread| {
                client_thread.join();
            }
        }

        pub fn start(port: u16, key: [TCrypto.key_length]u8, allocator: std.mem.Allocator) !@This() {
            const should_stop = try allocator.create(bool);
            const thread = try std.Thread.spawn(.{}, startInternal, .{ should_stop, port, key, allocator });

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

        pub fn stop(self: *@This()) void {
            self.should_stop.* = true;
            self.thread.join();
            self.allocator.destroy(self.should_stop);
        }
    };
}
