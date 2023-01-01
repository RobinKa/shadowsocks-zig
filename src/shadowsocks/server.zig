const std = @import("std");
const network = @import("network");
const Crypto = @import("crypto.zig");
const Headers = @import("headers.zig");
const Salts = @import("salts.zig");

fn readContent(buffer: []const u8, content: []u8, encryptor: *Crypto.Encryptor) !void {
    const encrypted = buffer[0 .. buffer.len - 16];
    var tag: [16]u8 = undefined;
    std.mem.copy(u8, &tag, buffer[buffer.len - 16 .. buffer.len]);
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

    request_salt: [32]u8 = undefined,
    response_salt: [32]u8 = undefined,
    key: []const u8,

    sent_initial_response: bool = false,
    response_encryptor: Crypto.Encryptor,

    length: u16 = undefined,
    request_decryptor: Crypto.Encryptor = undefined,
    session_subkey: [32]u8 = undefined,

    fn deinit(self: @This()) void {
        self.socket.close();
        self.remote_socket.close();
        self.socket_set.deinit();
    }
};

const ServerState = struct {
    key: []const u8,
    request_salt_cache: Salts.SaltCache,

    fn init(key: []const u8, allocator: std.mem.Allocator) !@This() {
        return .{
            .key = key,
            .request_salt_cache = try Salts.SaltCache.init(allocator),
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

fn handleWaitForFixed(state: *ClientState, server_state: *ServerState, allocator: std.mem.Allocator) !bool {
    // Initial request needs to have at least the fixed length header
    if (state.recv_buffer.items.len < 32 + 11 + 16) {
        return ShadowsocksError.InitialRequestTooSmall;
    }

    var session_subkey: [32]u8 = undefined;

    std.mem.copy(u8, &state.request_salt, state.recv_buffer.items[0..32]);

    // Detect replay attacks with duplicate salts
    const time: u64 = @intCast(u64, std.time.milliTimestamp());
    server_state.request_salt_cache.removeSaltsAfterTime(time + 60 * std.time.ms_per_s);

    if (!try server_state.request_salt_cache.maybeAddRequestSalt(&state.request_salt, time)) {
        return ShadowsocksError.DuplicateSalt;
    }

    {
        var key_and_request_salt = std.ArrayList(u8).init(allocator);
        defer key_and_request_salt.deinit();
        try key_and_request_salt.appendSlice(state.key);
        try key_and_request_salt.appendSlice(&state.request_salt);
        Crypto.deriveSessionSubkey(key_and_request_salt.items, &session_subkey);
    }

    state.request_decryptor = .{
        .key = session_subkey,
    };

    var decrypted: [11]u8 = undefined;
    try readContent(state.recv_buffer.items[32 .. 32 + 11 + 16], &decrypted, &state.request_decryptor);

    var stream = std.io.fixedBufferStream(&decrypted);
    var reader = stream.reader();
    const decoded_header = try Headers.FixedLengthRequestHeader.decode(reader);

    // Detect replay attacks by checking for old timestamps
    if (@intCast(u64, std.time.timestamp()) > decoded_header.timestamp + 30) {
        return ShadowsocksError.TimestampTooOld;
    }

    state.length = decoded_header.length;
    state.status = .wait_for_variable;

    try state.recv_buffer.replaceRange(0, 32 + 11 + 16, &.{});

    return true;
}

fn handleWaitForVariable(state: *ClientState, allocator: std.mem.Allocator) !bool {
    if (state.recv_buffer.items.len < state.length + 16) {
        return false;
    }

    var decrypted: []u8 = try allocator.alloc(u8, state.length);
    defer allocator.free(decrypted);

    try readContent(state.recv_buffer.items[0 .. state.length + 16], decrypted, &state.request_decryptor);

    var stream = std.io.fixedBufferStream(decrypted);
    var reader = stream.reader();
    const decoded_header = try Headers.VariableLengthRequestHeader.decode(reader, state.length, allocator);

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

    try state.recv_buffer.replaceRange(0, state.length + 16, &.{});

    return true;
}

fn handleWaitForLength(state: *ClientState) !bool {
    if (state.recv_buffer.items.len < 18) {
        return false;
    }

    var decrypted: [2]u8 = undefined;
    try readContent(state.recv_buffer.items[0..18], &decrypted, &state.request_decryptor);

    state.length = std.mem.readIntBig(u16, &decrypted);
    state.status = .wait_for_payload;

    try state.recv_buffer.replaceRange(0, 18, &.{});

    return true;
}

fn handleWaitForPayload(state: *ClientState, allocator: std.mem.Allocator) !bool {
    if (state.recv_buffer.items.len < state.length + 16) {
        return false;
    }

    var decrypted: []u8 = try allocator.alloc(u8, state.length);
    defer allocator.free(decrypted);

    try readContent(state.recv_buffer.items[0 .. state.length + 16], decrypted, &state.request_decryptor);

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

    try state.recv_buffer.replaceRange(0, state.length + 16, &.{});

    return true;
}

fn handleResponse(state: *ClientState, received: []const u8, allocator: std.mem.Allocator) !void {
    var send_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
    defer send_buffer.deinit();

    if (!state.sent_initial_response) {
        try send_buffer.appendSlice(&state.response_salt);

        const header: Headers.FixedLengthResponseHeader = .{
            .type = 1,
            .timestamp = @intCast(u64, std.time.timestamp()),
            .salt = state.request_salt,
            .length = @intCast(u16, received.len),
        };

        var encoded: [43]u8 = undefined;
        var stream = std.io.fixedBufferStream(&encoded);
        var writer = stream.writer();
        try header.encode(writer);

        var encrypted: [encoded.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        state.response_encryptor.encrypt(&encoded, &encrypted, &tag);

        try send_buffer.appendSlice(&encrypted);
        try send_buffer.appendSlice(&tag);

        state.sent_initial_response = true;
    } else {
        var encoded: [2]u8 = undefined;
        std.mem.writeIntBig(u16, &encoded, @intCast(u16, received.len));

        var encrypted_and_tag: [18]u8 = undefined;
        state.response_encryptor.encrypt(&encoded, encrypted_and_tag[0..2], encrypted_and_tag[2..18]);

        try send_buffer.appendSlice(&encrypted_and_tag);
    }

    var encrypted: []u8 = try allocator.alloc(u8, received.len);
    defer allocator.free(encrypted);

    var tag: [16]u8 = undefined;
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

fn closeSocketNoLinger(socket: network.Socket) void {
    const SO_LINGER = 0x00000800;

    const Linger = extern struct {
        l_onoff: u16,
        l_linger: u16,
    };

    const value: Linger = .{
        .l_onoff = 0,
        .l_linger = 0,
    };

    std.os.setsockopt(socket.internal, std.os.SOL.SOCKET, SO_LINGER, std.mem.asBytes(&value)) catch |err| {
        std.debug.print("Failed to set SO_LINGER: {s}", .{@errorName(err)});
    };

    socket.close();
}

fn handleClient(socket: network.Socket, server_state: *ServerState, allocator: std.mem.Allocator) !void {
    var response_salt: [32]u8 = undefined;

    {
        var seed: [32]u8 = undefined;
        try std.os.getrandom(&seed);
        Crypto.generateRandomSalt(&response_salt, seed);
    }

    var response_session_subkey: [32]u8 = undefined;

    {
        var key_and_response_salt = std.ArrayList(u8).init(allocator);
        defer key_and_response_salt.deinit();
        try key_and_response_salt.appendSlice(server_state.key);
        try key_and_response_salt.appendSlice(&response_salt);
        Crypto.deriveSessionSubkey(key_and_response_salt.items, &response_session_subkey);
    }

    var socket_set = try network.SocketSet.init(allocator);

    // TODO: if any of the trys fail, things aren't cleaned up properly.
    var state = ClientState{
        .socket = socket,
        .remote_socket = try network.Socket.create(.ipv4, .tcp),
        .socket_set = &socket_set,
        .key = server_state.key[0..32],
        .response_salt = response_salt,
        .response_encryptor = .{
            .key = response_session_subkey,
        },
        .recv_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024),
    };
    defer state.deinit();

    try state.socket_set.add(state.socket, .{
        .read = true,
        .write = false,
    });

    var buffer: [1024]u8 = undefined;
    while (true) {
        _ = try network.waitForSocketEvent(state.socket_set, null);

        if (state.socket_set.isReadyRead(state.socket)) {
            const count = try state.socket.receive(&buffer);
            std.debug.print("c->s {d}\n", .{count});

            if (count == 0) {
                return ShadowsocksError.ClientDisconnected;
            }

            try state.recv_buffer.appendSlice(buffer[0..count]);
        }

        if (state.socket_set.isReadyRead(state.remote_socket)) {
            const count = try state.remote_socket.receive(&buffer);
            std.debug.print("r->s {d}\n", .{count});

            if (count == 0) {
                return ShadowsocksError.RemoteDisconnected;
            }

            try handleResponse(&state, buffer[0..count], allocator);
        }

        while (true) {
            switch (state.status) {
                .wait_for_fixed => {
                    if (!try handleWaitForFixed(&state, server_state, allocator)) break;
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

fn handleClientCatchAll(socket: network.Socket, server_state: *ServerState, allocator: std.mem.Allocator) void {
    handleClient(socket, server_state, allocator) catch |err| {
        std.debug.print("client terminated: {s}\n", .{@errorName(err)});
    };
}

pub fn start(port: u16, key: []const u8, allocator: std.mem.Allocator) !void {
    var socket = try network.Socket.create(.ipv4, .tcp);
    defer closeSocketNoLinger(socket);
    try socket.bindToPort(port);
    try socket.listen();

    var server_state = try ServerState.init(key, allocator);
    defer server_state.deinit();

    std.debug.print("Listening on port {d}\n", .{port});

    while (true) {
        var client = try socket.accept();
        std.debug.print("Accepted new client\n", .{});

        (try std.Thread.spawn(.{}, handleClientCatchAll, .{ client, &server_state, allocator })).detach();
        std.time.sleep(std.time.ns_per_us * 100);
    }

    std.debug.print("Done", .{});
}
