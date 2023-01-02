const std = @import("std");
const builtin = @import("builtin");
const network = @import("network");
const shadowsocks_client = @import("client.zig");
const shadowsocks_server = @import("server.zig");

const MitmData = struct {
    sent: std.ArrayList(u8),
    received: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator) @This() {
        return .{
            .sent = std.ArrayList(u8).init(allocator),
            .received = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: @This()) void {
        self.sent.deinit();
        self.received.deinit();
    }
};

fn startMitmProxy(
    port: u16,
    remote_address: network.EndPoint,
    mitm_data: *MitmData,
    allocator: std.mem.Allocator,
) !void {
    var listen_socket = try network.Socket.create(.ipv4, .tcp);
    defer listen_socket.close();
    try listen_socket.bindToPort(port);
    try listen_socket.listen();

    while (true) {
        var client_socket = try listen_socket.accept();
        defer client_socket.close();

        var remote_socket = try network.Socket.create(.ipv4, .tcp);
        defer remote_socket.close();
        try remote_socket.connect(remote_address);

        var socket_set = try network.SocketSet.init(allocator);
        defer socket_set.deinit();
        try socket_set.add(client_socket, .{ .read = true, .write = false });
        try socket_set.add(remote_socket, .{ .read = true, .write = false });

        var buffer: [1024]u8 = undefined;

        while (true) {
            _ = try network.waitForSocketEvent(&socket_set, null);

            // c->s->r
            if (socket_set.isReadyRead(client_socket)) {
                const count = try client_socket.receive(&buffer);

                if (count == 0) {
                    break;
                }

                try mitm_data.sent.appendSlice(buffer[0..count]);

                var sent: usize = 0;
                while (sent < count) {
                    sent += try remote_socket.send(buffer[sent..count]);
                }
            }

            // r->s->c
            if (socket_set.isReadyRead(remote_socket)) {
                const count = try remote_socket.receive(&buffer);

                if (count == 0) {
                    break;
                }

                try mitm_data.received.appendSlice(buffer[0..count]);

                var sent: usize = 0;
                while (sent < count) {
                    sent += try client_socket.send(buffer[sent..count]);
                }
            }
        }
    }
}

fn runProxyServer(port: u16, key: [32]u8) !void {
    try shadowsocks_server.start(port, key, std.heap.page_allocator);
}

fn waitCanConnect(port: u16) !void {
    var socket = try network.Socket.create(.ipv4, .tcp);
    defer socket.close();

    var retries: u8 = 0;
    while (true) {
        socket.connect(.{
            .address = .{ .ipv4 = .{ .value = .{ 127, 0, 0, 1 } } },
            .port = port,
        }) catch {
            retries += 1;
            if (retries >= 5) {
                return error.CantConnectToRemote;
            }
            std.debug.print("Failed to connect on attempt {d}, retrying\n", .{retries});
            std.time.sleep(std.time.ns_per_s);
            continue;
        };

        break;
    }
}

test "client send initial payload" {
    const port = 10_001;
    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, "AcxUIVEsMN7a5bk2swV8uCFb9MGkY5pZumaStQ4CVKc=");

    _ = try std.Thread.spawn(.{}, runProxyServer, .{ port, key });
    try waitCanConnect(port);

    const initial_payload = "GET / HTTP/1.1\r\nHost: eu.httpbin.org\r\n\r\n";

    var client = try shadowsocks_client.Client.connect(.{ 127, 0, 0, 1 }, port, "eu.httpbin.org", 80, key, initial_payload, std.testing.allocator);
    defer client.deinit();

    var recv_buffer: [1024]u8 = undefined;
    var total_received: usize = 0;
    while (total_received < 9593) {
        const recv_count = try client.receive(&recv_buffer, std.testing.allocator);

        if (total_received == 0) {
            const expected = "HTTP/1.1 200 OK\r\n";
            try std.testing.expectEqualStrings(expected, recv_buffer[0..expected.len]);
        }

        total_received += recv_count;
    }
}

test "client send non-initial payload" {
    const port = 10_002;
    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, "AcxUIVEsMN7a5bk2swV8uCFb9MGkY5pZumaStQ4CVKc=");

    _ = try std.Thread.spawn(.{}, runProxyServer, .{ port, key });
    try waitCanConnect(port);

    var client = try shadowsocks_client.Client.connect(.{ 127, 0, 0, 1 }, port, "eu.httpbin.org", 80, key, &.{}, std.testing.allocator);
    defer client.deinit();

    const payload = "GET / HTTP/1.1\r\nHost: eu.httpbin.org\r\n\r\n";
    var sent = try client.send(payload, std.testing.allocator);
    try std.testing.expectEqual(payload.len, sent);

    var recv_buffer: [1024]u8 = undefined;
    var total_received: usize = 0;
    while (total_received < 9593) {
        const recv_count = try client.receive(&recv_buffer, std.testing.allocator);

        if (total_received == 0) {
            const expected = "HTTP/1.1 200 OK\r\n";
            try std.testing.expectEqualStrings(expected, recv_buffer[0..expected.len]);
        }

        total_received += recv_count;
    }
}

test "MITM replay fails" {
    const mitm_port = 10_003;
    const proxy_port = 10_004;

    // Start MITM proxy
    var mitm_data = MitmData.init(std.heap.page_allocator);
    defer mitm_data.deinit();
    _ = try std.Thread.spawn(.{}, startMitmProxy, .{
        mitm_port,
        .{
            .address = .{ .ipv4 = .{ .value = .{ 127, 0, 0, 1 } } },
            .port = proxy_port,
        },
        &mitm_data,
        std.heap.page_allocator,
    });

    // Start Shadowsocks proxy
    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, "AcxUIVEsMN7a5bk2swV8uCFb9MGkY5pZumaStQ4CVKc=");
    _ = try std.Thread.spawn(.{}, runProxyServer, .{ proxy_port, key });
    try waitCanConnect(proxy_port);

    // Proxy original http request
    var client = try shadowsocks_client.Client.connect(.{ 127, 0, 0, 1 }, mitm_port, "eu.httpbin.org", 80, key, &.{}, std.testing.allocator);
    defer client.deinit();

    const payload = "GET / HTTP/1.1\r\nHost: eu.httpbin.org\r\n\r\n";
    var sent = try client.send(payload, std.testing.allocator);
    try std.testing.expectEqual(payload.len, sent);

    var recv_buffer: [1024]u8 = undefined;
    var total_received: usize = 0;
    while (total_received < 9593) {
        const recv_count = try client.receive(&recv_buffer, std.testing.allocator);

        if (total_received == 0) {
            const expected = "HTTP/1.1 200 OK\r\n";
            try std.testing.expectEqualStrings(expected, recv_buffer[0..expected.len]);
        }

        total_received += recv_count;
    }

    // Replay client sends, expect server not to reply
    var socket = try network.Socket.create(.ipv4, .tcp);
    defer socket.close();
    try socket.connect(.{
        .address = .{ .ipv4 = .{ .value = .{ 127, 0, 0, 1 } } },
        .port = proxy_port,
    });

    const replay_sent = try socket.send(mitm_data.sent.items);
    try std.testing.expectEqual(@as(usize, mitm_data.sent.items.len), replay_sent);

    const replay_received = socket.receive(&recv_buffer);

    // TODO: Windows
    if (builtin.os.tag != .windows) {
        try std.testing.expectError(network.Socket.ReceiveError.ConnectionResetByPeer, replay_received);
    }
}
