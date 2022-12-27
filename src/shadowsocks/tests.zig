const std = @import("std");
const network = @import("network");
const shadowsocks_client = @import("client.zig");
const shadowsocks_server = @import("server.zig");

fn runProxyServer(port: u16, key: []const u8) !void {
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
            std.debug.print("Failed to connect on attempt {d}, retrying", .{retries});
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

    _ = try std.Thread.spawn(.{}, runProxyServer, .{ port, &key });
    try waitCanConnect(port);

    const initial_payload = "GET / HTTP/1.1\r\nHost: eu.httpbin.org\r\n\r\n";

    var client = try shadowsocks_client.Client.connect(.{ 127, 0, 0, 1 }, port, "eu.httpbin.org", 80, key, initial_payload);

    var recv_buffer: [1024]u8 = undefined;
    var total_received: usize = 0;
    while (total_received < 9593) {
        const recv_count = try client.receive(&recv_buffer);

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

    _ = try std.Thread.spawn(.{}, runProxyServer, .{ port, &key });
    try waitCanConnect(port);

    var client = try shadowsocks_client.Client.connect(.{ 127, 0, 0, 1 }, port, "eu.httpbin.org", 80, key, &.{});

    const payload = "GET / HTTP/1.1\r\nHost: eu.httpbin.org\r\n\r\n";
    var sent = try client.send(payload);
    try std.testing.expectEqual(payload.len, sent);

    var recv_buffer: [1024]u8 = undefined;
    var total_received: usize = 0;
    while (total_received < 9593) {
        const recv_count = try client.receive(&recv_buffer);

        if (total_received == 0) {
            const expected = "HTTP/1.1 200 OK\r\n";
            try std.testing.expectEqualStrings(expected, recv_buffer[0..expected.len]);
        }

        total_received += recv_count;
    }
}
