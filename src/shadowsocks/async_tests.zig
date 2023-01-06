const std = @import("std");
const network = @import("network");
const shadowsocks_client = @import("client.zig");
const async_server = @import("async_server.zig");
const crypto = @import("crypto.zig");

const logger = std.log.scoped(.@"shadowsocks.async_tests");

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
            const sleep_time_ms = std.math.shl(u64, 200, retries - 1);
            logger.info("Failed to connect on attempt {d}, retrying in {d}ms", .{ retries, sleep_time_ms });
            std.time.sleep(std.time.ns_per_ms * sleep_time_ms);
            continue;
        };

        break;
    }
}

fn httpClient(comptime TCrypto: type, port: u16, key: [TCrypto.key_length]u8, done: *bool) !void {
    //try waitCanConnect(port);
    std.time.sleep(std.time.ns_per_s);

    const initial_payload = "GET / HTTP/1.1\r\nHost: eu.httpbin.org\r\n\r\n";

    var client = try shadowsocks_client.Client(TCrypto).connect(
        .{ 127, 0, 0, 1 },
        port,
        "eu.httpbin.org",
        80,
        key,
        initial_payload,
        std.testing.allocator,
    );
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

    done.* = true;
}

fn clientSendInitialPayloadTest(comptime TCrypto: type, encoded_key: []const u8, port: u16) !void {
    var key: [TCrypto.key_length]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, encoded_key);

    var server = try async_server.Server(TCrypto).init(key, std.testing.allocator);
    defer server.deinit();
    
    try server.start(try std.net.Address.parseIp("0.0.0.0", port));

    var done = false;
    const client_thread = try std.Thread.spawn(.{}, httpClient, .{ TCrypto, port, key, &done });

    while (!done) {
        try server.tick();
    }

    client_thread.join();
}

test "client send initial payload - Blake3Aes256Gcm" {
    try clientSendInitialPayloadTest(crypto.Blake3Aes256Gcm, "AcxUIVEsMN7a5bk2swV8uCFb9MGkY5pZumaStQ4CVKc=", 10_001);
}
