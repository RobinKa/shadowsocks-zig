pub const Crypto = @import("shadowsocks/crypto.zig");
pub const Headers = @import("shadowsocks/headers.zig");
pub const Server = @import("shadowsocks/server.zig");

const std = @import("std");
const network = @import("network");

test "FixedLengthRequestHeader - derive, encode, encrypt, decrypt, decode" {
    var session_subkey: [32]u8 = undefined;
    Crypto.deriveSessionSubkey("test key", &session_subkey);

    var encode_encryptor: Crypto.Encryptor = .{
        .key = session_subkey,
    };

    var decode_encryptor: Crypto.Encryptor = .{
        .key = session_subkey,
    };

    const header = Headers.FixedLengthRequestHeader{
        .type = 0,
        .timestamp = 123,
        .length = 33,
    };

    var encoded: [11]u8 = undefined;
    var stream = std.io.fixedBufferStream(&encoded);
    var writer = stream.writer();

    try header.encode(writer);

    var encrypted: [encoded.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    encode_encryptor.encrypt(&encoded, &encrypted, &tag);

    var decrypted: [encrypted.len]u8 = undefined;
    try decode_encryptor.decrypt(&decrypted, &encrypted, tag);

    stream = std.io.fixedBufferStream(&decrypted);
    var reader = stream.reader();

    const decoded_header = try Headers.FixedLengthRequestHeader.decode(reader);

    try std.testing.expectEqual(header.length, decoded_header.length);
    try std.testing.expectEqual(header.timestamp, decoded_header.timestamp);
    try std.testing.expectEqual(header.type, decoded_header.type);
}

// fn runEchoServer(port: u16) !void {
//     var listen_socket = try network.Socket.create(.ipv4, .tcp);
//     defer listen_socket.close();
//     try listen_socket.bindToPort(port);
//     try listen_socket.listen();

//     while (true) {
//         var client = try listen_socket.accept();

//         while (true) {
//             var data: [128]u8 = undefined;
//             var received = try client.receive(&data);

//             var sent: usize = 0;
//             while (sent < received) {
//                 sent += try client.send(data[sent..received]);
//             }
//         }
//     }
// }

// fn runProxyServer(port: u16, encoded_key: []const u8) !void {
//     var key: [32]u8 = undefined;
//     try std.base64.standard.Decoder.decode(&key, encoded_key);

//     try Server.start(port, &key);
// }

// test "Server - test proxying echo server" {
//     const encoded_key = "AcxUIVEsMN7a5bk2swV8uCFb9MGkY5pZumaStQ4CVKc=";

//     (try std.Thread.spawn(.{}, runEchoServer, .{5666})).detach();
//     (try std.Thread.spawn(.{}, runProxyServer, .{ 5667, encoded_key })).detach();

//     var socket = try network.connectToHost(std.testing.allocator, "127.0.0.1", 5666, .tcp);

//     const test_data = [_]u8{ 1, 2, 4, 4 };
//     _ = try socket.send(&test_data);
//     var data: [128]u8 = undefined;
//     var received = try socket.receive(&data);
//     try std.testing.expectEqualSlices(u8, &test_data, data[0..received]);
// }
