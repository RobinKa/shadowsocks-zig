pub const Crypto = @import("shadowsocks/crypto.zig");
pub const Headers = @import("shadowsocks/headers.zig");
pub const Server = @import("shadowsocks/server.zig");
pub const Client = @import("shadowsocks/client.zig");

const std = @import("std");
const network = @import("network");

test {
    _ = @import("shadowsocks/tests.zig");
    _ = @import("shadowsocks/salts.zig");
}

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
    _ = try header.encode(&encoded);

    var encrypted: [encoded.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    encode_encryptor.encrypt(&encoded, &encrypted, &tag);

    var decrypted: [encrypted.len]u8 = undefined;
    try decode_encryptor.decrypt(&decrypted, &encrypted, tag);

    const decoded = try Headers.FixedLengthRequestHeader.decode(&decrypted);

    try std.testing.expectEqual(@as(usize, 11), decoded.bytes_read);
    try std.testing.expectEqual(header.length, decoded.result.length);
    try std.testing.expectEqual(header.timestamp, decoded.result.timestamp);
    try std.testing.expectEqual(header.type, decoded.result.type);
}
