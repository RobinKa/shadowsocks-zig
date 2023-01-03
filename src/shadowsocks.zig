pub const crypto = @import("shadowsocks/crypto.zig");
pub const headers = @import("shadowsocks/headers.zig");
pub const server = @import("shadowsocks/server.zig");
pub const udp_server = @import("shadowsocks/udp_server.zig");
pub const client = @import("shadowsocks/client.zig");

const std = @import("std");
const network = @import("network");

test {
    _ = @import("shadowsocks/tests.zig");
    _ = @import("shadowsocks/salts.zig");
    _ = @import("shadowsocks/udp_server.zig");
}

test "FixedLengthRequestHeader - derive, encode, encrypt, decrypt, decode" {
    inline for (crypto.Methods) |TCrypto| {
        var salt: [TCrypto.salt_length]u8 = try TCrypto.generateRandomSalt();
        var key: [TCrypto.key_length]u8 = undefined;
        try std.os.getrandom(&key);

        var session_subkey = TCrypto.deriveSessionSubkeyWithSalt(key, salt);

        var encode_encryptor: TCrypto.Encryptor = .{
            .key = session_subkey,
        };

        var decode_encryptor: TCrypto.Encryptor = .{
            .key = session_subkey,
        };

        const header = headers.FixedLengthRequestHeader{
            .type = 0,
            .timestamp = 123,
            .length = 33,
        };

        var encoded: [headers.FixedLengthRequestHeader.size]u8 = undefined;
        _ = try header.encode(&encoded);

        var encrypted: [encoded.len]u8 = undefined;
        var tag: [TCrypto.tag_length]u8 = undefined;
        encode_encryptor.encrypt(&encoded, &encrypted, &tag);

        var decrypted: [encrypted.len]u8 = undefined;
        try decode_encryptor.decrypt(&decrypted, &encrypted, tag);

        const decoded = try headers.FixedLengthRequestHeader.decode(&decrypted);

        try std.testing.expectEqual(@as(usize, headers.FixedLengthRequestHeader.size), decoded.bytes_read);
        try std.testing.expectEqual(header.length, decoded.result.length);
        try std.testing.expectEqual(header.timestamp, decoded.result.timestamp);
        try std.testing.expectEqual(header.type, decoded.result.type);
    }
}
