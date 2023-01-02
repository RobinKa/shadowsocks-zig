const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha8Poly1305 = std.crypto.aead.chacha_poly.ChaCha8Poly1305;
const ChaCha12Poly1305 = std.crypto.aead.chacha_poly.ChaCha12Poly1305;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub fn deriveSessionSubkey(key: []const u8, session_subkey: []u8) void {
    var blake = Blake3.initKdf("shadowsocks 2022 session subkey", .{});
    blake.update(key);
    blake.final(session_subkey);
}

fn Crypto(comptime TAlg: type, comptime salt_size: usize) type {
    // We use u96 for the nonce, so make sure nonce_length is 12 (96/8).
    std.debug.assert(TAlg.nonce_length == 12);

    return struct {
        pub const salt_length = salt_size;
        pub const tag_length = TAlg.tag_length;
        pub const key_length = TAlg.key_length;
        pub const nonce_length = TAlg.nonce_length;

        pub fn deriveSessionSubkeyWithSalt(key: [key_length]u8, salt: [salt_length]u8) [key_length]u8 {
            var key_and_salt: [key.len + salt.len]u8 = undefined;
            std.mem.copy(u8, key_and_salt[0..key.len], &key);
            std.mem.copy(u8, key_and_salt[key.len .. key.len + salt.len], &salt);

            var session_subkey: [key_length]u8 = undefined;
            deriveSessionSubkey(&key_and_salt, &session_subkey);

            return session_subkey;
        }

        pub fn generateRandomSalt() ![salt_length]u8 {
            var seed: [std.rand.DefaultCsprng.secret_seed_length]u8 = undefined;
            try std.os.getrandom(&seed);

            var salt: [salt_length]u8 = undefined;
            var prng = std.rand.DefaultCsprng.init(seed);
            prng.fill(&salt);

            return salt;
        }

        pub const Encryptor = struct {
            nonce: u96 = 0,
            key: [key_length]u8,

            pub fn encrypt(self: *@This(), message: []const u8, encrypted: []u8, tag: *[tag_length]u8) void {
                var nonce: [nonce_length]u8 = undefined;
                std.mem.writeIntLittle(u96, &nonce, self.nonce);

                TAlg.encrypt(encrypted, tag, message, "", nonce, self.key);

                self.nonce += 1;
            }

            pub fn decrypt(self: *@This(), message: []u8, encrypted: []const u8, tag: [tag_length]u8) !void {
                var nonce: [nonce_length]u8 = undefined;
                std.mem.writeIntLittle(u96, &nonce, self.nonce);

                try TAlg.decrypt(message, encrypted, tag, "", nonce, self.key);

                self.nonce += 1;
            }
        };
    };
}

pub const Blake3Aes128Gcm = Crypto(Aes128Gcm, 16);
pub const Blake3Aes256Gcm = Crypto(Aes256Gcm, 32);
pub const Blake3ChaCha8Poly1305 = Crypto(ChaCha8Poly1305, 32);
pub const Blake3ChaCha12Poly1305 = Crypto(ChaCha12Poly1305, 32);
pub const Blake3ChaCha20Poly1305 = Crypto(ChaCha20Poly1305, 32);

pub const Methods = [_]type{
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3ChaCha8Poly1305,
    Blake3ChaCha12Poly1305,
    Blake3ChaCha20Poly1305,
};

pub const Encryptor = Blake3Aes256Gcm.Encryptor;
pub const generateRandomSalt = Blake3Aes256Gcm.generateRandomSalt;
pub const deriveSessionSubkeyWithSalt = Blake3Aes256Gcm.deriveSessionSubkeyWithSalt;

test "deriveSessionSubkey" {
    var session_subkey: [32]u8 = undefined;
    deriveSessionSubkey("test123", &session_subkey);
    try std.testing.expectEqualSlices(u8, &.{ 0x1d, 0x06, 0xee, 0xfb, 0x51, 0xe3, 0xe1, 0xe9, 0x79, 0xf0, 0x6d, 0x97, 0x30, 0x7b, 0xc0, 0xba, 0xfb, 0xed, 0x23, 0x0b, 0x4c, 0x10, 0x4d, 0x1e, 0xd8, 0x8e, 0x75, 0x92, 0x33, 0xe6, 0x21, 0xf9 }, &session_subkey);
}

test "Encryptor encrypt" {
    var encryptor: Encryptor = .{
        .key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
    };

    try std.testing.expectEqual(@as(u96, 0), encryptor.nonce);

    const message = "asdfqwer";
    var encrypted: [message.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    encryptor.encrypt(message, &encrypted, &tag);

    try std.testing.expectEqualSlices(u8, &.{ 111, 207, 209, 184, 196, 91, 230, 207 }, &encrypted);
    try std.testing.expectEqualSlices(u8, &.{ 108, 175, 174, 87, 224, 85, 75, 9, 36, 55, 163, 93, 250, 24, 52, 249 }, &tag);
    try std.testing.expectEqual(@as(u96, 1), encryptor.nonce);
}

test "Encryptor decrypt" {
    var encryptor: Encryptor = .{
        .key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
    };

    try std.testing.expectEqual(@as(u96, 0), encryptor.nonce);

    const encrypted = [_]u8{ 111, 207, 209, 184, 196, 91, 230, 207 };
    const tag = [_]u8{ 108, 175, 174, 87, 224, 85, 75, 9, 36, 55, 163, 93, 250, 24, 52, 249 };
    var message: [encrypted.len]u8 = undefined;

    try encryptor.decrypt(&message, &encrypted, tag);

    try std.testing.expectEqualStrings("asdfqwer", &message);
    try std.testing.expectEqual(@as(u96, 1), encryptor.nonce);
}

test "generateRandomSalt" {
    inline for (Methods) |Method| {
        var salt_a: [Method.salt_length]u8 = try Method.generateRandomSalt();
        var salt_b: [Method.salt_length]u8 = try Method.generateRandomSalt();
        try std.testing.expect(!std.mem.eql(u8, &salt_a, &salt_b));
    }
}

test "Test decrypt real data" {
    const encoded_key = "AcxUIVEsMN7a5bk2swV8uCFb9MGkY5pZumaStQ4CVKc=";
    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, encoded_key);

    const data = [_]u8{ 0x63, 0xb2, 0x6f, 0x4d, 0xff, 0xe7, 0x84, 0x06, 0xc8, 0xc7, 0x5f, 0xa0, 0xe7, 0x0e, 0x9c, 0xdc, 0x46, 0x43, 0xf3, 0x6d, 0x0e, 0xeb, 0xfd, 0x50, 0xf0, 0x4b, 0xc0, 0x7a, 0x36, 0x3c, 0xf5, 0x34, 0x0a, 0xde, 0x75, 0x19, 0x6e, 0xd9, 0xb2, 0x89, 0xa6, 0xe0, 0x06, 0xc7, 0xc1, 0xc0, 0x9e, 0x54, 0x00, 0x93, 0x3c, 0xf0, 0xc1, 0x2e, 0xaf, 0xe5, 0x12, 0x53, 0x8b, 0x5c, 0x54, 0x0c, 0xc1, 0xab, 0x1e, 0x3b, 0xfd, 0x8d, 0x9a, 0xb4, 0xf9, 0x6d, 0xfd, 0x8b, 0x42, 0xb9, 0x2e, 0x78, 0xa0, 0xca, 0x9a, 0x48, 0xb7, 0xe5, 0xed, 0x6c, 0xbf, 0xfe, 0x63, 0xa4, 0x9c, 0x31, 0xd1, 0xb3, 0xa1, 0xd5, 0xd4, 0xe9, 0x2e, 0xa0, 0x1a, 0x61, 0x60, 0x1c, 0xef, 0xbb, 0xf8, 0xbd, 0x4e, 0xf9, 0x42, 0x95, 0x21, 0x59, 0x7d, 0x08, 0x1f, 0x7e, 0x6b, 0xf1, 0xe7, 0x5b, 0xe0, 0x42, 0x2d, 0xc3, 0x65, 0x05, 0xbb, 0xdf, 0x09, 0x03, 0x0b, 0x17, 0x84, 0x05, 0xbe, 0x86, 0xce, 0x29, 0x07, 0x54, 0xec, 0x6c, 0x5d, 0x24, 0xc0, 0x53, 0x83, 0x14, 0x74, 0xec, 0x9a, 0xed, 0x72, 0x69, 0xcc, 0x9c, 0x08, 0x2e, 0x5b, 0x71, 0x59, 0x71, 0x71, 0xbc, 0xff, 0x95, 0xa6, 0x59, 0x61, 0x48, 0x36, 0x59, 0xb2, 0x14, 0xa0, 0xe2, 0x2f, 0x2b, 0x54, 0x2d, 0xcc, 0x11, 0x41, 0x12, 0x8a, 0xf5, 0x00, 0x35, 0x50, 0x48, 0x04, 0x74, 0xea, 0x00, 0x5e, 0x83, 0x75, 0x18, 0x5d, 0xc3, 0xb6, 0xc0, 0xba, 0xb3, 0xdd, 0x1f, 0x66, 0xbc, 0xbc, 0xbe, 0x4a, 0x4c, 0x2f, 0xf1, 0xd6, 0x30, 0x8a, 0xed, 0x9b, 0x96, 0x5e, 0xd9, 0x19, 0x7a, 0x09, 0x3b, 0xb6, 0x1e, 0x47, 0xac, 0x95, 0x76, 0xa2, 0xd2, 0x13, 0xf6, 0xc1, 0xde, 0xc4, 0xba, 0xd8, 0xf9, 0x07, 0x8c, 0x21, 0xf0, 0xc0, 0x64, 0xa9, 0xb4, 0x74, 0xf4, 0x13, 0xea, 0xd8, 0xd8, 0xaf, 0xde, 0xa7, 0x48, 0xb6, 0x31, 0x70, 0x51, 0x6c, 0x04, 0xf1, 0xc5, 0x87, 0xfe, 0xfb, 0x47, 0x2b, 0x99, 0x8a, 0x6f, 0xa6, 0xde, 0x0c, 0xfc, 0x53, 0x5e, 0x33, 0x42, 0x80, 0x18, 0xa3, 0x47, 0x30, 0xd1, 0xcf, 0xdc, 0x65, 0x9a, 0xd6, 0xd4, 0x71, 0x39, 0x83, 0x17, 0x79, 0x6b, 0x87, 0x43, 0x43, 0xdf, 0x1e, 0x4f, 0xe1, 0x8f, 0xc7, 0x7f, 0xc0, 0x5e, 0xae, 0x95, 0x21, 0x8a, 0x7b, 0xe0, 0x7b, 0x49, 0x10, 0x91, 0xf7, 0xc9, 0xd2, 0x76, 0x96, 0x11, 0x13, 0xe8, 0xfa, 0x8b, 0x8a, 0xef, 0x2b, 0x08, 0xff, 0x03, 0x45, 0x7b, 0x06, 0xee, 0xb6, 0xb6, 0xf2, 0x64, 0xb9, 0x5d, 0x30, 0x25, 0xbc, 0x78, 0x49, 0x05, 0xb5, 0x53, 0x1e, 0x72, 0x56, 0x13, 0xb8, 0x58, 0x1c, 0xac, 0x7b, 0xf7, 0x12, 0x2e, 0xa1, 0xdd, 0xca, 0x25, 0x46, 0xd1, 0x74, 0x26, 0xbb, 0x0e, 0x64, 0xff, 0x12, 0x92, 0x9b, 0xd8, 0xb8, 0xeb, 0x02, 0xd9, 0x5f, 0xcf, 0xc1, 0x15, 0x18, 0x7a, 0xa3, 0x8a, 0x25, 0xc1, 0x50, 0xb4, 0x3d, 0xaa, 0x33, 0xb3, 0xfa, 0xf2, 0x82, 0x8e, 0xfe, 0xdd, 0x1a, 0xaa, 0xc8, 0x11, 0xd6, 0x8b, 0x9c, 0x21, 0x72, 0x3f, 0x1a, 0x3a, 0x3a, 0x2d, 0x5f, 0xea, 0xfd, 0xd4, 0x32, 0x89, 0x6d, 0x85, 0x6e, 0x51, 0x40, 0x10, 0xbb, 0x75, 0xdb, 0x07, 0x0d, 0xaf, 0x37, 0x76, 0x74, 0xeb, 0x63, 0x18, 0x3b, 0x9e, 0x3b, 0x26, 0xa5, 0x0c, 0xa3, 0x0d, 0x6f, 0x5e, 0xd3, 0x76, 0x27, 0xd9, 0x69, 0xe0, 0x12, 0xce, 0x10, 0x66, 0xed, 0xe3, 0xab, 0x5a, 0x59, 0x96, 0xc6, 0x7f, 0xc5, 0xb6, 0xcd, 0x56, 0x7d, 0xcf, 0xca, 0xc7, 0xa9, 0x6b, 0xe3, 0xc6, 0xff, 0xc2, 0x7c, 0x60, 0x34, 0x6b, 0xe5, 0x6c, 0x26, 0xf4, 0x92, 0x25, 0x9b, 0xb5, 0xab, 0xbc, 0x27, 0xc7, 0x14, 0xeb, 0xf7, 0xbc, 0x59, 0xf0, 0x12, 0xbc, 0x88, 0xbe, 0x15, 0x9d, 0xdf, 0x53, 0x28, 0x1d, 0x2d, 0x7a, 0x02, 0xfc, 0xa6, 0x98, 0x56, 0x0f, 0xff, 0x46, 0x91, 0xa1, 0xf1, 0xaf, 0xa3, 0x49, 0x88, 0xa0, 0xe4, 0xd7, 0x23, 0xe4, 0xfe, 0x91, 0x25, 0x32, 0x24, 0xb1, 0xab, 0x6f, 0xc4, 0xbd, 0x41, 0x35, 0x32, 0x82, 0xcd, 0xbd, 0x42, 0x4d, 0xeb, 0xab, 0xbd, 0x0b, 0x00, 0x76, 0xff, 0xa9, 0x13, 0xd0, 0xc6, 0xee, 0xef, 0x57, 0x56, 0xb9, 0x2a, 0x04, 0xa3, 0x21, 0x02, 0x75, 0xa9, 0xa5, 0x75, 0xc4, 0xce, 0xdf, 0x10, 0x14, 0x1d, 0x3d, 0xa6, 0x51, 0xe9, 0x87, 0xf7, 0xaa, 0xcb, 0x2c, 0xbd, 0xfd };

    const salt = data[0..32];

    var input = std.ArrayList(u8).init(std.testing.allocator);
    defer input.deinit();
    try input.appendSlice(&key);
    try input.appendSlice(salt);
    var session_subkey: [32]u8 = undefined;
    deriveSessionSubkey(input.items, &session_subkey);

    const fixed = data[32 .. 32 + 11];
    const tag = data[32 + 11 .. 32 + 11 + 16];

    var nonce: [96 / 8]u8 = undefined;
    std.mem.writeIntBig(u96, &nonce, 0);

    var message: [11]u8 = undefined;
    try Aes256Gcm.decrypt(&message, fixed, tag.*, "", nonce, session_subkey);
}
