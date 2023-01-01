const std = @import("std");

fn greaterThan(context: void, a: TimedSalt, b: TimedSalt) std.math.Order {
    _ = context;
    return std.math.order(a.timestamp, b.timestamp).invert();
}

const TimedSalt = struct {
    timestamp: u64,
    salt: []const u8,
};

const SaltQueue = std.PriorityQueue(
    TimedSalt,
    void,
    greaterThan,
);

pub const SaltCache = struct {
    request_salts: SaltQueue,
    request_salts_set: std.StringHashMap(void),
    request_salts_mutex: std.Thread.Mutex,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !@This() {
        return .{
            .request_salts = SaltQueue.init(allocator, {}),
            .request_salts_set = std.StringHashMap(void).init(allocator),
            .request_salts_mutex = std.Thread.Mutex{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *@This()) void {
        while (self.request_salts.count() > 0) {
            var salt = self.request_salts.remove();
            self.allocator.free(salt.salt);
        }

        self.request_salts.deinit();
        self.request_salts_set.deinit();
    }

    pub fn maybeAddRequestSalt(self: *@This(), salt: []const u8, timestamp: u64) !bool {
        var salt_copy = try self.allocator.dupe(u8, salt);
        errdefer self.allocator.free(salt_copy);

        self.request_salts_mutex.lock();
        defer self.request_salts_mutex.unlock();

        var kv = try self.request_salts_set.getOrPut(salt_copy);

        if (kv.found_existing) {
            self.allocator.free(salt_copy);
            return false;
        }

        try self.request_salts.add(.{
            .salt = salt_copy,
            .timestamp = timestamp,
        });

        return true;
    }

    pub fn removeSaltsAfterTime(self: *@This(), timestamp: u64) void {
        self.request_salts_mutex.lock();
        defer self.request_salts_mutex.unlock();

        while (self.request_salts.count() > 0) {
            const timed_salt = self.request_salts.peek();
            if (timed_salt.?.timestamp > timestamp) {
                _ = self.request_salts.remove();
                _ = self.request_salts_set.remove(timed_salt.?.salt);
                self.allocator.free(timed_salt.?.salt);
            } else {
                break;
            }
        }
    }
};

test "salt cache" {
    var cache = try SaltCache.init(std.testing.allocator);
    defer cache.deinit();

    const salt_a: [32]u8 = [_]u8{1} ** 32;
    const salt_b: [32]u8 = [_]u8{2} ** 32;

    var not_duplicate = try cache.maybeAddRequestSalt(&salt_a, 100);

    try std.testing.expectEqual(true, not_duplicate);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts_set.count());

    not_duplicate = try cache.maybeAddRequestSalt(&salt_a, 100);

    try std.testing.expectEqual(false, not_duplicate);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts_set.count());

    cache.removeSaltsAfterTime(150);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts_set.count());

    cache.removeSaltsAfterTime(50);
    try std.testing.expectEqual(@as(usize, 0), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 0), cache.request_salts_set.count());

    not_duplicate = try cache.maybeAddRequestSalt(&salt_a, 100);
    try std.testing.expectEqual(true, not_duplicate);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 1), cache.request_salts_set.count());

    not_duplicate = try cache.maybeAddRequestSalt(&salt_b, 50);
    try std.testing.expectEqual(true, not_duplicate);
    try std.testing.expectEqual(@as(usize, 2), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 2), cache.request_salts_set.count());

    cache.removeSaltsAfterTime(0);
    try std.testing.expectEqual(@as(usize, 0), cache.request_salts.len);
    try std.testing.expectEqual(@as(usize, 0), cache.request_salts_set.count());
}
