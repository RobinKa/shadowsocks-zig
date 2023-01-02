const std = @import("std");

fn saltGreaterThan(context: void, a: TimedSalt, b: TimedSalt) std.math.Order {
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
    saltGreaterThan,
);

pub const SaltCache = struct {
    salt_queue: SaltQueue,
    salt_set: std.StringHashMap(void),
    salt_mutex: std.Thread.Mutex,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) @This() {
        return .{
            .salt_queue = SaltQueue.init(allocator, {}),
            .salt_set = std.StringHashMap(void).init(allocator),
            .salt_mutex = std.Thread.Mutex{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *@This()) void {
        while (self.salt_queue.count() > 0) {
            var salt = self.salt_queue.remove();
            self.allocator.free(salt.salt);
        }

        self.salt_queue.deinit();
        self.salt_set.deinit();
    }

    pub fn maybeAdd(self: *@This(), salt: []const u8, timestamp: u64) !bool {
        var salt_copy = try self.allocator.dupe(u8, salt);
        errdefer self.allocator.free(salt_copy);

        self.salt_mutex.lock();
        defer self.salt_mutex.unlock();

        var kv = try self.salt_set.getOrPut(salt_copy);

        if (kv.found_existing) {
            self.allocator.free(salt_copy);
            return false;
        }

        try self.salt_queue.add(.{
            .salt = salt_copy,
            .timestamp = timestamp,
        });

        return true;
    }

    pub fn removeAfterTime(self: *@This(), timestamp: u64) void {
        self.salt_mutex.lock();
        defer self.salt_mutex.unlock();

        while (self.salt_queue.count() > 0) {
            const timed_salt = self.salt_queue.peek();
            if (timed_salt.?.timestamp > timestamp) {
                _ = self.salt_queue.remove();
                _ = self.salt_set.remove(timed_salt.?.salt);
                self.allocator.free(timed_salt.?.salt);
            } else {
                break;
            }
        }
    }
};

test "salt cache" {
    var cache = SaltCache.init(std.testing.allocator);
    defer cache.deinit();

    const salt_a: [32]u8 = [_]u8{1} ** 32;
    const salt_b: [32]u8 = [_]u8{2} ** 32;

    var not_duplicate = try cache.maybeAdd(&salt_a, 100);

    try std.testing.expectEqual(true, not_duplicate);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_set.count());

    not_duplicate = try cache.maybeAdd(&salt_a, 100);

    try std.testing.expectEqual(false, not_duplicate);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_set.count());

    cache.removeAfterTime(150);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_set.count());

    cache.removeAfterTime(50);
    try std.testing.expectEqual(@as(usize, 0), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 0), cache.salt_set.count());

    not_duplicate = try cache.maybeAdd(&salt_a, 100);
    try std.testing.expectEqual(true, not_duplicate);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 1), cache.salt_set.count());

    not_duplicate = try cache.maybeAdd(&salt_b, 50);
    try std.testing.expectEqual(true, not_duplicate);
    try std.testing.expectEqual(@as(usize, 2), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 2), cache.salt_set.count());

    cache.removeAfterTime(0);
    try std.testing.expectEqual(@as(usize, 0), cache.salt_queue.len);
    try std.testing.expectEqual(@as(usize, 0), cache.salt_set.count());
}
