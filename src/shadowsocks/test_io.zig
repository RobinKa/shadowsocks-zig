const std = @import("std");
const async_io = @import("async_io");
const os = std.os;
const IO = async_io.IO;
const testing = std.testing;

test "io" {
    const ms = 20;
    const count = 10;

    try struct {
        const Context = @This();

        io: IO,
        count: u32 = 0,

        fn run_test() !void {
            var self: Context = .{ .io = try IO.init(1, 0) };
            defer self.io.deinit();

            var completions: [count]IO.Completion = undefined;
            for (completions) |*completion| {
                self.io.timeout(
                    *Context,
                    &self,
                    timeout_callback,
                    completion,
                    ms * std.time.ns_per_ms,
                );
            }
            while (self.count < count) try self.io.tick();

            try self.io.tick();
            try testing.expectEqual(@as(u32, count), self.count);
        }

        fn timeout_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.TimeoutError!void,
        ) void {
            _ = completion;
            _ = result catch @panic("timeout error");

            self.count += 1;
        }
    }.run_test();
}

test "write/read/close" {
    try struct {
        const Context = @This();

        io: IO,
        done: bool = false,
        fd: os.fd_t,

        write_buf: [20]u8 = [_]u8{97} ** 20,
        read_buf: [20]u8 = [_]u8{98} ** 20,

        written: usize = 0,
        read: usize = 0,

        fn run_test() !void {
            const path = "test_io_write_read_close";
            const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = true });
            defer std.fs.cwd().deleteFile(path) catch {};

            var self: Context = .{
                .io = try IO.init(32, 0),
                .fd = file.handle,
            };
            defer self.io.deinit();

            var completion: IO.Completion = undefined;

            self.io.write(
                *Context,
                &self,
                write_callback,
                &completion,
                self.fd,
                &self.write_buf,
                10,
            );
            while (!self.done) try self.io.tick();

            try testing.expectEqual(self.write_buf.len, self.written);
            try testing.expectEqual(self.read_buf.len, self.read);
            try testing.expectEqualSlices(u8, &self.write_buf, &self.read_buf);
        }

        fn write_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.WriteError!usize,
        ) void {
            self.written = result catch @panic("write error");
            self.io.read(*Context, self, read_callback, completion, self.fd, &self.read_buf, 10);
        }

        fn read_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.ReadError!usize,
        ) void {
            self.read = result catch @panic("read error");
            self.io.close(*Context, self, close_callback, completion, self.fd);
        }

        fn close_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.CloseError!void,
        ) void {
            _ = completion;
            _ = result catch @panic("close error");

            self.done = true;
        }
    }.run_test();
}

test "accept/connect/send/receive" {
    try struct {
        const Context = @This();

        io: *IO,
        done: bool = false,
        server: os.socket_t,
        client: os.socket_t,

        accepted_sock: os.socket_t = undefined,

        send_buf: [10]u8 = [_]u8{ 1, 0, 1, 0, 1, 0, 1, 0, 1, 0 },
        recv_buf: [5]u8 = [_]u8{ 0, 1, 0, 1, 0 },

        sent: usize = 0,
        received: usize = 0,

        fn run_test() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);
            const kernel_backlog = 1;
            const server = try io.open_socket(address.any.family, os.SOCK.STREAM, os.IPPROTO.TCP);
            defer os.closeSocket(server);

            const client = try io.open_socket(address.any.family, os.SOCK.STREAM, os.IPPROTO.TCP);
            defer os.closeSocket(client);

            try os.setsockopt(
                server,
                os.SOL.SOCKET,
                os.SO.REUSEADDR,
                &std.mem.toBytes(@as(c_int, 1)),
            );
            try os.bind(server, &address.any, address.getOsSockLen());
            try os.listen(server, kernel_backlog);

            var self: Context = .{
                .io = &io,
                .server = server,
                .client = client,
            };

            var client_completion: IO.Completion = undefined;
            self.io.connect(
                *Context,
                &self,
                connect_callback,
                &client_completion,
                client,
                address,
            );

            var server_completion: IO.Completion = undefined;
            self.io.accept(*Context, &self, accept_callback, &server_completion, server);

            while (!self.done) try self.io.tick();

            try testing.expectEqual(self.send_buf.len, self.sent);
            try testing.expectEqual(self.recv_buf.len, self.received);

            try testing.expectEqualSlices(u8, self.send_buf[0..self.received], &self.recv_buf);
        }

        fn connect_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.ConnectError!void,
        ) void {
            _ = result catch @panic("connect error");

            self.io.send(
                *Context,
                self,
                send_callback,
                completion,
                self.client,
                &self.send_buf,
            );
        }

        fn send_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.SendError!usize,
        ) void {
            _ = completion;

            self.sent = result catch @panic("send error");
        }

        fn accept_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.AcceptError!os.socket_t,
        ) void {
            self.accepted_sock = result catch @panic("accept error");
            self.io.recv(
                *Context,
                self,
                recv_callback,
                completion,
                self.accepted_sock,
                &self.recv_buf,
            );
        }

        fn recv_callback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.RecvError!usize,
        ) void {
            _ = completion;

            self.received = result catch @panic("recv error");
            self.done = true;
        }
    }.run_test();
}
