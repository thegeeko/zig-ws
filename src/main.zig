const std = @import("std");

test "hand shake" {
    const testing = std.testing;
    testing.log_level = .debug;

    var ta = testing.allocator_instance;
    const alloc = ta.allocator();
    defer {
        const check = ta.deinit();
        if (check == .leak) {
            @panic("Memory Leak");
        }
    }

    var server = std.http.Server.init(alloc, .{});

    const addr = try std.net.Address.parseIp("127.0.0.1", 3000);
    try server.listen(addr);

    outer: while (true) {
        var res = try server.accept(.{
            .allocator = alloc,
        });
        defer res.deinit();

        while (res.reset() != .closing) {
            res.wait() catch |err| switch (err) {
                error.HttpHeadersInvalid => continue :outer,
                error.EndOfStream => continue,
                else => return err,
            };

            std.debug.print("{s} {s} {s}", .{
                @tagName(res.request.method),
                @tagName(res.request.version),
                res.request.target,
            });
        }
    }
}
