const std = @import("std");
const Response = std.http.Server.Response;
const WsEvents = @import("ws").WsEvents;
const WebSocket = @import("ws").WebSocket;

fn on_msg(msg: []const u8, ws: *WebSocket) void {
    std.log.debug("{s}", .{msg});
    ws.send(msg) catch unreachable;
}

pub fn main() !void {
    var ga = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = ga.allocator();
    defer {
        const check = ga.deinit();
        if (check == .leak) {
            @panic("Memory Leak");
        }
    }

    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const addr = try std.net.Address.parseIp("127.0.0.1", 3000);
    try server.listen(addr);
    std.log.info("server started in port: {}", .{3000});

    const ws_events = WsEvents{
        .on_msg = on_msg,
    };

    outer: while (true) {
        var res = try server.accept(.{ .allocator = allocator });
        defer res.deinit();

        while (res.reset() != .closing) {
            res.wait() catch |err| switch (err) {
                error.HttpHeadersInvalid => continue :outer,
                error.EndOfStream => continue,
                else => return err,
            };

            var ws = try WebSocket.init(allocator, &res);
            try ws.handle(ws_events);
        }
    }
}
