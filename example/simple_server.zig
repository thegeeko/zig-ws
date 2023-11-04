const std = @import("std");
const Response = std.http.Server.Response;
const WsEvents = @import("ws").WsEvents;
const WebSocket = @import("ws").WebSocket;
const CloseStatus = @import("ws").CloseStatus;

fn on_msg(msg: []const u8, ws: *WebSocket) void {
    std.log.debug("msg: ({})", .{msg.len});
    ws.send(msg) catch unreachable;
}

fn on_binary(msg: []const u8, ws: *WebSocket) void {
    std.log.debug("msg - bin: ({})", .{msg.len});
    ws.send_binary(msg) catch unreachable;
}

fn on_close(status_code: ?CloseStatus, msg: ?[]const u8, ws: *WebSocket) void {
    _ = ws;
    if (status_code) |code| {
        const msg_unwrapped = msg orelse "no_msg";
        std.log.debug("close: ({}), {s}", .{ code, msg_unwrapped });
    } else {
        std.log.debug("close w/o msg", .{});
    }
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

    // avoid heap allocations for better performace but limited
    // message size .. can be useful if u will only do small messages
    //
    // var buf: [1024]u8 = undefined;
    // var fba = std.heap.FixedBufferAllocator.init(&buf);
    // const allocator = fba.allocator();

    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const addr = try std.net.Address.parseIp("127.0.0.1", 3000);
    try server.listen(addr);
    std.log.info("server started in port: {}", .{3000});

    const ws_events = WsEvents{
        .on_msg = on_msg,
        .on_binary = on_binary,
        .on_close = on_close,
    };

    while (true) {
        var res = try server.accept(.{ .allocator = allocator });
        defer res.deinit();

        res.wait() catch |err| switch (err) {
            error.HttpHeadersInvalid => continue,
            error.ConnectionResetByPeer => continue,
            error.EndOfStream => continue,
            else => return err,
        };

        var ws = try WebSocket.init(allocator, &res);
        defer ws.deinit();

        try ws.handle(ws_events);
    }
}
