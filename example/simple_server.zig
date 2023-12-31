const std = @import("std");
const Response = std.http.Server.Response;

// ZIG_WS
const WsEvents = @import("ws").WsEvents;
const WebSocket = @import("ws").WebSocket;
const CloseStatus = @import("ws").CloseStatus;

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
        .on_binary = on_binary,
    };

    while (true) {
        var res = try server.accept(.{ .allocator = allocator });

        res.wait() catch |err| switch (err) {
            error.HttpHeadersInvalid => continue,
            error.ConnectionResetByPeer => continue,
            error.EndOfStream => continue,
            else => return err,
        };

        // will take the ownership of the response
        var ws = try WebSocket.init(allocator, &res);
        defer ws.deinit();

        try ws.handle(ws_events);
    }
}

fn on_msg(msg: []const u8, ws: *WebSocket) void {
    std.log.debug("msg: ({}) {s}", .{ msg.len, msg });
    ws.send(msg) catch unreachable;
}

fn on_binary(msg: []const u8, ws: *WebSocket) void {
    std.log.debug("msg - bin: ({}) {}", .{ msg.len, std.fmt.fmtSliceHexLower(msg) });
    ws.send_binary(msg) catch unreachable;
}
