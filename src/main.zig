const std = @import("std");
const Request = std.http.Server.Request;
const Response = std.http.Server.Response;

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const HandShakeRequestError = error{
    no_client_secret,
    other,
};

/// verify request and make sure it have the following fileds with the appropriate data eg:
///
/// Upgrade: websocket
/// Connection: Upgrade
/// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
fn is_valid_req(req: Request) HandShakeRequestError!void {
    const upgrade = req.headers.getFirstValue("Upgrade") orelse
        return HandShakeRequestError.other;
    const connection = req.headers.getFirstValue("Connection") orelse
        return HandShakeRequestError.other;
    const websocket_key = req.headers.getFirstValue("Sec-WebSocket-Key") orelse
        return HandShakeRequestError.no_client_secret;

    std.debug.print(
        \\
        \\upgrade: {s}
        \\connection: {s}
        \\Sec-WebSocket-Key: {s}
        \\
    , .{ upgrade, connection, websocket_key });

    if (std.mem.eql(u8, upgrade, "websocket ") or std.mem.eql(u8, connection, "Upgrade ")) {
        return HandShakeRequestError.other;
    }
}

/// write the handshake response but doesn't send it
fn perform_handshake(res: *Response) !void {
    const req = res.request;
    const client_sec = req.headers.getFirstValue("Sec-WebSocket-Key").?;

    var leading_whitespace: u8 = 0;
    var trailing_whitespace: u8 = 0;
    var last_char: u8 = ' ';
    var i: usize = 0;

    // count leading whitespace
    while (i < client_sec.len) {
        if (client_sec[i] != ' ') break;

        leading_whitespace += 1;
        last_char = ' ';
        i += 1;
    }

    // count trilling whitespace
    i = client_sec.len - 1;
    while (i > 0) {
        if (client_sec[i] != ' ') break;

        trailing_whitespace += 1;
        last_char = ' ';
        i -= 1;
    }

    // fixed stack buffer to avoid allocations
    // @FIXME make sure it's always enough
    var buf: [512]u8 = undefined;
    const total_len = client_sec.len + WS_GUID.len;
    var concat_sec: []u8 = buf[0..total_len];
    @memcpy(concat_sec[0..client_sec.len], client_sec);
    @memcpy(concat_sec[client_sec.len..], WS_GUID);

    // sha1 output will always be 20b
    var sha1_output: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(concat_sec, &sha1_output, .{});

    // base64 encode the sha1 output
    const encoder = std.base64.standard.Encoder;
    const basae64_output_size = encoder.calcSize(sha1_output.len);

    // reusing the concat buffer
    @memset(&buf, 0);
    var base64_output = buf[0..basae64_output_size];
    _ = encoder.encode(base64_output, &sha1_output);

    std.debug.print("{s}", .{base64_output});
    res.status = .switching_protocols;
    res.transfer_encoding = .{ .content_length = 0 };
    try res.headers.append("Upgrade", "websocket");
    try res.headers.append("Connection", "Upgrade");
    try res.headers.append("Sec-WebSocket-Accept", base64_output);
    try res.do();
}

test "hand shake" {
    const testing = std.testing;
    testing.log_level = .debug;

    std.debug.print("\nserver started in port: {}", .{3000});

    var ta = testing.allocator_instance;
    const alloc = ta.allocator();
    defer {
        const check = ta.deinit();
        if (check == .leak) {
            @panic("Memory Leak");
        }
    }

    var server = std.http.Server.init(alloc, .{ .reuse_address = true });

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

            std.debug.print("\n{s} {s} {s}", .{
                @tagName(res.request.method),
                @tagName(res.request.version),
                res.request.target,
            });

            try is_valid_req(res.request);
            try perform_handshake(&res);
            try res.finish();
        }
    }
}
