const std = @import("std");
const Request = std.http.Server.Request;
const Response = std.http.Server.Response;

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_VERSION = "13";

/// removes any trilling or leading whitespace
///
/// returns a slice of the passed slice aka you don't own the slice it's just ref from the passed
/// slice
fn remove_whitespace(str: []const u8) []const u8 {
    var leading_whitespace: u8 = 0;
    var trailing_whitespace: u8 = 0;
    var last_char: u8 = ' ';
    var i: usize = 0;

    // count leading whitespace
    while (i < str.len) {
        if (str[i] != ' ') break;

        leading_whitespace += 1;
        last_char = ' ';
        i += 1;
    }

    // count trilling whitespace
    i = str.len - 1;
    while (i > 0) {
        if (str[i] != ' ') break;

        trailing_whitespace += 1;
        last_char = ' ';
        i -= 1;
    }

    return str[leading_whitespace .. str.len - trailing_whitespace];
}

const HandShakeRequestError = error{
    not_get_request,
    invalid_http_version,
    no_host_header,
    no_upgrade_header,
    no_connection_header,
    no_client_secret,
    no_websocket_version,
};

/// verifies request and make sure it have the needed fileds with the appropriate data
/// it doesn't care about the origin header cus it's required from browser clients but not
/// other non-browser clients
///
/// more on the requirements here: [spec section 4.1](https://datatracker.ietf.org/doc/html/rfc6455#section-4.1)
fn is_valid_req(req: Request) HandShakeRequestError!void {
    const eql = std.mem.eql;
    const err = HandShakeRequestError;

    if (req.method != .GET) {
        return err.not_get_request;
    }

    if (req.version != .@"HTTP/1.1") {
        return err.invalid_http_version;
    }

    // @FIXME should make sure it's a valid URI
    if (!req.headers.contains("Host")) {
        return err.no_host_header;
    }

    if (req.headers.getFirstValue("Upgrade")) |header| {
        if (!eql(u8, remove_whitespace(header), "websocket")) return err.no_upgrade_header;
    } else return err.no_upgrade_header;

    if (req.headers.getFirstValue("Connection")) |header| {
        if (!eql(u8, remove_whitespace(header), "Upgrade")) return err.no_connection_header;
    } else return err.no_connection_header;

    if (req.headers.getFirstValue("Sec-WebSocket-Key")) |header| {
        const encoder = std.base64.standard.Encoder;
        // the spec states it should be a base64 encoding of a random 16-byte value
        if (remove_whitespace(header).len != encoder.calcSize(16)) return err.no_client_secret;
    } else return err.no_client_secret;

    if (req.headers.getFirstValue("Sec-WebSocket-Version")) |header| {
        if (!eql(u8, remove_whitespace(header), WS_VERSION)) return err.no_websocket_version;
    } else return err.no_websocket_version;
}

/// write the handshake response but doesn't send it
fn perform_handshake(res: *Response) !void {
    const req = res.request;
    const client_sec = remove_whitespace(req.headers.getFirstValue("Sec-WebSocket-Key").?);

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
