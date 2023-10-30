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

/// verifies request and make sure it have the needed fileds with the appropriate data
/// it doesn't care about the origin header cus it's required from browser clients but not
/// other non-browser clients
///
/// more on the requirements here: [spec section 4.1](https://datatracker.ietf.org/doc/html/rfc6455#section-4.1)
fn is_valid_req(req: *const Request) !void {
    const Error = error{
        not_get_request,
        invalid_http_version,
        no_host_header,
        no_upgrade_header,
        no_connection_header,
        no_client_secret,
        no_websocket_version,
    };

    const eql = std.mem.eql;

    if (req.method != .GET) {
        return Error.not_get_request;
    }

    if (req.version != .@"HTTP/1.1") {
        return Error.invalid_http_version;
    }

    // @FIXME should make sure it's a valid URI
    if (!req.headers.contains("Host")) {
        return Error.no_host_header;
    }

    if (req.headers.getFirstValue("Upgrade")) |header| {
        if (!eql(u8, remove_whitespace(header), "websocket")) return Error.no_upgrade_header;
    } else return Error.no_upgrade_header;

    if (req.headers.getFirstValue("Connection")) |header| {
        if (!eql(u8, remove_whitespace(header), "Upgrade")) return Error.no_connection_header;
    } else return Error.no_connection_header;

    if (req.headers.getFirstValue("Sec-WebSocket-Key")) |header| {
        const encoder = std.base64.standard.Encoder;
        // the spec states it should be a base64 encoding of a random 16-byte value
        if (remove_whitespace(header).len != encoder.calcSize(16)) return Error.no_client_secret;
    } else return Error.no_client_secret;

    if (req.headers.getFirstValue("Sec-WebSocket-Version")) |header| {
        if (!eql(u8, remove_whitespace(header), WS_VERSION)) return Error.no_websocket_version;
    } else return Error.no_websocket_version;
}

/// write the handshake response but doesn't send it
fn write_handshake(res: *Response) !void {
    const req = res.request;
    const client_sec = remove_whitespace(req.headers.getFirstValue("Sec-WebSocket-Key").?);

    // 512byte should be more than enough since it's the base64
    // encoding of a 16-byte
    //
    // "The value of this header field MUST be a
    //  nonce consisting of a randomly selected 16-byte value that has
    //  been base64-encoded"
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
    var base64_output = buf[0..basae64_output_size];
    _ = encoder.encode(base64_output, &sha1_output);

    res.status = .switching_protocols;
    res.transfer_encoding = .{ .content_length = 0 };
    try res.headers.append("Upgrade", "websocket");
    try res.headers.append("Connection", "Upgrade");
    try res.headers.append("Sec-WebSocket-Accept", base64_output);
    try res.do();
}

/// op codes according to the [spec](https://datatracker.ietf.org/doc/html/rfc6455#section-11.8)
pub const Opcode = enum(u4) {
    op_continue = 0x0,
    text = 0x1,
    binary = 0x2,
    rsv3 = 0x3,
    rsv4 = 0x4,
    rsv5 = 0x5,
    rsv6 = 0x6,
    rsv7 = 0x7,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    rsvB = 0xB,
    rsvC = 0xC,
    rsvD = 0xD,
    rsvE = 0xE,
    rsvF = 0xF,

    pub fn is_control(opcode: Opcode) bool {
        return @intFromEnum(opcode) & 0x8 != 0;
    }
};

const WsFrameHeader = packed struct {
    const Self = @This();

    // first byte
    opcode: Opcode,
    rsv3: u1 = 0,
    rsv2: u1 = 0,
    rsv1: u1 = 0,
    final: bool = true,

    // second byte
    size: u7,
    masked: bool = false,

    const mask_size = 4;
    const header_size = 2;
    const max_frame_size = mask_size + header_size + @sizeOf(u64);

    pub fn payload_size_bytes_count(self: *const Self) usize {
        return switch (self.size) {
            0...125 => 0,
            126 => @sizeOf(u16),
            127 => @sizeOf(u64),
        };
    }

    comptime {
        // making sure the struct is always 2 bytes
        std.debug.assert(@sizeOf(@This()) == 2);
    }
};

const WsFrame = struct {
    frame_header: WsFrameHeader,
    mask: [4]u8,
    data: []const u8,
};

pub const WsEvents = struct {
    /// called whenever a message recived
    on_msg: ?fn ([]const u8, ws: *WebSocket) void = null,
    /// called after writing the response headers and before sending it
    on_upgrade: ?fn (res: *Response, ws: *WebSocket) void = null,
    /// called when recived a close frame
    on_close: ?fn ([]const u8, ws: *WebSocket) void = null,
};

pub const WebSocket = struct {
    const Self = @This();
    const Error = error{
        action_without_active_connection,
    };

    allocator: std.mem.Allocator,
    res: *Response,
    stream: *std.net.Stream,
    active: bool = false,

    /// init the object and checks if the request is a valid handshake request
    /// the request is data is included in the response object
    pub fn init(allocator: std.mem.Allocator, res: *Response) !Self {
        try is_valid_req(&res.request);

        var ws = Self{
            .allocator = allocator,
            .res = res,
            .stream = &res.connection.stream,
        };

        return ws;
    }

    /// handle handshaking and proccess data frames
    /// don't use this inside WsEvents
    pub fn handle(self: *Self, comptime events: WsEvents) !void {
        try write_handshake(self.res);

        if (events.on_upgrade) |on_upgrade|
            on_upgrade(self.res, self);

        try self.res.finish();

        self.active = true;
        while (self.active) {
            var stream_reader = self.stream.reader();

            const frame_header = try stream_reader.readStruct(WsFrameHeader);

            var payload_size: u64 = 0;
            const payload_size_bytes_count = frame_header.payload_size_bytes_count();

            if (payload_size_bytes_count == 0) {
                payload_size = frame_header.size;
            } else {
                var buf: [@sizeOf(u64)]u8 = undefined;
                var sized_buf = buf[0..payload_size_bytes_count];
                _ = try stream_reader.read(sized_buf);

                if (payload_size_bytes_count == @sizeOf(u16)) {
                    payload_size =
                        @as(u16, @intCast(sized_buf[1])) | @as(u16, @intCast(sized_buf[0])) << 8;
                } else {
                    payload_size =
                        @as(u64, @intCast(sized_buf[7])) |
                        @as(u64, @intCast(sized_buf[6])) << 8 |
                        @as(u64, @intCast(sized_buf[5])) << 16 |
                        @as(u64, @intCast(sized_buf[4])) << 24 |
                        @as(u64, @intCast(sized_buf[3])) << 32 |
                        @as(u64, @intCast(sized_buf[2])) << 40 |
                        @as(u64, @intCast(sized_buf[1])) << 48 |
                        @as(u64, @intCast(sized_buf[0])) << 56;
                }
            }

            var mask: [WsFrameHeader.mask_size]u8 = undefined;
            if (frame_header.masked)
                _ = try stream_reader.readAtLeast(&mask, WsFrameHeader.mask_size);

            var payload = try self.allocator.alloc(u8, payload_size);
            defer self.allocator.free(payload);

            _ = try stream_reader.readAtLeast(payload, payload_size);

            if (frame_header.masked) {
                // unmasking according to the spec
                for (0.., payload) |i, char| {
                    payload[i] = char ^ mask[i % 4];
                }
            }

            switch (frame_header.opcode) {
                .text => {
                    if (events.on_msg) |on_msg|
                        on_msg(payload, self);
                },
                .close => {
                    if (events.on_close) |on_close|
                        on_close(payload, self);

                    try self.close(payload);
                },
                else => {
                    @panic("unimplemented opcode");
                },
            }
        }
    }

    pub fn close(self: *Self, msg: []const u8) !void {
        if (!self.active) return Error.action_without_active_connection;

        try self.write(.close, msg);
        self.active = false;
    }

    /// send unmasked message as the server should according to the spec
    pub fn send(self: *Self, msg: []const u8) !void {
        if (!self.active) return Error.action_without_active_connection;

        try self.write(.text, msg);
    }

    fn write(self: *Self, opcode: Opcode, payload: []const u8) !void {
        var total_size: usize = 0;

        var frame_header_size: u7 = switch (payload.len) {
            0...125 => @truncate(payload.len),
            126...65535 => 126,
            else => 127,
        };

        total_size += WsFrameHeader.header_size;
        var reply = WsFrameHeader{
            .size = frame_header_size,
            .opcode = opcode,
        };

        var payload_size_bytes = reply.payload_size_bytes_count();
        total_size += payload_size_bytes;
        total_size += payload.len;

        var data_frame = try self.allocator.alloc(u8, total_size);
        defer self.allocator.free(data_frame);

        var i: usize = 0;
        var header = std.mem.asBytes(&reply);
        @memcpy(data_frame[i..WsFrameHeader.header_size], header);
        i += WsFrameHeader.header_size;

        if (payload_size_bytes == @sizeOf(u16)) {
            const size: u16 = @truncate(payload.len);
            // swap endiannes for the network
            const swapped_size = (size >> 8) | (size << 8);
            @memcpy(
                data_frame[i .. i + @sizeOf(u16)],
                std.mem.asBytes(&swapped_size),
            );
            i += @sizeOf(u16);
        } else if (payload_size_bytes == @sizeOf(u64)) {
            const size: u64 = @truncate(payload.len);
            // swap endiannes for the network
            var swapped_size = size;
            swapped_size = (swapped_size & 0x00000000ffffffff) << 32 | (swapped_size & 0xffffffff00000000) >> 32;
            swapped_size = (swapped_size & 0x0000ffff0000ffff) << 16 | (swapped_size & 0xffff0000ffff0000) >> 16;
            swapped_size = (swapped_size & 0x00ff00ff00ff00ff) << 8 | (swapped_size & 0xff00ff00ff00ff00) >> 8;
            @memcpy(
                data_frame[WsFrameHeader.header_size .. WsFrameHeader.header_size + @sizeOf(u64)],
                std.mem.asBytes(&swapped_size),
            );
            i += @sizeOf(u64);
        }

        @memcpy(data_frame[i .. i + payload.len], payload);
        _ = try self.stream.writeAll(data_frame);
    }
};

test "hand shake" {
    const testing = std.testing;
    testing.log_level = .debug;
}
