// Custom printf implementation for freestanding environment
// No libc dependency, avoids hardware division

const syscalls = @import("syscalls.zig");

const OutputBuffer = struct {
    const SIZE: usize = 128;

    buf: [SIZE]u8 = undefined,
    ptr: usize = 0,
    fd: c_int = -1,

    fn flush(self: *OutputBuffer) void {
        if (self.ptr > 0 and self.fd >= 0) {
            _ = syscalls.write(self.fd, &self.buf, self.ptr);
            self.ptr = 0;
        }
    }

    fn putchar(self: *OutputBuffer, c: u8, fd: c_int) void {
        if (fd != self.fd) {
            self.flush();
            self.fd = fd;
        }
        self.buf[self.ptr] = c;
        self.ptr += 1;
        if (self.ptr >= SIZE or c == '\n' or c == '\r') {
            self.flush();
        }
    }

    fn putstr(self: *OutputBuffer, s: [*:0]const u8, fd: c_int) void {
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            self.putchar(s[i], fd);
        }
    }
};

var output = OutputBuffer{};

fn putcharFd(c: u8, fd: c_int) void {
    output.putchar(c, fd);
}

fn putstrFd(s: [*:0]const u8, fd: c_int) void {
    output.putstr(s, fd);
}

fn flushBuf() void {
    output.flush();
}

const utils = @import("utils.zig");

fn kprintn(fd: c_int, val: u64, base: u64, min_width: usize) void {
    const digits = "0123456789abcdef";
    var buf: [22]u8 = undefined;
    var p: usize = 0;
    var ul = val;

    while (ul != 0 or p < min_width) {
        const dm = utils.divmod(ul, base);
        buf[p] = digits[@intCast(dm.rem)];
        p += 1;
        ul = dm.quot;
        if (ul == 0 and min_width == 0) break;
    }
    if (p == 0) {
        buf[p] = '0';
        p += 1;
    }

    while (p > 0) {
        p -= 1;
        putcharFd(buf[p], fd);
    }
}

// Runtime format string parser
pub fn vfdprintf(fd: c_int, fmt: [*:0]const u8, args: []const FormatArg) void {
    var i: usize = 0;
    var arg_idx: usize = 0;

    while (fmt[i] != 0) {
        if (fmt[i] != '%') {
            putcharFd(fmt[i], fd);
            i += 1;
            continue;
        }

        i += 1; // skip '%'
        if (fmt[i] == 0) break;

        var lflag: bool = false;

        // Check for 'l' modifier
        if (fmt[i] == 'l') {
            lflag = true;
            i += 1;
            if (fmt[i] == 0) break;
        }

        const spec = fmt[i];
        i += 1;

        if (arg_idx >= args.len) {
            putcharFd('?', fd);
            continue;
        }

        const arg = args[arg_idx];
        arg_idx += 1;

        switch (spec) {
            'c' => {
                putcharFd(@truncate(arg.asUint() & 0x7f), fd);
            },
            's' => {
                switch (arg) {
                    .str => |s| putstrFd(s, fd),
                    .slice => |s| for (s) |c| putcharFd(c, fd),
                    .ptr => |p| if (p != 0) putstrFd(@ptrFromInt(p), fd) else putstrFd("(null)", fd),
                    else => putstrFd("(null)", fd),
                }
            },
            'd' => {
                const val = if (lflag) arg.asInt() else @as(i64, @as(i32, @truncate(arg.asInt())));
                if (val < 0) {
                    putcharFd('-', fd);
                    kprintn(fd, @intCast(-val), 10, 0);
                } else {
                    kprintn(fd, @intCast(val), 10, 0);
                }
            },
            'u' => {
                const val = if (lflag) arg.asUint() else @as(u64, @as(u32, @truncate(arg.asUint())));
                kprintn(fd, val, 10, 0);
            },
            'o' => {
                const val = if (lflag) arg.asUint() else @as(u64, @as(u32, @truncate(arg.asUint())));
                kprintn(fd, val, 8, 0);
            },
            'p' => {
                putcharFd('0', fd);
                putcharFd('x', fd);
                kprintn(fd, arg.asUint(), 16, 0);
            },
            'x' => {
                const val = if (lflag) arg.asUint() else @as(u64, @as(u32, @truncate(arg.asUint())));
                kprintn(fd, val, 16, 0);
            },
            'X' => {
                const val = if (lflag) arg.asUint() else @as(u64, @as(u32, @truncate(arg.asUint())));
                const width: usize = if (lflag) 16 else 8;
                kprintn(fd, val, 16, width);
            },
            '%' => {
                putcharFd('%', fd);
                arg_idx -= 1; // Don't consume an argument
            },
            else => {
                putcharFd('%', fd);
                if (lflag) putcharFd('l', fd);
                putcharFd(spec, fd);
                arg_idx -= 1;
            },
        }
    }

    flushBuf();
}

// Format argument tagged union
pub const FormatArg = union(enum) {
    uint: u64,
    int: i64,
    ptr: usize,
    str: [*:0]const u8,
    slice: []const u8,

    pub fn fromUint(v: anytype) FormatArg {
        return .{ .uint = @intCast(v) };
    }

    pub fn fromInt(v: anytype) FormatArg {
        return .{ .int = @intCast(v) };
    }

    pub fn fromPtr(v: anytype) FormatArg {
        return .{ .ptr = @intFromPtr(v) };
    }

    pub fn fromStr(v: [*:0]const u8) FormatArg {
        return .{ .str = v };
    }

    pub fn fromSlice(v: []const u8) FormatArg {
        return .{ .slice = v };
    }

    fn asUint(self: FormatArg) u64 {
        return switch (self) {
            .uint => |v| v,
            .int => |v| @bitCast(v),
            .ptr => |v| v,
            else => 0,
        };
    }

    fn asInt(self: FormatArg) i64 {
        return switch (self) {
            .int => |v| v,
            .uint => |v| @bitCast(v),
            else => 0,
        };
    }
};

// Convenience wrappers
pub fn printf(fmt: [*:0]const u8, args: []const FormatArg) void {
    vfdprintf(2, fmt, args);
}

pub fn fdprintf(fd: c_int, fmt: [*:0]const u8, args: []const FormatArg) void {
    vfdprintf(fd, fmt, args);
}

// Simple string output without formatting
pub fn puts(s: [*:0]const u8) void {
    putstrFd(s, 2);
    putcharFd('\n', 2);
    flushBuf();
}

pub fn fputs(s: [*:0]const u8, fd: c_int) void {
    putstrFd(s, fd);
    flushBuf();
}
