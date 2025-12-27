// Utility functions for freestanding environment

const syscalls = @import("syscalls.zig");

pub fn memset(dest: [*]u8, c: u8, n: usize) [*]u8 {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        dest[i] = c;
    }
    return dest;
}

pub fn memcpy(dest: [*]u8, src: [*]const u8, n: usize) [*]u8 {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        dest[i] = src[i];
    }
    return dest;
}

pub fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int {
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

pub fn readAll(fd: c_int, buf: [*]u8, sz: usize) usize {
    var off: usize = 0;
    while (off < sz) {
        const n = syscalls.read(fd, buf + off, sz - off);
        if (n <= 0) break;
        off += @intCast(n);
    }
    return off;
}

// Page alignment helpers
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

pub inline fn roundPg(x: usize) usize {
    return (x + PAGE_MASK) & ~PAGE_MASK;
}

pub inline fn truncPg(x: usize) usize {
    return x & ~PAGE_MASK;
}

const elf = @import("std").elf;

pub inline fn pflags(x: u32) c_int {
    var prot: c_int = 0;
    if (x & elf.PF_X != 0) prot |= syscalls.PROT_EXEC;
    if (x & elf.PF_W != 0) prot |= syscalls.PROT_WRITE;
    if (x & elf.PF_R != 0) prot |= syscalls.PROT_READ;
    return prot;
}

pub fn divmod(a: u64, m: u64) struct { quot: u64, rem: u64 } {
    if (m == 0) return .{ .quot = 0, .rem = 0 };
    var q: u64 = 0;
    var x: u64 = a;
    var d: u64 = m;
    var shift: u64 = 1;
    while ((d << 1) > d and (d << 1) <= x) {
        d <<= 1;
        shift <<= 1;
    }
    while (shift != 0) {
        if (x >= d) {
            x -= d;
            q += shift;
        }
        d >>= 1;
        shift >>= 1;
    }
    return .{ .quot = q, .rem = x };
}

// Export as weak symbols for compiler-emitted calls
comptime {
    @export(&memsetWrapper, .{ .name = "memset", .linkage = .weak });
    @export(&memcpyWrapper, .{ .name = "memcpy", .linkage = .weak });
}

fn memsetWrapper(dest: ?*anyopaque, c: c_int, n: usize) callconv(.c) ?*anyopaque {
    if (dest) |d| {
        _ = memset(@ptrCast(d), @truncate(@as(c_uint, @bitCast(c))), n);
    }
    return dest;
}

fn memcpyWrapper(dest: ?*anyopaque, src: ?*const anyopaque, n: usize) callconv(.c) ?*anyopaque {
    if (dest) |d| {
        if (src) |s| {
            _ = memcpy(@ptrCast(d), @ptrCast(s), n);
        }
    }
    return dest;
}
