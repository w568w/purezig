// Utility functions for freestanding environment

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const elf = std.elf;

pub fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int {
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

pub const ReadExactError = posix.ReadError || error{EndOfStream};

pub fn readExact(fd: posix.fd_t, buf: []u8) ReadExactError!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try posix.read(fd, buf[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
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

pub inline fn pflags(x: u32) u32 {
    var prot: u32 = 0;
    if (x & elf.PF_X != 0) prot |= linux.PROT.EXEC;
    if (x & elf.PF_W != 0) prot |= linux.PROT.WRITE;
    if (x & elf.PF_R != 0) prot |= linux.PROT.READ;
    return prot;
}
