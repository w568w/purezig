// Utility functions for freestanding environment

const syscalls = @import("syscalls.zig");

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

