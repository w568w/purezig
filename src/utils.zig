// Utility functions for freestanding environment

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const elf = std.elf;

pub const ReadExactError = posix.ReadError || error{EndOfStream};

pub fn readExact(fd: posix.fd_t, buf: []u8) ReadExactError!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try posix.read(fd, buf[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

pub inline fn pflags(x: u32) u32 {
    var prot: u32 = 0;
    if (x & elf.PF_X != 0) prot |= linux.PROT.EXEC;
    if (x & elf.PF_W != 0) prot |= linux.PROT.WRITE;
    if (x & elf.PF_R != 0) prot |= linux.PROT.READ;
    return prot;
}
