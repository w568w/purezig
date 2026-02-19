// Syscall wrappers using Zig standard library
// Uses std.os.linux for freestanding target

const std = @import("std");
const linux = std.os.linux;

// Open flags
pub const O_RDONLY: c_int = 0;

// Seek constants
pub const SEEK_SET: c_int = 0;
pub const SEEK_CUR: c_int = 1;
pub const SEEK_END: c_int = 2;

// Memory protection flags
pub const PROT_NONE: c_int = 0x0;
pub const PROT_READ: c_int = 0x1;
pub const PROT_WRITE: c_int = 0x2;
pub const PROT_EXEC: c_int = 0x4;

// Memory mapping flags
pub const MAP_SHARED: c_int = 0x01;
pub const MAP_PRIVATE: c_int = 0x02;
pub const MAP_FIXED: c_int = 0x10;
pub const MAP_ANONYMOUS: c_int = 0x20;

pub const MAP_FAILED: usize = @bitCast(@as(isize, -1));

// Syscall wrappers using std.os.linux

pub fn exit(status: c_int) noreturn {
    _ = linux.syscall1(.exit, @bitCast(@as(isize, status)));
    unreachable;
}

pub fn open(filename: [*:0]const u8, flags: c_int) c_int {
    const rc = linux.syscall2(.open, @intFromPtr(filename), @bitCast(@as(isize, flags)));
    return if (@as(isize, @bitCast(rc)) < 0) -1 else @intCast(rc);
}

pub fn close(fd: c_int) c_int {
    const rc = linux.syscall1(.close, @bitCast(@as(isize, fd)));
    return if (@as(isize, @bitCast(rc)) < 0) -1 else 0;
}

pub fn read(fd: c_int, buf: [*]u8, count: usize) isize {
    const rc = linux.syscall3(.read, @bitCast(@as(isize, fd)), @intFromPtr(buf), count);
    return @bitCast(rc);
}

pub fn write(fd: c_int, buf: [*]const u8, count: usize) isize {
    const rc = linux.syscall3(.write, @bitCast(@as(isize, fd)), @intFromPtr(buf), count);
    return @bitCast(rc);
}

pub fn lseek(fd: c_int, offset: i64, whence: c_int) i64 {
    const rc = linux.syscall3(.lseek, @bitCast(@as(isize, fd)), @bitCast(offset), @bitCast(@as(isize, whence)));
    return @bitCast(rc);
}

pub fn mmap(
    addr: ?*anyopaque,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) usize {
    const rc = linux.syscall6(
        .mmap,
        @intFromPtr(addr),
        length,
        @bitCast(@as(isize, prot)),
        @bitCast(@as(isize, flags)),
        @bitCast(@as(isize, fd)),
        @bitCast(offset),
    );
    return rc;
}

pub fn munmap(addr: *anyopaque, length: usize) c_int {
    const rc = linux.syscall2(.munmap, @intFromPtr(addr), length);
    return if (@as(isize, @bitCast(rc)) < 0) -1 else 0;
}

pub fn mprotect(addr: *anyopaque, length: usize, prot: c_int) c_int {
    const rc = linux.syscall3(
        .mprotect,
        @intFromPtr(addr),
        length,
        @bitCast(@as(isize, prot)),
    );
    return if (@as(isize, @bitCast(rc)) < 0) -1 else 0;
}
