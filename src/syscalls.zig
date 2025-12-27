// Direct Linux syscall wrappers for x86_64
// No libc dependency

// Syscall numbers for x86_64
const SYS_read: usize = 0;
const SYS_write: usize = 1;
const SYS_open: usize = 2;
const SYS_close: usize = 3;
const SYS_lseek: usize = 8;
const SYS_mmap: usize = 9;
const SYS_mprotect: usize = 10;
const SYS_munmap: usize = 11;
const SYS_exit: usize = 60;

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

// Generic syscall with up to 6 arguments
pub fn syscall6(
    number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) isize {
    // x86_64 syscall ABI:
    // rax = syscall number
    // rdi, rsi, rdx, r10, r8, r9 = arguments
    // syscall instruction clobbers rcx and r11
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (number),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{r10}" (arg4),
          [arg5] "{r8}" (arg5),
          [arg6] "{r9}" (arg6),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
}

inline fn syscall0(number: usize) isize {
    return syscall6(number, 0, 0, 0, 0, 0, 0);
}

inline fn syscall1(number: usize, arg1: usize) isize {
    return syscall6(number, arg1, 0, 0, 0, 0, 0);
}

inline fn syscall2(number: usize, arg1: usize, arg2: usize) isize {
    return syscall6(number, arg1, arg2, 0, 0, 0, 0);
}

inline fn syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) isize {
    return syscall6(number, arg1, arg2, arg3, 0, 0, 0);
}

const MAX_ERRNO: isize = 4095;

fn checkError(rc: isize) isize {
    if (rc < 0 and rc >= -MAX_ERRNO) {
        return -1;
    }
    return rc;
}

// Syscall wrappers

pub fn exit(status: c_int) noreturn {
    _ = syscall1(SYS_exit, @bitCast(@as(isize, status)));
    unreachable;
}

pub fn open(filename: [*:0]const u8, flags: c_int) c_int {
    const rc = syscall2(SYS_open, @intFromPtr(filename), @bitCast(@as(isize, flags)));
    return @intCast(checkError(rc));
}

pub fn close(fd: c_int) c_int {
    const rc = syscall1(SYS_close, @bitCast(@as(isize, fd)));
    return @intCast(checkError(rc));
}

pub fn read(fd: c_int, buf: [*]u8, count: usize) isize {
    const rc = syscall3(SYS_read, @bitCast(@as(isize, fd)), @intFromPtr(buf), count);
    return checkError(rc);
}

pub fn write(fd: c_int, buf: [*]const u8, count: usize) isize {
    const rc = syscall3(SYS_write, @bitCast(@as(isize, fd)), @intFromPtr(buf), count);
    return checkError(rc);
}

pub fn lseek(fd: c_int, offset: i64, whence: c_int) i64 {
    const rc = syscall3(
        SYS_lseek,
        @bitCast(@as(isize, fd)),
        @bitCast(offset),
        @bitCast(@as(isize, whence)),
    );
    return @bitCast(checkError(rc));
}

pub fn mmap(
    addr: ?*anyopaque,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) usize {
    const rc = syscall6(
        SYS_mmap,
        @intFromPtr(addr),
        length,
        @bitCast(@as(isize, prot)),
        @bitCast(@as(isize, flags)),
        @bitCast(@as(isize, fd)),
        @bitCast(offset),
    );
    // For mmap, return raw result (MAP_FAILED = -1)
    return @bitCast(rc);
}

pub fn munmap(addr: *anyopaque, length: usize) c_int {
    const rc = syscall2(SYS_munmap, @intFromPtr(addr), length);
    return @intCast(checkError(rc));
}

pub fn mprotect(addr: *anyopaque, length: usize, prot: c_int) c_int {
    const rc = syscall3(
        SYS_mprotect,
        @intFromPtr(addr),
        length,
        @bitCast(@as(isize, prot)),
    );
    return @intCast(checkError(rc));
}
