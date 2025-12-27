// Symbol resolution from memory-mapped ELF
// Parses /proc/self/maps to find libc and resolves dlopen/dlsym

const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const syscalls = @import("syscalls.zig");
const utils = @import("utils.zig");
const printf = @import("printf.zig");

const MAPS_PATH = "/proc/self/maps";
const MAPS_BUF_SIZE = 64 * 1024;

// RTLD flags for dlopen
pub const RTLD_LAZY: c_int = 0x0001;
pub const RTLD_NOW: c_int = 0x0002;

// Context containing resolved dlopen/dlsym function pointers
pub const Context = struct {
    dlopen_ptr: *const fn (?[*:0]const u8, c_int) callconv(.c) ?*anyopaque,
    dlsym_ptr: *const fn (?*anyopaque, [*:0]const u8) callconv(.c) ?*anyopaque,

    pub fn dlopen(self: Context, path: ?[*:0]const u8, flags: c_int) ?*anyopaque {
        return self.dlopen_ptr(path, flags);
    }

    pub fn dlsym(self: Context, handle: ?*anyopaque, name: [*:0]const u8, comptime T: type) ?T {
        const ptr = self.dlsym_ptr(handle, name) orelse return null;
        return @ptrCast(ptr);
    }
};

var cached_libc_base: ?usize = null;

// In-memory ELF module structure
const Module = struct {
    eh: ?*const elf.Elf64_Ehdr = null,
    ph: ?[*]const elf.Elf64_Phdr = null,
    dyn: ?[*]const elf.Elf64_Dyn = null,
    base: usize = 0,

    // SYSV hash table
    nbucket: u32 = 0,
    nchain: u32 = 0,
    buckets: ?[*]const u32 = null,
    chains: ?[*]const u32 = null,

    // GNU hash table
    gnu_nbucket: u32 = 0,
    gnu_symoffset: u32 = 0,
    gnu_maskwords: u32 = 0,
    gnu_shift2: u32 = 0,
    gnu_bloom: ?[*]const usize = null,
    gnu_buckets: ?[*]const u32 = null,
    gnu_chain: ?[*]const u32 = null,

    // Symbol/string tables
    dynsym: ?[*]const elf.Elf64_Sym = null,
    dynstr: ?[*:0]const u8 = null,
};

fn u32Mod(a: u32, m: u32) u32 {
    return @intCast(utils.divmod(a, m).rem);
}

// Helper: convert DT_* pointer/offset to absolute VA
fn dynPtr(base: usize, lo: usize, hi: usize, p: usize) usize {
    var v = p;
    if (v < lo or v >= hi) {
        v += base;
    }
    return v;
}

const MapsEntry = struct {
    start: usize,
    offset: usize,
    path: ?[]const u8,
};

// Parse one /proc/self/maps line
// Format: start-end perms offset dev inode path
fn parseMapsLine(line: []const u8) ?MapsEntry {
    var it = mem.tokenizeScalar(u8, line, ' ');

    // Field 1: start-end
    const addr_range = it.next() orelse return null;
    const dash_pos = mem.indexOfScalar(u8, addr_range, '-') orelse return null;
    const start = std.fmt.parseUnsigned(usize, addr_range[0..dash_pos], 16) catch return null;

    // Field 2: perms (skip)
    _ = it.next() orelse return null;

    // Field 3: offset
    const offset_str = it.next() orelse return null;
    const offset = std.fmt.parseUnsigned(usize, offset_str, 16) catch return null;

    // Field 4: dev (skip)
    _ = it.next() orelse return null;

    // Field 5: inode (skip)
    _ = it.next() orelse return null;

    // Field 6: path (rest of line, may be empty)
    const rest = it.rest();
    const path: ?[]const u8 = if (rest.len == 0) null else rest;

    return .{ .start = start, .offset = offset, .path = path };
}

// Find libc base from /proc/self/maps
fn findLibcBase() ?usize {
    if (cached_libc_base) |base| return base;

    const fd = syscalls.open(MAPS_PATH, syscalls.O_RDONLY);
    if (fd < 0) return null;

    var buf: [MAPS_BUF_SIZE]u8 = undefined;
    const n = utils.readAll(fd, &buf, buf.len - 1);
    _ = syscalls.close(fd);
    if (n == 0) return null;

    var lines = mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (mem.indexOf(u8, line, "libc") == null) continue;

        if (parseMapsLine(line)) |entry| {
            if (entry.path != null and entry.offset == 0) {
                cached_libc_base = entry.start;

                printf.fdprintf(2, "libc base 0x%lx @ %s\n", &[_]printf.FormatArg{
                    printf.FormatArg.fromUint(entry.start),
                    printf.FormatArg.fromSlice(entry.path.?),
                });

                return entry.start;
            }
        }
    }

    return null;
}

const ModInitError = error{
    InvalidElfHeader,
    DynamicOutOfRange,
    NoDynamic,
    MissingSymbols,
};

// Initialize module from base address
fn modInit(m: *Module, base: usize) ModInitError!void {
    m.base = base;
    m.eh = @ptrFromInt(base);

    const eh = m.eh.?;

    // Validate ELF header
    if (!mem.startsWith(u8, &eh.e_ident, elf.MAGIC)) {
        return error.InvalidElfHeader;
    }

    m.ph = @ptrFromInt(base + eh.e_phoff);
    const ph = m.ph.?;

    printf.fdprintf(2, "mod_init: base=0x%lx phoff=0x%lx phnum=%u entsz=%u\n", &[_]printf.FormatArg{
        printf.FormatArg.fromUint(base),
        printf.FormatArg.fromUint(eh.e_phoff),
        printf.FormatArg.fromUint(eh.e_phnum),
        printf.FormatArg.fromUint(eh.e_phentsize),
    });

    // Find load range and PT_DYNAMIC in single pass
    var lo: usize = std.math.maxInt(usize);
    var hi: usize = 0;
    var dyn_addr: ?usize = null;

    for (ph[0..eh.e_phnum]) |p| {
        switch (p.p_type) {
            elf.PT_LOAD => {
                const seg_lo = base + p.p_vaddr;
                const seg_hi = seg_lo + p.p_memsz;
                if (seg_lo < lo) lo = seg_lo;
                if (seg_hi > hi) hi = seg_hi;
            },
            elf.PT_DYNAMIC => {
                dyn_addr = base + p.p_vaddr;
            },
            else => {},
        }
    }

    // Validate PT_DYNAMIC
    const da = dyn_addr orelse {
        printf.fdprintf(2, "mod_init: no PT_DYNAMIC\n", &[_]printf.FormatArg{});
        return error.NoDynamic;
    };

    if (da < lo or da + @sizeOf(elf.Elf64_Dyn) > hi) {
        printf.fdprintf(2, "mod_init: PT_DYNAMIC out of range: 0x%lx [0x%lx..0x%lx)\n", &[_]printf.FormatArg{
            printf.FormatArg.fromUint(da),
            printf.FormatArg.fromUint(lo),
            printf.FormatArg.fromUint(hi),
        });
        return error.DynamicOutOfRange;
    }

    m.dyn = @ptrFromInt(da);
    printf.fdprintf(2, "mod_init: PT_DYNAMIC @ 0x%lx\n", &[_]printf.FormatArg{
        printf.FormatArg.fromUint(da),
    });

    // Parse dynamic section
    const dyn = m.dyn.?;
    var di: usize = 0;
    while (dyn[di].d_tag != elf.DT_NULL) : (di += 1) {
        const d = dyn[di];
        switch (d.d_tag) {
            elf.DT_STRTAB => {
                m.dynstr = @ptrFromInt(dynPtr(base, lo, hi, d.d_val));
            },
            elf.DT_SYMTAB => {
                m.dynsym = @ptrFromInt(dynPtr(base, lo, hi, d.d_val));
            },
            elf.DT_HASH => {
                const h: [*]const u32 = @ptrFromInt(dynPtr(base, lo, hi, d.d_val));
                m.nbucket = h[0];
                m.nchain = h[1];
                m.buckets = h + 2;
                m.chains = h + 2 + m.nbucket;
            },
            elf.DT_GNU_HASH => {
                const gh: [*]const u32 = @ptrFromInt(dynPtr(base, lo, hi, d.d_val));
                m.gnu_nbucket = gh[0];
                m.gnu_symoffset = gh[1];
                m.gnu_maskwords = gh[2];
                m.gnu_shift2 = gh[3];
                m.gnu_bloom = @ptrFromInt(@intFromPtr(gh + 4));
                m.gnu_buckets = @ptrFromInt(@intFromPtr(m.gnu_bloom.?) + m.gnu_maskwords * @sizeOf(usize));
                m.gnu_chain = @ptrFromInt(@intFromPtr(m.gnu_buckets.?) + m.gnu_nbucket * @sizeOf(u32));
            },
            else => {},
        }
    }

    printf.fdprintf(2, "mod_init: dynsym=%p dynstr=%p gnu_hash=%p sysv_hash=%p\n", &[_]printf.FormatArg{
        printf.FormatArg.fromPtr(m.dynsym),
        printf.FormatArg.fromPtr(m.dynstr),
        printf.FormatArg.fromPtr(m.gnu_buckets),
        printf.FormatArg.fromPtr(m.buckets),
    });

    if (m.dynsym == null or m.dynstr == null) {
        return error.MissingSymbols;
    }
}

// SYSV hash function
fn sysvHash(name: [*:0]const u8) u32 {
    var h: u32 = 0;
    for (mem.span(name)) |c| {
        h = (h << 4) +% c;
        const g = h & 0xF0000000;
        if (g != 0) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

// GNU hash function
fn gnuHash(name: [*:0]const u8) u32 {
    var h: u32 = 5381;
    for (mem.span(name)) |c| {
        h = (h *% 33) +% c;
    }
    return h;
}

// GNU hash lookup
fn lookupGnu(m: *const Module, name: [*:0]const u8) ?*const elf.Elf64_Sym {
    if (m.gnu_buckets == null) return null;

    const h = gnuHash(name);
    const bloom_idx = (h / (@sizeOf(usize) * 8)) & (m.gnu_maskwords - 1);
    const bitmask = (@as(usize, 1) << @intCast(h % (@sizeOf(usize) * 8))) |
        (@as(usize, 1) << @intCast((h >> @intCast(m.gnu_shift2)) % (@sizeOf(usize) * 8)));

    if ((m.gnu_bloom.?[bloom_idx] & bitmask) != bitmask) {
        return null;
    }

    var idx = m.gnu_buckets.?[u32Mod(h, m.gnu_nbucket)];
    if (idx == 0) return null;

    while (true) {
        const hv = m.gnu_chain.?[idx - m.gnu_symoffset];
        if ((hv | 1) == (h | 1)) {
            const sym = &m.dynsym.?[idx];
            if (sym.st_name != 0) {
                const sym_name: [*:0]const u8 = @ptrCast(m.dynstr.? + sym.st_name);
                if (utils.strcmp(sym_name, name) == 0) {
                    return sym;
                }
            }
        }
        if ((hv & 1) != 0) break;
        idx += 1;
    }

    return null;
}

// SYSV hash lookup
fn lookupSysv(m: *const Module, name: [*:0]const u8) ?*const elf.Elf64_Sym {
    if (m.buckets == null) return null;

    const h = sysvHash(name);
    var i = m.buckets.?[u32Mod(h, m.nbucket)];

    while (i != 0) {
        const sym = &m.dynsym.?[i];
        if (sym.st_name != 0) {
            const sym_name: [*:0]const u8 = @ptrCast(m.dynstr.? + sym.st_name);
            if (utils.strcmp(sym_name, name) == 0) {
                return sym;
            }
        }
        i = m.chains.?[i];
    }

    return null;
}

// Resolve symbol by name
fn resolveSym(m: *const Module, name: [*:0]const u8) ?*anyopaque {
    const sym = lookupGnu(m, name) orelse lookupSysv(m, name) orelse return null;
    const sym_type = sym.st_type();
    if (sym_type != elf.STT_FUNC and sym_type != elf.STT_GNU_IFUNC) {
        return null;
    }
    return @ptrFromInt(m.base + sym.st_value);
}

pub const ResolveError = error{
    NoLibcBase,
    SymbolNotFound,
} || ModInitError;

// Initialize and return Context with resolved dlopen/dlsym
pub fn init(interp_base: usize) ResolveError!Context {
    const base = findLibcBase() orelse blk: {
        if (interp_base != 0) {
            printf.puts("Falling back to the interpreter, for muslc the loader/libc are the same");
            break :blk interp_base;
        }
        return error.NoLibcBase;
    };

    var m = Module{};
    try modInit(&m, base);

    // Try glibc internal first, then fallback to dlopen
    const dlopen_ptr = resolveSym(&m, "__libc_dlopen_mode") orelse resolveSym(&m, "dlopen");
    const dlsym_ptr = resolveSym(&m, "dlsym");

    if (dlopen_ptr == null or dlsym_ptr == null) {
        return error.SymbolNotFound;
    }

    return .{
        .dlopen_ptr = @ptrCast(dlopen_ptr.?),
        .dlsym_ptr = @ptrCast(dlsym_ptr.?),
    };
}
