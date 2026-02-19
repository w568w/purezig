// ELF Loader - loads ELF executables and their interpreters
// Hijacks AT_ENTRY to regain control after dynamic linker initialization

const std = @import("std");
const elf = std.elf;
const linux = std.os.linux;
const posix = std.posix;
const utils = @import("utils.zig");
const fdl_resolve = @import("fdl_resolve.zig");

const print = std.debug.print;

const PATH_MAX = 4096;
const MAX_PHNUM = 16;

fn checkEhdr(ehdr: *const elf.Elf64_Ehdr) bool {
    return std.mem.startsWith(u8, &ehdr.e_ident, elf.MAGIC) and
        ehdr.e_ident[elf.EI_CLASS] == elf.ELFCLASS64 and
        ehdr.e_ident[elf.EI_VERSION] == 1 and
        (ehdr.e_type == .EXEC or ehdr.e_type == .DYN);
}

const LoadElfError = posix.MMapError || posix.SeekError || posix.MProtectError || utils.ReadExactError;

/// Map ELF PT_LOAD segments into anonymous memory.
/// Returns the base address of the loaded image.
fn loadSegments(fd: posix.fd_t, ehdr: *const elf.Elf64_Ehdr, phdr: [*]const elf.Elf64_Phdr) LoadElfError!usize {
    var minva: usize = ~@as(usize, 0);
    var maxva: usize = 0;
    const dyn = ehdr.e_type == .DYN;

    for (phdr[0..ehdr.e_phnum]) |p| {
        if (p.p_type != elf.PT_LOAD) continue;
        if (p.p_vaddr < minva) minva = p.p_vaddr;
        const end = p.p_vaddr + p.p_memsz;
        if (end > maxva) maxva = end;
    }

    minva = utils.truncPg(minva);
    maxva = utils.roundPg(maxva);

    // Reserve the full address range
    const hint: ?[*]align(utils.PAGE_SIZE) u8 = if (dyn) null else @ptrFromInt(minva);
    const reservation = try posix.mmap(
        hint,
        maxva - minva,
        linux.PROT.NONE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = !dyn },
        -1,
        0,
    );
    const base: usize = @intFromPtr(reservation.ptr);
    errdefer posix.munmap(reservation);

    // Map each PT_LOAD segment (MAP_FIXED replaces portions of the reservation)
    for (phdr[0..ehdr.e_phnum]) |p| {
        if (p.p_type != elf.PT_LOAD) continue;

        const off = p.p_vaddr & utils.PAGE_MASK;
        const seg_start = (if (dyn) base else 0) + utils.truncPg(p.p_vaddr);
        const sz = utils.roundPg(p.p_memsz + off);

        const mapped = try posix.mmap(
            @ptrFromInt(seg_start),
            sz,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true },
            -1,
            0,
        );

        try posix.lseek_SET(fd, p.p_offset);
        const dest: [*]u8 = @ptrFromInt(@intFromPtr(mapped.ptr) + off);
        try utils.readExact(fd, dest[0..p.p_filesz]);

        try posix.mprotect(@alignCast(mapped.ptr[0..sz]), utils.pflags(p.p_flags));
    }

    return base;
}

/// Result of loading a single ELF file.
const ElfInfo = struct {
    ehdr: elf.Elf64_Ehdr,
    base: usize,
    entry: usize,
    interp: ?[*:0]const u8,
};

/// Open an ELF file, validate its header, load it into memory, and
/// optionally extract the PT_INTERP path.  `interp_buf` receives the
/// null-terminated interpreter path when one exists.
fn readElf(path: [*:0]const u8, interp_buf: *[PATH_MAX]u8) ElfInfo {
    const fd = posix.openZ(path, .{}, 0) catch {
        errx("can't open", path);
    };
    defer posix.close(fd);

    // Read and validate ELF header
    var ehdr_bytes: [@sizeOf(elf.Elf64_Ehdr)]u8 = undefined;
    utils.readExact(fd, &ehdr_bytes) catch {
        errx("can't read ELF header", path);
    };
    const ehdr: elf.Elf64_Ehdr = @bitCast(ehdr_bytes);

    if (!checkEhdr(&ehdr)) {
        errx("bogus or incompatible ELF header", path);
    }

    // Read program headers
    if (ehdr.e_phnum > MAX_PHNUM) {
        errx("too many program headers", path);
    }
    var phdr_buf: [MAX_PHNUM * @sizeOf(elf.Elf64_Phdr)]u8 align(@alignOf(elf.Elf64_Phdr)) = undefined;
    const phdr_size = @as(usize, ehdr.e_phnum) * @sizeOf(elf.Elf64_Phdr);

    posix.lseek_SET(fd, ehdr.e_phoff) catch {
        errx("can't seek to program headers", path);
    };
    utils.readExact(fd, phdr_buf[0..phdr_size]) catch {
        errx("can't read program headers", path);
    };
    const phdr: [*]const elf.Elf64_Phdr = @ptrCast(@alignCast(&phdr_buf));

    // Load segments into memory
    const base = loadSegments(fd, &ehdr, phdr) catch {
        errx("can't load ELF", path);
    };
    const entry = ehdr.e_entry + if (ehdr.e_type == .DYN) base else 0;

    // Look for PT_INTERP
    var interp: ?[*:0]const u8 = null;
    for (phdr[0..ehdr.e_phnum]) |ph| {
        if (ph.p_type != elf.PT_INTERP) continue;
        if (ph.p_filesz >= PATH_MAX) {
            errx("interpreter path too long", path);
        }
        posix.lseek_SET(fd, ph.p_offset) catch {
            errx("can't seek to interpreter path", path);
        };
        utils.readExact(fd, interp_buf[0..ph.p_filesz]) catch {
            errx("can't read interpreter path", path);
        };
        interp_buf[ph.p_filesz] = 0;
        interp = @ptrCast(interp_buf);
        break;
    }

    return .{ .ehdr = ehdr, .base = base, .entry = entry, .interp = interp };
}

/// Pointers into the newly-constructed process stack.
const StackInfo = struct {
    sp: [*]usize,
    argv: [*][*:0]u8,
    auxv: [*]elf.Elf64_auxv_t,
};

/// Clone the original process stack with a new argv while preserving
/// envp and the auxiliary vector.
fn buildStack(
    orig_sp: [*]usize,
    argv: []const [*:0]const u8,
    buf: *align(16) [4096]u8,
) StackInfo {
    // Walk past the original argv to find where envp+auxv begin
    var p = orig_sp + 1; // skip argc
    while (p[0] != 0) : (p += 1) {} // skip argv
    p += 1; // skip argv terminator

    const env_start = p;
    while (p[0] != 0) : (p += 1) {} // skip envp
    p += 1; // skip envp terminator
    while (p[0] != 0) : (p += 2) {} // skip auxv pairs
    p += 1; // skip auxv terminator

    const env_aux_len = p - env_start;
    const argc = argv.len;

    // Build new stack: [argc] [argv...] [0] [envp...] [0] [auxv...] [0]
    const sp: [*]usize = @ptrCast(@alignCast(buf));
    sp[0] = argc;

    const new_argv: [*][*:0]u8 = @ptrCast(sp + 1);
    const dest: [*][*:0]const u8 = @ptrCast(new_argv);
    @memmove(dest, argv);

    const env_aux_dst: [*]usize = @ptrCast(new_argv + argc);
    @memmove(env_aux_dst, env_start[0..env_aux_len]);

    // Locate auxv in the new stack (skip envp null terminator)
    var env_p: [*]usize = @ptrCast(&new_argv[argc + 1]);
    while (env_p[0] != 0) : (env_p += 1) {}
    env_p += 1;

    return .{
        .sp = sp,
        .argv = new_argv,
        .auxv = @ptrCast(@alignCast(env_p)),
    };
}

fn patchAuxv(
    auxv: [*]elf.Elf64_auxv_t,
    prog: *const ElfInfo,
    interp_base: ?usize,
    hijack_entry: usize,
    exec_filename: usize,
) void {
    var av = auxv;
    while (av[0].a_type != elf.AT_NULL) : (av += 1) {
        switch (av[0].a_type) {
            elf.AT_PHDR => av[0].a_un.a_val = prog.base + prog.ehdr.e_phoff,
            elf.AT_PHNUM => av[0].a_un.a_val = prog.ehdr.e_phnum,
            elf.AT_PHENT => av[0].a_un.a_val = prog.ehdr.e_phentsize,
            elf.AT_ENTRY => av[0].a_un.a_val = hijack_entry,
            elf.AT_EXECFN => av[0].a_un.a_val = exec_filename,
            elf.AT_BASE => if (interp_base) |b| {
                av[0].a_un.a_val = b;
            },
            else => {},
        }
    }
}

fn errx(msg: [*:0]const u8, file: ?[*:0]const u8) noreturn {
    if (file) |f| {
        print("error: {s}: {s}\n", .{ msg, f });
    } else {
        print("error: {s}\n", .{msg});
    }
    linux.exit(1);
}

pub fn Loader(
    comptime app_main: fn (c_int, [*][*:0]u8) c_int,
    comptime fdl_main: fn (*fdl_resolve.Context) void,
) type {
    return struct {
        const Self = @This();

        pub const _start = {};

        pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
            linux.exit(1);
        }

        comptime {
            _ = Self.z_start;
        }

        var entry_sp: ?[*]usize = null;
        var interp_base: usize = 0;

        /// Initial entry point (called from z_start via inline asm).
        /// Replicates the std.start initialization sequence: PIE
        /// relocations first, then TLS setup.
        pub export fn z_entry(sp: [*]usize) callconv(.c) void {
            @setRuntimeSafety(false);
            @disableInstrumentation();

            const argc: usize = sp[0];
            const argv: [*][*:0]u8 = @ptrCast(sp + 1);
            var env_p: [*]usize = @ptrCast(sp + 1 + argc + 1);
            while (env_p[0] != 0) : (env_p += 1) {}
            env_p += 1;
            const auxv: [*]elf.Elf64_auxv_t = @ptrCast(@alignCast(env_p));

            var at_phdr: usize = 0;
            var at_phnum: usize = 0;
            {
                var i: usize = 0;
                while (auxv[i].a_type != elf.AT_NULL) : (i += 1) {
                    switch (auxv[i].a_type) {
                        elf.AT_PHDR => at_phdr = auxv[i].a_un.a_val,
                        elf.AT_PHNUM => at_phnum = auxv[i].a_un.a_val,
                        else => {},
                    }
                }
            }
            const phdrs = @as([*]elf.Elf64_Phdr, @ptrFromInt(at_phdr))[0..at_phnum];

            // PIE relocations must happen before any global variable access
            @call(.always_inline, std.pie.relocate, .{phdrs});

            std.os.linux.elf_aux_maybe = auxv;
            std.os.linux.tls.initStatic(phdrs);

            entry_sp = sp;
            _ = app_main(@intCast(argc), argv);
        }

        /// Called after the dynamic loader finishes initialisation.
        pub export fn fdl_entry_impl() callconv(.c) void {
            print("Loader is in memory... Start parsing logic\n", .{});

            var ctx = fdl_resolve.init(interp_base) catch {
                linux.exit(1);
            };
            fdl_main(&ctx);

            linux.exit(0);
        }

        /// Naked trampoline that the hijacked AT_ENTRY points to.
        pub export fn z_fdl_entry() callconv(.naked) noreturn {
            asm volatile (
                \\andq $-16, %%rsp
                \\call *%[impl]
                \\hlt
                :
                : [impl] "r" (@intFromPtr(&Self.fdl_entry_impl)),
            );
        }

        /// Load an ELF executable (and its interpreter, if any),
        /// patch the auxiliary vector, and jump to the entry point.
        pub fn execElf(file: [*:0]const u8, argv: []const [*:0]const u8) void {
            const orig_sp = entry_sp orelse return;

            // 1. Build a new process stack with our argv
            var stack_buf: [4096]u8 align(16) = undefined;
            const stack = buildStack(orig_sp, argv, &stack_buf);

            // 2. Load the program
            var interp_path_buf: [PATH_MAX]u8 = undefined;
            const prog = readElf(file, &interp_path_buf);

            // 3. If the program needs a dynamic linker, load it too
            var unused_buf: [PATH_MAX]u8 = undefined;
            const interp: ?ElfInfo = if (prog.interp) |path| blk: {
                print("elf_interp: {s}\n", .{path});
                break :blk readElf(path, &unused_buf);
            } else null;

            // 4. Patch auxiliary vector (hijack AT_ENTRY → z_fdl_entry)
            patchAuxv(
                stack.auxv,
                &prog,
                if (interp) |i| i.base else null,
                @intFromPtr(&Self.z_fdl_entry),
                @intFromPtr(stack.argv[1]),
            );

            if (interp) |i| {
                interp_base = i.base;
            }

            print("Calling trampo...file: {s}, interp: {s}\n", .{
                file,
                if (prog.interp) |p| p else @as([*:0]const u8, "(none)"),
            });

            // 5. Jump to the dynamic loader (or directly to the program)
            const target = if (interp) |i| i.entry else prog.entry;
            trampo(target, stack.sp);
        }

        /// Raw program entry point — passes the stack pointer to z_entry.
        pub export fn z_start() callconv(.naked) noreturn {
            asm volatile (
                \\mov %%rsp, %%rdi
                \\call *%[entry]
                \\hlt
                :
                : [entry] "r" (@intFromPtr(&Self.z_entry)),
            );
        }
    };
}

/// Trampoline: set the stack pointer and jump to an entry address.
fn trampo(entry: usize, sp: [*]usize) noreturn {
    asm volatile (
        \\mov %[sp], %%rsp
        \\jmp *%[entry]
        :
        : [entry] "r" (entry),
          [sp] "r" (@intFromPtr(sp)),
    );
    while (true) {}
}
