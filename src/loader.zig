// ELF Loader - loads ELF executables and their interpreters
// Hijacks AT_ENTRY to regain control after dynamic linker initialization

const std = @import("std");
const elf = std.elf;
const linux = std.os.linux;
const posix = std.posix;
const utils = @import("utils.zig");
const fdl_resolve = @import("fdl_resolve.zig");

const print = std.debug.print;

const Z_PROG: usize = 0;
const Z_INTERP: usize = 1;

// Check ELF header validity
fn checkEhdr(ehdr: *const elf.Elf64_Ehdr) bool {
    return std.mem.startsWith(u8, &ehdr.e_ident, elf.MAGIC) and
        ehdr.e_ident[elf.EI_CLASS] == elf.ELFCLASS64 and
        ehdr.e_ident[elf.EI_VERSION] == 1 and
        (ehdr.e_type == .EXEC or ehdr.e_type == .DYN);
}

const LoadElfError = posix.MMapError || posix.SeekError || posix.MProtectError || error{ReadFailed};

// Load ELF into anonymous memory
fn loadelfAnon(fd: posix.fd_t, ehdr: *const elf.Elf64_Ehdr, phdr: [*]const elf.Elf64_Phdr) LoadElfError!usize {
    var minva: usize = ~@as(usize, 0);
    var maxva: usize = 0;
    const dyn = ehdr.e_type == .DYN;

    // Find min/max virtual addresses from PT_LOAD segments
    for (phdr[0..ehdr.e_phnum]) |p| {
        if (p.p_type != elf.PT_LOAD) continue;
        if (p.p_vaddr < minva) minva = p.p_vaddr;
        const end = p.p_vaddr + p.p_memsz;
        if (end > maxva) maxva = end;
    }

    minva = utils.truncPg(minva);
    maxva = utils.roundPg(maxva);

    // Reserve address space
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

    // Map each segment (MAP_FIXED will replace portions of the PROT_NONE reservation)
    for (phdr[0..ehdr.e_phnum]) |p| {
        if (p.p_type != elf.PT_LOAD) continue;

        const off = p.p_vaddr & utils.PAGE_MASK;
        const start_addr: usize = if (dyn) base else 0;
        const seg_start = start_addr + utils.truncPg(p.p_vaddr);
        const sz = utils.roundPg(p.p_memsz + off);

        // Map segment with read/write for loading
        const mapped = try posix.mmap(
            @ptrFromInt(seg_start),
            sz,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true },
            -1,
            0,
        );

        // Seek and read segment content
        try posix.lseek_SET(fd, p.p_offset);

        const dest: [*]u8 = @ptrFromInt(@intFromPtr(mapped.ptr) + off);
        if (utils.readAll(fd, dest, p.p_filesz) != p.p_filesz) {
            return error.ReadFailed;
        }

        // Set final protections
        try posix.mprotect(@alignCast(mapped.ptr[0..sz]), utils.pflags(p.p_flags));
    }

    return base;
}

fn errx(msg: [*:0]const u8, file: ?[*:0]const u8) noreturn {
    if (file) |f| {
        print("error: {s}: {s}\n", .{ msg, f });
    } else {
        print("error: {s}\n", .{msg});
    }
    linux.exit(1);
}

// Generic Loader configured by main.zig
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

        // Entry point called from z_start.
        // Must replicate std.start initialization: PIE relocations, then TLS setup.
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

        // Called after dynamic loader initializes
        pub export fn fdl_entry_impl() callconv(.c) void {
            print("Loader is in memory... Start parsing logic\n", .{});

            var ctx = fdl_resolve.init(interp_base) catch {
                linux.exit(1);
            };
            fdl_main(&ctx);

            linux.exit(0);
        }

        // z_fdl_entry: Entry point after dynamic loader initializes
        pub export fn z_fdl_entry() callconv(.naked) noreturn {
            asm volatile (
                \\andq $-16, %%rsp
                \\call *%[impl]
                \\hlt
                :
                : [impl] "r" (@intFromPtr(&Self.fdl_entry_impl)),
            );
        }

        // Main ELF execution function
        pub fn execElf(file: [*:0]const u8, argc: c_int, argv: [*][*:0]u8) void {
            var ehdrs: [2]elf.Elf64_Ehdr = undefined;
            var base: [2]usize = undefined;
            var entry: [2]usize = undefined;
            var elf_interp: ?[*:0]u8 = null;
            var current_file: [*:0]const u8 = file;
            const PATH_MAX = 4096;
            var static_interp: [PATH_MAX]u8 = undefined;

            var sp = entry_sp orelse return;

            // Build new stack with our argv
            // Skip argc
            var p = sp + 1;
            // Skip argv
            while (p[0] != 0) : (p += 1) {}
            p += 1;

            const from = p;
            // Skip env
            while (p[0] != 0) : (p += 1) {}
            p += 1;
            // Skip aux vector
            while (p[0] != 0) : (p += 2) {}
            p += 1;

            // Calculate sizes and build new stack
            const usize_argc = @as(usize, @intCast(argc));
            const usize_env_aux = p - from;

            // Allocate on stack (use a fixed buffer since we can't use alloca)
            var stack_buf: [4096]u8 align(16) = undefined;
            const new_sp: [*]usize = @ptrCast(@alignCast(&stack_buf));

            new_sp[0] = usize_argc;
            const argv_ptr = @as([*][*:0]u8, @ptrCast(new_sp + 1));
            @memmove(argv_ptr, argv[0..usize_argc]);
            const env_aux_ptr = @as([*]usize, @ptrCast(argv_ptr + usize_argc));
            @memmove(env_aux_ptr, from[0..usize_env_aux]);

            sp = new_sp;
            const new_argv: [*][*:0]u8 = @ptrCast(sp + 1);

            // Find env and auxv
            var env_p: [*]usize = @ptrCast(&new_argv[@intCast(argc + 1)]);
            while (env_p[0] != 0) : (env_p += 1) {}
            env_p += 1;
            var av: [*]elf.Elf64_auxv_t = @ptrCast(@alignCast(env_p));

            // Load ELF files (program and optionally interpreter)
            var i: usize = 0;
            while (true) : (i += 1) {
                if (i >= 2) {
                    errx("too many ELF interpreters", null);
                }
                const ehdr = &ehdrs[i];

                // Open file
                const fd = posix.openZ(current_file, .{}, 0) catch {
                    errx("can't open", current_file);
                };

                // Read ELF header
                var ehdr_bytes: [@sizeOf(elf.Elf64_Ehdr)]u8 = undefined;
                if (utils.readAll(fd, &ehdr_bytes, @sizeOf(elf.Elf64_Ehdr)) != @sizeOf(elf.Elf64_Ehdr)) {
                    errx("can't read ELF header", current_file);
                }
                ehdr.* = @bitCast(ehdr_bytes);

                if (!checkEhdr(ehdr)) {
                    errx("bogus or incompatible ELF header", current_file);
                }

                // Read program headers
                const MAX_PHNUM = 16;
                if (ehdr.e_phnum > MAX_PHNUM) {
                    errx("too many program headers", current_file);
                }
                const phdr_size = @as(usize, ehdr.e_phnum) * @sizeOf(elf.Elf64_Phdr);
                var phdr_buf: [MAX_PHNUM * @sizeOf(elf.Elf64_Phdr)]u8 align(@alignOf(elf.Elf64_Phdr)) = undefined;

                posix.lseek_SET(fd, ehdr.e_phoff) catch {
                    errx("can't lseek to program header", current_file);
                };
                if (utils.readAll(fd, &phdr_buf, phdr_size) != phdr_size) {
                    errx("can't read program header", current_file);
                }

                const phdr: [*]const elf.Elf64_Phdr = @ptrCast(@alignCast(&phdr_buf));

                // Load ELF
                base[i] = loadelfAnon(fd, ehdr, phdr) catch {
                    errx("can't load ELF", current_file);
                };

                // Calculate entry point
                entry[i] = ehdr.e_entry;
                if (ehdr.e_type == .DYN) {
                    entry[i] += base[i];
                }

                // If we just loaded the interpreter, we're done
                if (elf_interp != null and @intFromPtr(current_file) == @intFromPtr(elf_interp.?)) {
                    posix.close(fd);
                    break;
                }

                // Look for PT_INTERP
                for (phdr[0..ehdr.e_phnum]) |ph| {
                    if (ph.p_type != elf.PT_INTERP) continue;

                    // Read interpreter path
                    if (ph.p_filesz >= PATH_MAX) {
                        errx("interpreter path too long", null);
                    }
                    var interp_buf: [PATH_MAX]u8 = undefined;
                    posix.lseek_SET(fd, ph.p_offset) catch {
                        errx("can't lseek interp segment", null);
                    };

                    const interp_size = ph.p_filesz;
                    if (utils.readAll(fd, &interp_buf, interp_size) != interp_size) {
                        errx("can't read interp segment", null);
                    }
                    interp_buf[interp_size] = 0;

                    @memmove(@as([*]u8, @ptrCast(&static_interp)), interp_buf[0..(interp_size + 1)]);

                    elf_interp = @ptrCast(&static_interp);
                    print("elf_interp: {s}\n", .{elf_interp.?});
                    current_file = elf_interp.?;
                }

                posix.close(fd);

                // If no interpreter, we're done
                if (elf_interp == null) {
                    break;
                }
            }

            // Modify auxiliary vector
            while (av[0].a_type != elf.AT_NULL) : (av += 1) {
                switch (av[0].a_type) {
                    elf.AT_PHDR => {
                        av[0].a_un.a_val = base[Z_PROG] + ehdrs[Z_PROG].e_phoff;
                    },
                    elf.AT_PHNUM => {
                        av[0].a_un.a_val = ehdrs[Z_PROG].e_phnum;
                    },
                    elf.AT_PHENT => {
                        av[0].a_un.a_val = ehdrs[Z_PROG].e_phentsize;
                    },
                    elf.AT_ENTRY => {
                        // Hijack entry point!
                        av[0].a_un.a_val = @intFromPtr(&Self.z_fdl_entry);
                    },
                    elf.AT_EXECFN => {
                        av[0].a_un.a_val = @intFromPtr(new_argv[1]);
                    },
                    elf.AT_BASE => {
                        if (elf_interp != null) {
                            av[0].a_un.a_val = base[Z_INTERP];
                        }
                    },
                    else => {},
                }
            }

            if (elf_interp != null) {
                interp_base = base[Z_INTERP];
            }

            print("Calling trampo...file: {s}, interp: {s}\n", .{
                if (current_file[0] != 0) current_file else "(null)",
                if (elf_interp) |ei| ei else @as([*:0]const u8, "(null)"),
            });

            // Jump to dynamic loader (or program entry if static)
            const target_entry = if (elf_interp != null) entry[Z_INTERP] else entry[Z_PROG];
            trampo(target_entry, sp);

            // Should not reach
            linux.exit(0);
        }

        // z_start: Program entry point
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

// Trampoline to dynamic loader
pub fn trampo(entry: usize, sp: [*]usize) noreturn {
    asm volatile (
        \\mov %[sp], %%rsp
        \\jmp *%[entry]
        :
        : [entry] "r" (entry),
          [sp] "r" (@intFromPtr(sp)),
    );
    while (true) {}
}
