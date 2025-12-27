// ELF Loader - loads ELF executables and their interpreters
// Hijacks AT_ENTRY to regain control after dynamic linker initialization

const std = @import("std");
const elf = std.elf;
const syscalls = @import("syscalls.zig");
const utils = @import("utils.zig");
const printf = @import("printf.zig");
const fdl_resolve = @import("fdl_resolve.zig");

const Z_PROG: usize = 0;
const Z_INTERP: usize = 1;

// Check ELF header validity
fn checkEhdr(ehdr: *const elf.Elf64_Ehdr) bool {
    return std.mem.startsWith(u8, &ehdr.e_ident, elf.MAGIC) and
        ehdr.e_ident[elf.EI_CLASS] == elf.ELFCLASS64 and
        ehdr.e_ident[elf.EI_VERSION] == 1 and
        (ehdr.e_type == .EXEC or ehdr.e_type == .DYN);
}

// Load ELF into anonymous memory
fn loadelfAnon(fd: c_int, ehdr: *const elf.Elf64_Ehdr, phdr: [*]const elf.Elf64_Phdr) ?usize {
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

    // For dynamic ELF let the kernel choose the address
    const hint: ?*anyopaque = if (dyn) null else @ptrFromInt(minva);
    var flags: c_int = if (dyn) 0 else syscalls.MAP_FIXED;
    flags |= syscalls.MAP_PRIVATE | syscalls.MAP_ANONYMOUS;

    // Reserve address space
    const base_result = syscalls.mmap(hint, maxva - minva, syscalls.PROT_NONE, flags, -1, 0);
    if (base_result == syscalls.MAP_FAILED) {
        return null;
    }
    const base: [*]u8 = @ptrFromInt(base_result);

    // Map each segment (MAP_FIXED will replace portions of the PROT_NONE reservation)
    for (phdr[0..ehdr.e_phnum]) |p| {
        if (p.p_type != elf.PT_LOAD) continue;

        const off = p.p_vaddr & utils.PAGE_MASK;
        const start_addr: usize = if (dyn) @intFromPtr(base) else 0;
        const seg_start = start_addr + utils.truncPg(p.p_vaddr);
        const sz = utils.roundPg(p.p_memsz + off);

        // Map segment with read/write for loading
        const map_flags = syscalls.MAP_FIXED | syscalls.MAP_ANONYMOUS | syscalls.MAP_PRIVATE;
        const mapped = syscalls.mmap(
            @ptrFromInt(seg_start),
            sz,
            syscalls.PROT_READ | syscalls.PROT_WRITE,
            map_flags,
            -1,
            0,
        );
        if (mapped == syscalls.MAP_FAILED) {
            _ = syscalls.munmap(@ptrCast(base), maxva - minva);
            return null;
        }

        // Seek and read segment content
        if (syscalls.lseek(fd, @intCast(p.p_offset), syscalls.SEEK_SET) < 0) {
            _ = syscalls.munmap(@ptrCast(base), maxva - minva);
            return null;
        }

        const dest: [*]u8 = @ptrFromInt(mapped + off);
        if (utils.readAll(fd, dest, p.p_filesz) != p.p_filesz) {
            _ = syscalls.munmap(@ptrCast(base), maxva - minva);
            return null;
        }

        // Set final protections
        if (syscalls.mprotect(@ptrFromInt(mapped), sz, utils.pflags(p.p_flags)) < 0) {
            _ = syscalls.munmap(@ptrCast(base), maxva - minva);
            return null;
        }
    }

    return @intFromPtr(base);
}

// Error exit
fn errx(eval: c_int, msg: [*:0]const u8, arg: ?[*:0]const u8) noreturn {
    printf.fputs("error: ", 2);
    if (arg) |a| {
        printf.printf(msg, &[_]printf.FormatArg{printf.FormatArg.fromStr(a)});
    } else {
        printf.fputs(msg, 2);
    }
    printf.fputs("\n", 2);
    syscalls.exit(eval);
}

// Generic Loader configured by main.zig
pub fn Loader(
    comptime app_main: fn (c_int, [*][*:0]u8) c_int,
    comptime fdl_main: fn (*fdl_resolve.Context) void,
) type {
    return struct {
        const Self = @This();

        var entry_sp: ?[*]usize = null;
        var interp_base: usize = 0;

        // Entry point called from z_start
        pub export fn z_entry(sp: [*]usize) callconv(.c) void {
            entry_sp = sp;
            const argc: usize = sp[0];
            const argv: [*][*:0]u8 = @ptrCast(sp + 1);
            _ = app_main(@intCast(argc), argv);
        }

        // Called after dynamic loader initializes
        pub export fn fdl_entry_impl() callconv(.c) void {
            printf.puts("Loader is in memory... Start parsing logic");

            var ctx = fdl_resolve.init(interp_base) catch {
                syscalls.exit(1);
            };
            fdl_main(&ctx);

            syscalls.exit(0);
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
                    errx(1, "too many ELF interpreters", null);
                }
                const ehdr = &ehdrs[i];

                // Open file
                const fd = syscalls.open(current_file, syscalls.O_RDONLY);
                if (fd < 0) {
                    errx(1, "can't open %s", current_file);
                }

                // Read ELF header
                var ehdr_bytes: [@sizeOf(elf.Elf64_Ehdr)]u8 = undefined;
                if (utils.readAll(fd, &ehdr_bytes, @sizeOf(elf.Elf64_Ehdr)) != @sizeOf(elf.Elf64_Ehdr)) {
                    errx(1, "can't read ELF header %s", current_file);
                }
                ehdr.* = @bitCast(ehdr_bytes);

                if (!checkEhdr(ehdr)) {
                    errx(1, "bogus or incompatible ELF header %s", current_file);
                }

                // Read program headers
                const MAX_PHNUM = 16;
                if (ehdr.e_phnum > MAX_PHNUM) {
                    errx(1, "too many program headers in %s", current_file);
                }
                const phdr_size = @as(usize, ehdr.e_phnum) * @sizeOf(elf.Elf64_Phdr);
                var phdr_buf: [MAX_PHNUM * @sizeOf(elf.Elf64_Phdr)]u8 align(@alignOf(elf.Elf64_Phdr)) = undefined;

                if (syscalls.lseek(fd, @intCast(ehdr.e_phoff), syscalls.SEEK_SET) < 0) {
                    errx(1, "can't lseek to program header %s", current_file);
                }
                if (utils.readAll(fd, &phdr_buf, phdr_size) != phdr_size) {
                    errx(1, "can't read program header %s", current_file);
                }

                const phdr: [*]const elf.Elf64_Phdr = @ptrCast(@alignCast(&phdr_buf));

                // Load ELF
                base[i] = loadelfAnon(fd, ehdr, phdr) orelse {
                    errx(1, "can't load ELF %s", current_file);
                };

                // Calculate entry point
                entry[i] = ehdr.e_entry;
                if (ehdr.e_type == .DYN) {
                    entry[i] += base[i];
                }

                // If we just loaded the interpreter, we're done
                if (elf_interp != null and @intFromPtr(current_file) == @intFromPtr(elf_interp.?)) {
                    _ = syscalls.close(fd);
                    break;
                }

                // Look for PT_INTERP
                for (phdr[0..ehdr.e_phnum]) |ph| {
                    if (ph.p_type != elf.PT_INTERP) continue;

                    // Read interpreter path
                    if (ph.p_filesz >= PATH_MAX) {
                        errx(1, "interpreter path too long", null);
                    }
                    var interp_buf: [PATH_MAX]u8 = undefined;
                    if (syscalls.lseek(fd, @intCast(ph.p_offset), syscalls.SEEK_SET) < 0) {
                        errx(1, "can't lseek interp segment", null);
                    }

                    const interp_size = ph.p_filesz;
                    if (utils.readAll(fd, &interp_buf, interp_size) != interp_size) {
                        errx(1, "can't read interp segment", null);
                    }
                    interp_buf[interp_size] = 0;

                    @memmove(@as([*]u8, @ptrCast(&static_interp)), interp_buf[0..(interp_size + 1)]);

                    elf_interp = @ptrCast(&static_interp);
                    printf.printf("elf_interp: %s\n", &[_]printf.FormatArg{
                        printf.FormatArg.fromStr(elf_interp.?),
                    });
                    current_file = elf_interp.?;
                }

                _ = syscalls.close(fd);

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

            printf.printf("Calling trampo...file: %s, interp: %s\n", &[_]printf.FormatArg{
                printf.FormatArg.fromStr(if (current_file[0] != 0) current_file else "(null)"),
                printf.FormatArg.fromStr(if (elf_interp) |ei| ei else "(null)"),
            });

            // Jump to dynamic loader (or program entry if static)
            const target_entry = if (elf_interp != null) entry[Z_INTERP] else entry[Z_PROG];
            trampo(target_entry, sp);

            // Should not reach
            syscalls.exit(0);
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
