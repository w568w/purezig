// Foreign dlopen demo - main entry point
// Loads an ELF executable and hijacks its entry point to demonstrate
// dynamic symbol resolution from a statically-linked binary

const loader = @import("loader.zig");
const syscalls = @import("syscalls.zig");
const printf = @import("printf.zig");
const utils = @import("utils.zig");
const fdl = @import("fdl_resolve.zig");

const DL_APP_DEFAULT: [*:0]const u8 = "/bin/sleep";

// Main function called from z_entry
fn appMain(argc: c_int, argv: [*][*:0]u8) c_int {
    const msg = "appMain called\n";
    _ = syscalls.write(2, msg.ptr, msg.len);

    const app: [*:0]const u8 = if (argc > 1 and argv[1][0] != 0)
        argv[1]
    else
        DL_APP_DEFAULT;

    var targv = [_][*:0]const u8{ app, "x" };
    LoaderImpl.execElf(app, 2, @ptrCast(&targv));
    return 1;
}

// Called after dynamic linker initializes and symbols are resolved
fn fdlMain(ctx: *fdl.Context) void {
    printf.printf("dlopen=%p dlsym=%p\n", &[_]printf.FormatArg{
        printf.FormatArg.fromPtr(ctx.dlopen_ptr),
        printf.FormatArg.fromPtr(ctx.dlsym_ptr),
    });

    const handle = ctx.dlopen(null, fdl.RTLD_NOW) orelse return;
    printf.printf("handle: %p\n", &[_]printf.FormatArg{printf.FormatArg.fromPtr(handle)});

    if (ctx.dlsym(handle, "puts", *const fn ([*:0]const u8) callconv(.c) c_int)) |puts| {
        _ = puts("[libc puts] hello via foreign dlopen");
    }

    if (ctx.dlsym(handle, "printf", *const fn ([*:0]const u8, ...) callconv(.c) c_int)) |libc_printf| {
        _ = libc_printf("[libc printf] Number: %d, String: %s\n", @as(i32, 42), "test");
    }

    if (ctx.dlsym(handle, "strlen", *const fn ([*:0]const u8) callconv(.c) usize)) |strlen| {
        const test_str = "Hello, World!";
        const len = strlen(test_str);
        printf.printf("[libc strlen] Length of '%s' is %u\n", &[_]printf.FormatArg{
            printf.FormatArg.fromStr(test_str),
            printf.FormatArg.fromUint(len),
        });
    }

    if (ctx.dlsym(handle, "getpid", *const fn () callconv(.c) c_int)) |getpid| {
        const pid = getpid();
        printf.printf("[libc getpid] Process ID: %d\n", &[_]printf.FormatArg{
            printf.FormatArg.fromInt(pid),
        });
    }

    printf.puts("Done");
}

// Instantiate the Loader with our callbacks
const LoaderImpl = loader.Loader(appMain, fdlMain);

// Panic handler for freestanding environment
pub fn panic(_: []const u8, _: ?*@import("std").builtin.StackTrace, _: ?usize) noreturn {
    syscalls.exit(1);
}

// Ensure required symbols are exported
comptime {
    _ = LoaderImpl.z_start;
    _ = utils.memset;
}
