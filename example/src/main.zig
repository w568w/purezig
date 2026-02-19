const std = @import("std");
const fdl = @import("foreign_dlopen");

const print = std.debug.print;

const DL_APP_DEFAULT: [*:0]const u8 = "/bin/sleep";

fn appMain(argc: c_int, argv: [*][*:0]u8) c_int {
    print("appMain called\n", .{});

    const app: [*:0]const u8 = if (argc > 1 and argv[1][0] != 0)
        argv[1]
    else
        DL_APP_DEFAULT;

    Impl.execElf(app, &.{ app, "x" });
    return 1;
}

fn fdlMain(ctx: *fdl.Context) void {
    print("dlopen=0x{x} dlsym=0x{x}\n", .{ @intFromPtr(ctx.dlopen_ptr), @intFromPtr(ctx.dlsym_ptr) });

    const handle = ctx.dlopen(null, fdl.RTLD_NOW) orelse return;
    print("handle: 0x{x}\n", .{@intFromPtr(handle)});

    if (ctx.dlsym(handle, "puts", *const fn ([*:0]const u8) callconv(.c) c_int)) |puts| {
        _ = puts("[libc puts] hello via foreign dlopen");
    }

    if (ctx.dlsym(handle, "printf", *const fn ([*:0]const u8, ...) callconv(.c) c_int)) |libc_printf| {
        _ = libc_printf("[libc printf] Number: %d, String: %s\n", @as(i32, 42), "test");
    }

    if (ctx.dlsym(handle, "strlen", *const fn ([*:0]const u8) callconv(.c) usize)) |strlen| {
        const test_str = "Hello, World!";
        const len = strlen(test_str);
        print("[libc strlen] Length of '{s}' is {d}\n", .{ test_str, len });
    }

    if (ctx.dlsym(handle, "getpid", *const fn () callconv(.c) c_int)) |getpid| {
        const pid = getpid();
        print("[libc getpid] Process ID: {d}\n", .{pid});
    }

    print("Done\n", .{});
}

const Impl = fdl.Entry(appMain, fdlMain);
pub const _start = Impl._start;
pub const panic = Impl.panic;
