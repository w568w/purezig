const loader = @import("loader.zig");
const syscalls = @import("syscalls.zig");
const utils = @import("utils.zig");
const fdl = @import("fdl_resolve.zig");

fn appMain(_: c_int, _: [*][*:0]u8) c_int {
    var argv = [_][*:0]const u8{ "/bin/sleep", "0" };
    LoaderImpl.execElf("/bin/sleep", 2, @ptrCast(&argv));
    return 1;
}

fn fdlMain(ctx: *fdl.Context) void {
    const libc = ctx.dlopen(null, fdl.RTLD_NOW).?;
    const example = ctx.dlopen("./zig-out/lib/libexample.so", fdl.RTLD_NOW).?;

    // Call functions from our custom .so
    const add = ctx.dlsym(example, "add", *const fn (c_int, c_int) callconv(.c) c_int).?;
    const greet = ctx.dlsym(example, "greet", *const fn ([*:0]const u8) callconv(.c) void).?;
    const factorial = ctx.dlsym(example, "factorial", *const fn (c_int) callconv(.c) c_int).?;

    // Call libc functions
    const printf = ctx.dlsym(libc, "printf", *const fn ([*:0]const u8, ...) callconv(.c) c_int).?;
    const fflush = ctx.dlsym(libc, "fflush", *const fn (?*anyopaque) callconv(.c) c_int).?;

    // Demo
    _ = printf("add(3, 4) = %d\n", add(3, 4));
    _ = printf("factorial(5) = %d\n", factorial(5));
    greet("World");
    _ = fflush(null);
}

const LoaderImpl = loader.Loader(appMain, fdlMain);

pub fn panic(_: []const u8, _: ?*@import("std").builtin.StackTrace, _: ?usize) noreturn {
    syscalls.exit(1);
}

comptime {
    _ = LoaderImpl.z_start;
    _ = utils.memset;
}
