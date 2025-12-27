const loader = @import("loader.zig");
const syscalls = @import("syscalls.zig");
const utils = @import("utils.zig");
const fdl = @import("fdl_resolve.zig");

// Bootstrap main: load /bin/sleep to initialize dynamic linker
fn appMain(_: c_int, _: [*][*:0]u8) c_int {
    var argv = [_][*:0]const u8{ "/bin/sleep", "0" };
    LoaderImpl.execElf("/bin/sleep", 2, @ptrCast(&argv));
    return 1;
}

// Core main: called after dynamic linker is ready
fn fdlMain(ctx: *fdl.Context) void {
    // Get handle to current process (libc already loaded)
    const handle = ctx.dlopen(null, fdl.RTLD_NOW) orelse return;

    // Resolve and call puts()
    const puts = ctx.dlsym(handle, "puts", *const fn ([*:0]const u8) callconv(.c) c_int) orelse return;
    _ = puts("Hello from foreign dlopen!");

    // Resolve and call printf()
    const printf = ctx.dlsym(handle, "printf", *const fn ([*:0]const u8, ...) callconv(.c) c_int) orelse return;
    _ = printf("The answer is: %d\n", @as(c_int, 42));
}

// Define loader implementation and initialize static variables.
// Note: MUST be called once and only once in the entire program!
const LoaderImpl = loader.Loader(appMain, fdlMain);

pub fn panic(_: []const u8, _: ?*@import("std").builtin.StackTrace, _: ?usize) noreturn {
    syscalls.exit(1);
}

comptime {
    _ = LoaderImpl.z_start;
    _ = utils.memset;
}
