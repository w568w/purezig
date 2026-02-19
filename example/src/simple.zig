const fdl = @import("foreign_dlopen");

fn appMain(_: c_int, _: [*][*:0]u8) c_int {
    Impl.execElf("/bin/sleep", &.{ "/bin/sleep", "0" });
    return 1;
}

fn fdlMain(ctx: *fdl.Context) void {
    const libc = ctx.dlopen(null, fdl.RTLD_NOW).?;
    const example = ctx.dlopen("./zig-out/lib/libexample.so", fdl.RTLD_NOW).?;

    const add = ctx.dlsym(example, "add", *const fn (c_int, c_int) callconv(.c) c_int).?;
    const greet = ctx.dlsym(example, "greet", *const fn ([*:0]const u8) callconv(.c) void).?;
    const factorial = ctx.dlsym(example, "factorial", *const fn (c_int) callconv(.c) c_int).?;

    const printf = ctx.dlsym(libc, "printf", *const fn ([*:0]const u8, ...) callconv(.c) c_int).?;
    const fflush = ctx.dlsym(libc, "fflush", *const fn (?*anyopaque) callconv(.c) c_int).?;

    _ = printf("add(3, 4) = %d\n", add(3, 4));
    _ = printf("factorial(5) = %d\n", factorial(5));
    greet("World");
    _ = fflush(null);
}

const Impl = fdl.Entry(appMain, fdlMain);
pub const _start = Impl._start;
pub const panic = Impl.panic;
