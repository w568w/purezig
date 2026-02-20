# Purezig

A freestanding & *fully*-static Zig binary that can call foreign functions via `dlopen`/`dlsym` without linking to libc.

## 1. How it works

I stole the idea from [this repo](https://github.com/Caesurus/foreign-dlopen) (which is written in C) and reimplemented it in Zig. The basic idea is:

1. Find a dynamic ELF binary on the system (e.g. `/bin/ls`, `/bin/sleep`, etc) that is linked against `libc.so`.
2. Load the ELF binary into memory manually (using `mmap` and reading the file).
3. Hijack the entry point of the ELF binary to jump back into our own code after the dynamic linker has initialized.
4. Make ld.so load it, which initializes the dynamic linker and loads `libc.so` into our process.
5. We get back control, locate the `dlopen` and `dlsym` symbols from `/proc/self/maps` by parsing libc's hash table.
6. Now we can call `dlopen`/`dlsym`!

Read [`example/src/simple.zig`](example/src/simple.zig) for a minimal example.

## 2. Limitations

- Linux x86_64 only (Possible to extend to other architectures, but not implemented yet)
- Requires a dynamic ELF binary on the system

## 3. Usage

### 3.1 As a dependency

Add `foreign_dlopen` to your `build.zig.zon` by running:

```bash
zig fetch --save git+https://github.com/w568w/purezig.git
```

Or add it manually:

```zig
.dependencies = .{
    // From git:
    .foreign_dlopen = .{
        .url = "git+https://github.com/w568w/purezig.git#<commit-hash>",
        .hash = "...",
    },
    // Or from a local path:
    .foreign_dlopen = .{ .path = "../path/to/purezig" },
},
```

In your `build.zig`, import the dependency and use the provided `configureExe` helper:

```zig
const std = @import("std");
const foreign_dlopen = @import("foreign_dlopen");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const dep = b.dependency("foreign_dlopen", .{});
    const fdl_mod = dep.module("foreign_dlopen");

    const exe = b.addExecutable(.{
        .name = "my_app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            // 1. Use target triple x86_64-linux-none
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .abi = .none,
            }),
            .optimize = optimize,
            .red_zone = false,
            .stack_protector = false,
            .stack_check = false,
            .unwind_tables = .none,
            .link_libc = false,
            // 2. Import the foreign_dlopen module
            .imports = &.{.{ .name = "foreign_dlopen", .module = fdl_mod }},
        }),
        // 3. Self-hosted compiler has some bugs and builds broken executables atm, so we need to use llvm to build the final binary.
        .use_llvm = true,
    });
    // 4. Configure the executable with the helper function, which sets the entry point.
    foreign_dlopen.configureExe(exe);
    b.installArtifact(exe);
}
```

Then in your source file:

```zig
const fdl = @import("foreign_dlopen");

// 4. Define the two entry points: appMain is the main function of our application, and fdlMain is called by the hijacked ELF binary after the dynamic linker has initialized.
fn appMain(_: c_int, _: [*][*:0]u8) c_int {
    // Pick any dynamically-linked ELF on the system as a "host" binary.
    // Its dynamic linker will be loaded, giving us access to dlopen/dlsym.
    Impl.execElf("/bin/sleep", &.{ "/bin/sleep", "0" });
    return 1; // <- This should never be reached.
}

fn fdlMain(ctx: *fdl.Context) void {
    // Now we have a working dlopen/dlsym!
    const libc = ctx.dlopen(null, fdl.RTLD_NOW).?;
    const puts = ctx.dlsym(libc, "puts", *const fn ([*:0]const u8) callconv(.c) c_int).?;
    _ = puts("Hello from a static binary!");
}

// 1. Declare the entry points with fdl.Entry, which sets up the necessary boilerplate to jump into our code after the dynamic linker has initialized.
const Impl = fdl.Entry(appMain, fdlMain);
// 2. _start is required when .os_tag = .linux, although it is not actually used in our scenario.
pub const _start = Impl._start;
// 3. Declare the panic handler.
pub const panic = Impl.panic;
```

### 3.2 Run the example

A complete working example is in the [`example/`](example/) directory:

```bash
cd example
zig build simple    # loads a custom .so and calls its functions
zig build run       # resolves libc symbols (puts, printf, strlen, getpid)
```

## 4. Requirements

- Zig 0.15+
