const std = @import("std");
const foreign_dlopen = @import("foreign_dlopen");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const dep = b.dependency("foreign_dlopen", .{});
    const fdl_mod = dep.module("foreign_dlopen");

    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .none,
    });

    // Main demo
    const exe = addDemo(b, target, optimize, fdl_mod, "src/main.zig", "demo");
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the main demo");
    run_step.dependOn(&run_cmd.step);

    // Simple demo
    const simple_exe = addDemo(b, target, optimize, fdl_mod, "src/simple.zig", "simple_demo");
    b.installArtifact(simple_exe);

    const simple_run = b.addRunArtifact(simple_exe);
    simple_run.step.dependOn(b.getInstallStep());

    const simple_step = b.step("simple", "Run the simple demo");
    simple_step.dependOn(&simple_run.step);

    // Example shared library (C)
    const example_lib = b.addLibrary(.{
        .name = "example",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .abi = .gnu,
            }),
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    example_lib.root_module.addCSourceFile(.{ .file = b.path("lib/example.c") });
    b.installArtifact(example_lib);

    simple_step.dependOn(&example_lib.step);
}

fn addDemo(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    fdl_mod: *std.Build.Module,
    src: []const u8,
    name: []const u8,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
            .red_zone = false,
            .stack_protector = false,
            .stack_check = false,
            .unwind_tables = .none,
            .link_libc = false,
            .imports = &.{.{ .name = "foreign_dlopen", .module = fdl_mod }},
        }),
        .use_llvm = true,
    });
    foreign_dlopen.configureExe(exe);
    return exe;
}
