const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    // Freestanding target (uses Linux syscalls directly)
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });

    // Main demo
    const exe = addDemo(b, target, optimize, "src/main.zig", "foreign_dlopen_demo");
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the demo");
    run_step.dependOn(&run_cmd.step);

    // Simple demo (minimal example)
    const simple_exe = addDemo(b, target, optimize, "src/simple_main.zig", "simple_demo");
    b.installArtifact(simple_exe);

    const simple_run = b.addRunArtifact(simple_exe);
    simple_run.step.dependOn(b.getInstallStep());

    const simple_step = b.step("simple", "Run the minimal demo");
    simple_step.dependOn(&simple_run.step);
}

fn addDemo(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    src: []const u8,
    name: []const u8,
) *std.Build.Step.Compile {
    const root_module = b.createModule(.{
        .root_source_file = b.path(src),
        .target = target,
        .optimize = optimize,
        .red_zone = false,
        .stack_protector = false,
        .stack_check = false,
        .unwind_tables = .none,
        .link_libc = false,
    });

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = root_module,
        .use_llvm = true,
    });

    exe.entry = .{ .symbol_name = "z_start" };
    exe.pie = true;
    exe.image_base = 0x66660000;

    return exe;
}
