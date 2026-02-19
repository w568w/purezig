const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("foreign_dlopen", .{
        .root_source_file = b.path("src/root.zig"),
    });
}

pub fn configureExe(exe: *std.Build.Step.Compile) void {
    exe.entry = .{ .symbol_name = "z_start" };
    exe.pie = true;
    exe.image_base = 0x66660000;
}
