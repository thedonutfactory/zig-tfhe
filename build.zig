const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    // Create a module for the main source
    const main_module = b.addModule("main", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });

    // Create the main executable
    const exe = b.addExecutable(.{
        .name = "zig-tfhe",
        .root_module = main_module,
    });

    exe.linkLibC();
    exe.linkSystemLibrary("m");

    b.installArtifact(exe);

    // Create run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Create run step
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Create test executable
    const test_exe = b.addTest(.{
        .root_module = main_module,
    });

    test_exe.linkLibC();
    test_exe.linkSystemLibrary("m");

    const test_run = b.addRunArtifact(test_exe);

    // Create test step
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}