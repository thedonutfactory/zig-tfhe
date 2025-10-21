const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    // Create a module for the main source
    const tfhe_module = b.addModule("tfhe", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });

    // Create test executable
    const test_exe = b.addTest(.{
        .root_module = tfhe_module,
    });

    test_exe.linkLibC();
    test_exe.linkSystemLibrary("m");

    const test_run = b.addRunArtifact(test_exe);

    // Create test step
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    // Create example module and executable
    const example_module = b.addModule("add_two_numbers_example", .{
        .root_source_file = b.path("examples/add_two_numbers.zig"),
        .target = target,
    });

    // Add the tfhe module as a dependency for the example
    example_module.addImport("tfhe", tfhe_module);

    const example_exe = b.addExecutable(.{
        .name = "add_two_numbers",
        .root_module = example_module,
    });

    example_exe.linkLibC();
    example_exe.linkSystemLibrary("m");

    b.installArtifact(example_exe);

    // Create example run command
    const example_run_cmd = b.addRunArtifact(example_exe);
    example_run_cmd.step.dependOn(b.getInstallStep());

    // Create example run step
    const example_run_step = b.step("example", "Run the add_two_numbers example");
    example_run_step.dependOn(&example_run_cmd.step);
}
