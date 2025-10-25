const std = @import("std");

pub fn build(b: *std.Build) void {
    // Default to native CPU with all features for best performance
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = null, // Use native architecture
            .os_tag = null, // Use native OS
            .abi = null, // Use native ABI
            .cpu_model = .native, // Use native CPU model (enables CPU-specific optimizations)
        },
    });

    // Default to ReleaseFast for optimal performance
    // TFHE is computationally intensive, so we want fast execution by default
    // Can still override with -Doptimize=Debug for debugging
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (-O flag)",
    ) orelse .ReleaseFast;

    // Create a module for the main source
    const main_module = b.addModule("main", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

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

    // Create example: add_two_numbers
    const add_two_numbers_module = b.addModule("add_two_numbers", .{
        .root_source_file = b.path("examples/add_two_numbers.zig"),
        .target = target,
        .optimize = optimize,
    });
    add_two_numbers_module.addImport("main", main_module);

    const add_two_numbers_exe = b.addExecutable(.{
        .name = "add_two_numbers",
        .root_module = add_two_numbers_module,
    });
    add_two_numbers_exe.linkLibC();
    add_two_numbers_exe.linkSystemLibrary("m");

    b.installArtifact(add_two_numbers_exe);

    const add_two_numbers_run = b.addRunArtifact(add_two_numbers_exe);
    add_two_numbers_run.step.dependOn(b.getInstallStep());

    const add_two_numbers_step = b.step("add_two_numbers", "Run the add_two_numbers example");
    add_two_numbers_step.dependOn(&add_two_numbers_run.step);
}
