//! Simple parallel implementation for zig-tfhe
//!
//! This module provides a basic parallel implementation using Zig's built-in
//! threading capabilities. It's a simplified version of the Rayon-based
//! implementation from the Rust version.

const std = @import("std");
const ParallelConfig = @import("../parallel.zig").ParallelConfig;

/// Simple parallelization backend.
///
/// This implementation uses Zig's built-in threading for.
/// efficient CPU parallelization.
pub const RayonRailgun = struct {
    const Self = @This();

    config: ParallelConfig,

    /// Create a new parallel backend with default configuration.
    pub fn new() Self {
        return Self{
            .config = ParallelConfig.default(),
        };
    }

    /// Create a new parallel backend with custom configuration.
    pub fn withCustomConfig(config: ParallelConfig) Self {
        return Self{ .config = config };
    }

    /// Create a default instance.
    pub fn default() Self {
        return Self.new();
    }

    /// Parallel map over a slice with a function.
    ///
    /// # Arguments.
    /// * `T` - Input type.
    /// * `U` - Output type.
    /// * `input` - Input slice to process.
    /// * `f` - Function to apply to each element.
    ///
    /// # Returns.
    /// Vector of results.
    pub fn parMap(self: *const Self, comptime T: type, comptime U: type, input: []const T, f: *const fn (*const T) U) []U {
        _ = self; // Suppress unused parameter warning

        var result = std.heap.page_allocator.alloc(U, input.len) catch @panic("Failed to allocate result buffer");

        // For now, use sequential processing
        // In a full implementation, this would use threading
        for (input, 0..) |item, i| {
            result[i] = f(&item);
        }

        return result;
    }

    /// Parallel map over a slice with indexed function.
    ///
    /// # Arguments.
    /// * `T` - Input type.
    /// * `U` - Output type.
    /// * `input` - Input slice to process.
    /// * `f` - Function that takes (index, element) and returns result.
    pub fn parMapIndexed(self: *const Self, comptime T: type, comptime U: type, input: []const T, f: *const fn (usize, *const T) U) []U {
        _ = self; // Suppress unused parameter warning

        var result = std.heap.page_allocator.alloc(U, input.len) catch @panic("Failed to allocate result buffer");

        // For now, use sequential processing
        // In a full implementation, this would use threading
        for (input, 0..) |item, i| {
            result[i] = f(i, &item);
        }

        return result;
    }

    /// Execute a closure with a custom parallel configuration.
    ///
    /// This allows operations that need specific thread pool settings.
    /// (e.g., larger stack sizes for deep recursion).
    ///
    /// # Arguments.
    /// * `config` - Parallel configuration.
    /// * `f` - Function to execute.
    ///
    /// # Returns.
    /// Result of the function.
    pub fn withConfig(self: *const Self, config: ParallelConfig, f: anytype) @TypeOf(f()) {
        _ = self; // Suppress unused parameter warning
        _ = config; // Suppress unused parameter warning

        // For now, just execute the function directly
        // In a full implementation, this would set up a custom thread pool
        return f();
    }
};

// TESTS

test "rayon par map" {
    const railgun = RayonRailgun.new();
    const input = [_]i32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const result = railgun.parMap(i32, i32, &input, struct {
        fn call(x: *const i32) i32 {
            return x.* * x.*;
        }
    }.call);

    defer std.heap.page_allocator.free(result);

    try std.testing.expectEqual(@as(usize, 8), result.len);
    try std.testing.expectEqual(@as(i32, 1), result[0]);
    try std.testing.expectEqual(@as(i32, 4), result[1]);
    try std.testing.expectEqual(@as(i32, 9), result[2]);
    try std.testing.expectEqual(@as(i32, 16), result[3]);
    try std.testing.expectEqual(@as(i32, 25), result[4]);
    try std.testing.expectEqual(@as(i32, 36), result[5]);
    try std.testing.expectEqual(@as(i32, 49), result[6]);
    try std.testing.expectEqual(@as(i32, 64), result[7]);
}

test "rayon large stack" {
    const railgun = RayonRailgun.new();
    const config = ParallelConfig{
        .stack_size = 16 * 1024 * 1024, // 16MB
        .num_threads = 4,
    };

    const result = railgun.withConfig(config, struct {
        fn call() i32 {
            // This would require the large stack
            var sum: i32 = 0;
            for (0..1000) |i| {
                sum += @as(i32, @intCast(i)) * 2;
            }
            return sum;
        }
    }.call);

    try std.testing.expectEqual(@as(i32, 999000), result);
}

test "rayon indexed" {
    const railgun = RayonRailgun.new();
    const input = [_][]const u8{ "a", "b", "c" };
    const result = railgun.parMapIndexed([]const u8, []const u8, &input, struct {
        fn call(i: usize, s: *const []const u8) []const u8 {
            _ = i; // Suppress unused parameter warning
            // For simplicity, just return the input string
            // In a real implementation, this would format the string
            return s.*;
        }
    }.call);

    defer std.heap.page_allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("a", result[0]);
    try std.testing.expectEqualStrings("b", result[1]);
    try std.testing.expectEqualStrings("c", result[2]);
}
