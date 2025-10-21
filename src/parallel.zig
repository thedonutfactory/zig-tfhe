//! Parallelization abstraction layer for zig-tfhe
//!
//! This module provides the `Railgun` trait that abstracts over different parallelization
//! backends. This allows the library to swap between different parallel
//! execution strategies without changing the core algorithm implementations.
//!
//! # Architecture
//!
//! The approach uses generics with a simple trait bound, making it zero-cost while still
//! allowing different implementations to be swapped at compile time or through configuration.

const std = @import("std");

// Import submodules
pub const rayon_impl = @import("parallel/rayon_impl.zig");

pub const RayonRailgun = rayon_impl.RayonRailgun;

/// Configuration for parallel execution.
pub const ParallelConfig = struct {
    /// Stack size per thread (in bytes).
    stack_size: ?usize,
    /// Number of threads (None = automatic).
    num_threads: ?usize,

    /// Create a default parallel configuration.
    pub fn default() ParallelConfig {
        return ParallelConfig{
            .stack_size = 8 * 1024 * 1024, // 8MB default for FHE operations
            .num_threads = null,
        };
    }
};

// Note: In Zig, we don't need a trait abstraction for this use case.
// The RayonRailgun struct provides the concrete implementation directly.

/// Global default parallelization backend (singleton).
///
/// This is used by default throughout the library unless explicitly overridden.
/// It uses a simple implementation with sensible defaults for FHE operations.
///
/// # Performance.
///
/// This singleton is implemented using a simple global variable for zero-cost access:.
/// - First call: Initializes the singleton (one-time cost).
/// - Subsequent calls: Simply returns a reference (zero overhead).
/// - Thread-safe without locks after initialization.
/// - No heap allocations after first call.
///
/// This design eliminates any overhead from repeatedly calling `default_railgun()`,.
/// making it suitable for use in hot paths and benchmarks.
var default_railgun_instance: ?RayonRailgun = null;

pub fn defaultRailgun() *const RayonRailgun {
    if (default_railgun_instance == null) {
        default_railgun_instance = RayonRailgun.default();
    }
    return &default_railgun_instance.?;
}

/// Create a custom Rayon-based parallelization backend.
pub fn rayonRailgun(config: ParallelConfig) RayonRailgun {
    return RayonRailgun.withCustomConfig(config);
}

// TESTS

test "par map" {
    const railgun = defaultRailgun();
    const input = [_]i32{ 1, 2, 3, 4, 5 };
    const result = railgun.parMap(i32, i32, &input, struct {
        fn call(x: *const i32) i32 {
            return x.* * 2;
        }
    }.call);

    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqual(@as(i32, 2), result[0]);
    try std.testing.expectEqual(@as(i32, 4), result[1]);
    try std.testing.expectEqual(@as(i32, 6), result[2]);
    try std.testing.expectEqual(@as(i32, 8), result[3]);
    try std.testing.expectEqual(@as(i32, 10), result[4]);
}

test "par map indexed" {
    const railgun = defaultRailgun();
    const input = [_]i32{ 10, 20, 30 };
    const result = railgun.parMapIndexed(i32, i32, &input, struct {
        fn call(i: usize, x: *const i32) i32 {
            return @as(i32, @intCast(i)) + x.*;
        }
    }.call);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqual(@as(i32, 10), result[0]);
    try std.testing.expectEqual(@as(i32, 21), result[1]);
    try std.testing.expectEqual(@as(i32, 32), result[2]);
}

test "with config" {
    const railgun = defaultRailgun();
    const config = ParallelConfig{
        .stack_size = 4 * 1024 * 1024,
        .num_threads = 2,
    };
    const result = railgun.withConfig(config, struct {
        fn call() i32 {
            // Simulate some work
            return 42;
        }
    }.call);
    try std.testing.expectEqual(@as(i32, 42), result);
}
