//! Utility functions for TFHE operations.
//!
//! This module provides utility functions for converting between different
//! representations, generating noise, and other common operations used
//! throughout the TFHE library.

const std = @import("std");
const params = @import("params.zig");
const tlwe = @import("tlwe.zig");

/// Global atomic counter for generating unique seeds.
var global_seed_counter = std.atomic.Value(u64).init(1);

/// Generate a unique random seed for RNG initialization.
/// Uses atomic counter, timestamp, and stack address for maximum uniqueness.
pub fn getUniqueSeed() u64 {
    const counter = global_seed_counter.fetchAdd(1, .monotonic);
    const timestamp = @as(u64, @intCast(std.time.nanoTimestamp()));
    var stack_var: u8 = 0;
    const addr = @intFromPtr(&stack_var);
    return (counter ^ timestamp) +% addr;
}

/// Type alias for Ciphertext (TLWE Level 0).
pub const Ciphertext = tlwe.TLWELv0;

/// Convert a floating-point number to torus representation.
pub fn f64ToTorus(d: f64) params.Torus {
    const normalized = @mod(d, 1.0);
    const torus = normalized * @as(f64, @floatFromInt(std.math.pow(u64, 2, params.TORUS_SIZE)));
    const clamped = @max(0.0, @min(torus, @as(f64, @floatFromInt(std.math.maxInt(params.Torus)))));
    return @as(params.Torus, @intFromFloat(clamped));
}

/// Convert a torus value to floating-point representation.
pub fn torusToF64(t: params.Torus) f64 {
    return @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(std.math.pow(u64, 2, params.TORUS_SIZE)));
}

/// Convert a vector of floating-point numbers to torus representation.
pub fn f64ToTorusVec(allocator: std.mem.Allocator, d: []const f64) ![]params.Torus {
    var result = try allocator.alloc(params.Torus, d.len);
    for (d, 0..) |val, i| {
        result[i] = f64ToTorus(val);
    }
    return result;
}

/// Simple normal distribution using Box-Muller transform.
pub const NormalDist = struct {
    mean: f64,
    stddev: f64,
    has_spare: bool = false,
    spare: f64 = 0.0,

    pub fn init(mean: f64, stddev: f64) NormalDist {
        return NormalDist{
            .mean = mean,
            .stddev = stddev,
            .has_spare = false,
            .spare = 0.0,
        };
    }

    pub fn next(self: *NormalDist, rng: anytype) f64 {
        if (self.has_spare) {
            self.has_spare = false;
            return self.spare * self.stddev + self.mean;
        }

        // Box-Muller transform
        const uniform1 = rng.float(f64);
        const uniform2 = rng.float(f64);
        const mag = self.stddev * @sqrt(-2.0 * @log(uniform1));
        const z0 = mag * @cos(2.0 * std.math.pi * uniform2);
        const z1 = mag * @sin(2.0 * std.math.pi * uniform2);

        self.has_spare = true;
        self.spare = z1;
        return z0 + self.mean;
    }
};

/// Generate gaussian noise in torus representation.
pub fn gaussianTorus(
    mu: params.Torus,
    normal_distr: *NormalDist,
    rng: anytype,
) params.Torus {
    const sample = normal_distr.next(rng);
    return f64ToTorus(sample) +% mu;
}

/// Generate gaussian noise from floating-point mean.
pub fn gaussianF64(
    mu: f64,
    normal_distr: *NormalDist,
    rng: anytype,
) params.Torus {
    const mu_torus = f64ToTorus(mu);
    return gaussianTorus(mu_torus, normal_distr, rng);
}

/// Generate gaussian noise for a vector of floating-point means.
pub fn gaussianF64Vec(
    allocator: std.mem.Allocator,
    mu: []const f64,
    normal_distr: *NormalDist,
    rng: anytype,
) ![]params.Torus {
    var result = try allocator.alloc(params.Torus, mu.len);
    for (mu, 0..) |val, i| {
        result[i] = gaussianTorus(f64ToTorus(val), normal_distr, rng);
    }
    return result;
}

/// Generate gaussian noise for a vector of torus means.
pub fn gaussianTorusVec(
    allocator: std.mem.Allocator,
    mu: []const params.Torus,
    normal_distr: *NormalDist,
    rng: anytype,
) ![]params.Torus {
    var result = try allocator.alloc(params.Torus, mu.len);
    for (mu, 0..) |val, i| {
        result[i] = gaussianTorus(val, normal_distr, rng);
    }
    return result;
}

test "gaussian 32bit" {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(42);
    var normal = NormalDist.init(0.0, 0.1);

    const torus = try gaussianTorusVec(allocator, &[_]params.Torus{12}, &normal, rng.random());
    defer allocator.free(torus);
    try std.testing.expect(torus.len == 1);

    const torus2 = try gaussianTorusVec(allocator, &[_]params.Torus{ 12, 11 }, &normal, rng.random());
    defer allocator.free(torus2);
    try std.testing.expect(torus2.len == 2);
}

test "comprehensive f64 to torus conversions" {
    // Test various f64 to torus conversions
    const test_values = [_]f64{ 0.0, 0.125, 0.25, 0.5, 0.75, 1.0, -0.125, -0.25, -0.5 };

    for (test_values) |val| {
        const torus = f64ToTorus(val);
        const back = torusToF64(torus);
        _ = back;
    }

    // Test specific critical values
    const critical_values = [_]f64{ 0.0, 0.125, -0.125, 0.25, -0.25 };
    for (critical_values) |val| {
        const torus = f64ToTorus(val);
        const back = torusToF64(torus);
        _ = back;
    }
}

test "comprehensive gaussian sampling" {
    // Test gaussian sampling with different parameters
    var rng = std.Random.DefaultPrng.init(42);
    var normal_distr1 = NormalDist.init(0.0, 0.01);
    var normal_distr2 = NormalDist.init(0.0, 0.1);
    var normal_distr3 = NormalDist.init(0.5, 0.01);

    for (0..5) |_| {
        const sample = normal_distr1.next(rng.random());
        _ = sample;
    }

    for (0..5) |_| {
        const sample = normal_distr2.next(rng.random());
        _ = sample;
    }

    for (0..5) |_| {
        const sample = normal_distr3.next(rng.random());
        _ = sample;
    }
}

test "comprehensive gaussian noise generation" {
    var rng = std.Random.DefaultPrng.init(42);
    var normal_distr = NormalDist.init(0.0, 0.01);

    // Test gaussian_torus
    const mu_torus = f64ToTorus(0.125);
    for (0..5) |_| {
        const noise = gaussianTorus(mu_torus, &normal_distr, rng.random());
        _ = torusToF64(noise);
    }

    // Test gaussian_f64
    for (0..5) |_| {
        const noise = gaussianF64(0.125, &normal_distr, rng.random());
        _ = torusToF64(noise);
    }
}

test "comprehensive vector operations" {
    const allocator = std.testing.allocator;

    // Test f64_to_torus_vec
    const test_f64_vec = [_]f64{ 0.0, 0.125, 0.25, 0.5, 0.75 };
    const torus_vec = try f64ToTorusVec(allocator, &test_f64_vec);
    defer allocator.free(torus_vec);

    for (torus_vec) |t| {
        _ = torusToF64(t);
    }

    // Test gaussian_f64_vec
    var rng = std.Random.DefaultPrng.init(42);
    var normal_distr = NormalDist.init(0.0, 0.01);
    const gaussian_vec = try gaussianF64Vec(allocator, &test_f64_vec, &normal_distr, rng.random());
    defer allocator.free(gaussian_vec);

    for (gaussian_vec) |g| {
        _ = torusToF64(g);
    }
}
