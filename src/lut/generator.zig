//! Lookup table generator for programmable bootstrapping
//!
//! This module provides functionality to generate lookup tables from functions
//! for use in programmable bootstrapping operations.

const std = @import("std");
const params = @import("../params.zig");
const encoder = @import("encoder.zig");
const lookup_table = @import("lookup_table.zig");

/// Generator for creating lookup tables from functions
///
/// The generator creates lookup tables that encode arbitrary functions
/// for evaluation during programmable bootstrapping.
pub const Generator = struct {
    const Self = @This();

    /// Encoder for message space
    encoder: encoder.Encoder,
    /// Polynomial degree (N from TRGSW parameters)
    poly_degree: usize,
    /// Lookup table size (equals poly_degree for standard TFHE)
    lookup_table_size: usize,

    /// Create a new LUT generator
    ///
    /// # Arguments
    /// * `message_modulus` - Number of possible messages (e.g., 2 for binary)
    pub fn new(message_modulus: usize) Self {
        const poly_degree = params.implementation.trgsw_lv1.N;
        // For standard TFHE, lookup_table_size = poly_degree (poly_extend_factor = 1)
        // Only for extended configurations is lookup_table_size > poly_degree
        const lookup_table_size = poly_degree;

        return Self{
            .encoder = encoder.Encoder.new(message_modulus),
            .poly_degree = poly_degree,
            .lookup_table_size = lookup_table_size,
        };
    }

    /// Create a new LUT generator with custom scale
    ///
    /// # Arguments
    /// * `message_modulus` - Number of possible messages
    /// * `scale` - Custom scaling factor for encoding
    pub fn withScale(message_modulus: usize, scale: f64) Self {
        const poly_degree = params.implementation.trgsw_lv1.N;
        const lookup_table_size = poly_degree; // Standard: lookup_table_size = poly_degree

        return Self{
            .encoder = encoder.Encoder.withScale(message_modulus, scale),
            .poly_degree = poly_degree,
            .lookup_table_size = lookup_table_size,
        };
    }

    /// Generate a lookup table from a function
    ///
    /// # Arguments
    /// * `f` - Function to encode (maps message index to output value)
    ///
    /// # Returns
    /// Generated lookup table
    pub fn generateLookupTable(self: *const Self, f: *const fn (usize) usize) lookup_table.LookupTable {
        var lut = lookup_table.LookupTable.new();
        self.generateLookupTableAssign(f, &lut);
        return lut;
    }

    /// Generate a lookup table and write to the provided output
    ///
    /// This is the core implementation of lookup table generation.
    /// The algorithm follows the tfhe-go reference implementation:
    ///
    /// 1. Create raw LUT buffer (size = lookup_table_size)
    /// 2. For each message x, fill range with encoded f(x)
    /// 3. Rotate by offset
    /// 4. Negate tail
    /// 5. Store in polynomial
    ///
    /// # Arguments
    /// * `f` - Function to encode
    /// * `lut_out` - Output lookup table to write to
    pub fn generateLookupTableAssign(self: *const Self, f: *const fn (usize) usize, lut_out: *lookup_table.LookupTable) void {
        const message_modulus = self.encoder.message_modulus;

        // Create raw LUT buffer (size = lookup_table_size, which equals N for standard TFHE)
        var lut_raw = std.heap.page_allocator.alloc(params.Torus, self.lookup_table_size) catch @panic("Failed to allocate LUT buffer");
        defer std.heap.page_allocator.free(lut_raw);
        @memset(lut_raw, 0);

        // Fill each message's range with encoded output
        for (0..message_modulus) |x| {
            const start = divRound(x * self.lookup_table_size, message_modulus);
            const end = divRound((x + 1) * self.lookup_table_size, message_modulus);

            // Apply function to message index
            const y = f(x);

            // Encode the output: message * scale
            // Use the same encoder as the input to maintain consistency
            const encoded_y = self.encoder.encode(y);

            // Fill range
            for (start..end) |xx| {
                lut_raw[xx] = encoded_y;
            }
        }

        // Rotate by offset
        const offset = divRound(self.lookup_table_size, 2 * message_modulus);

        // Apply rotation
        var rotated = std.heap.page_allocator.alloc(params.Torus, self.lookup_table_size) catch @panic("Failed to allocate rotated buffer");
        defer std.heap.page_allocator.free(rotated);
        @memset(rotated, 0);

        for (0..self.lookup_table_size) |i| {
            const src_idx = (i + offset) % self.lookup_table_size;
            rotated[i] = lut_raw[src_idx];
        }

        // Negate tail portion
        for ((self.lookup_table_size - offset)..self.lookup_table_size) |i| {
            rotated[i] = ~rotated[i] +% 1; // Wrapping negation
        }

        // Store in polynomial
        // For poly_extend_factor=1: just copy all lookup_table_size coefficients
        for (0..self.lookup_table_size) |i| {
            lut_out.poly.b[i] = rotated[i];
            lut_out.poly.a[i] = 0;
        }
    }

    /// Generate a lookup table from a function that returns Torus values
    ///
    /// # Arguments
    /// * `f` - Function that maps message index to Torus output value
    ///
    /// # Returns
    /// Generated lookup table
    pub fn generateLookupTableFull(self: *const Self, f: *const fn (usize) params.Torus) lookup_table.LookupTable {
        var lut = lookup_table.LookupTable.new();
        self.generateLookupTableFullAssign(f, &lut);
        return lut;
    }

    /// Generate a lookup table with full control over Torus values
    ///
    /// # Arguments
    /// * `f` - Function that maps message index to Torus output value
    /// * `lut_out` - Output lookup table to write to
    pub fn generateLookupTableFullAssign(self: *const Self, f: *const fn (usize) params.Torus, lut_out: *lookup_table.LookupTable) void {
        const message_modulus = self.encoder.message_modulus;

        var lut_raw = std.heap.page_allocator.alloc(params.Torus, self.lookup_table_size) catch @panic("Failed to allocate LUT buffer");
        defer std.heap.page_allocator.free(lut_raw);
        @memset(lut_raw, 0);

        for (0..message_modulus) |x| {
            const start = divRound(x * self.lookup_table_size, message_modulus);
            const end = divRound((x + 1) * self.lookup_table_size, message_modulus);

            const y = f(x);

            for (start..end) |i| {
                lut_raw[i] = y;
            }
        }

        const offset = divRound(self.lookup_table_size, 2 * message_modulus);
        var rotated = std.heap.page_allocator.alloc(params.Torus, self.lookup_table_size) catch @panic("Failed to allocate rotated buffer");
        defer std.heap.page_allocator.free(rotated);
        @memset(rotated, 0);

        for (0..self.lookup_table_size) |i| {
            const src_idx = (i + offset) % self.lookup_table_size;
            rotated[i] = lut_raw[src_idx];
        }

        for ((self.lookup_table_size - offset)..self.lookup_table_size) |i| {
            rotated[i] = ~rotated[i] +% 1; // Wrapping negation
        }

        for (0..self.lookup_table_size) |i| {
            lut_out.poly.b[i] = rotated[i];
            lut_out.poly.a[i] = 0;
        }
    }

    /// Generate a lookup table with custom message modulus and scale
    ///
    /// # Arguments
    /// * `f` - Function to encode
    /// * `message_modulus` - Custom message modulus
    /// * `scale` - Custom scale factor
    ///
    /// # Returns
    /// Generated lookup table
    pub fn generateLookupTableCustom(self: *const Self, f: *const fn (usize) usize, message_modulus: usize, scale: f64) lookup_table.LookupTable {
        var lut = lookup_table.LookupTable.new();

        // Temporarily change encoder
        var temp_generator = self.*;
        temp_generator.encoder = encoder.Encoder.withScale(message_modulus, scale);

        temp_generator.generateLookupTableAssign(f, &lut);

        return lut;
    }

    /// Switch the modulus of x from Torus (2^32) to lookup_table_size
    ///
    /// For standard TFHE with lookup_table_size=N: result in [0, N)
    ///
    /// # Arguments
    /// * `x` - Torus value to convert
    ///
    /// # Returns
    /// Converted value in [0, lookup_table_size)
    pub fn modSwitch(self: *const Self, x: params.Torus) usize {
        const scaled = (@as(f64, @floatFromInt(x)) / @as(f64, @floatFromInt(std.math.maxInt(u32)))) * @as(f64, @floatFromInt(self.lookup_table_size));
        const result = @as(usize, @intFromFloat(scaled + 0.5)) % self.lookup_table_size;
        return result;
    }

    /// Get the message modulus
    pub fn messageModulus(self: *const Self) usize {
        return self.encoder.message_modulus;
    }

    /// Get the polynomial degree
    pub fn polyDegree(self: *const Self) usize {
        return self.poly_degree;
    }

    /// Get the lookup table size
    pub fn lookupTableSize(self: *const Self) usize {
        return self.lookup_table_size;
    }
};

/// Perform integer division with rounding
///
/// # Arguments
/// * `a` - Dividend
/// * `b` - Divisor
///
/// # Returns
/// Rounded result of a / b
fn divRound(a: usize, b: usize) usize {
    return (a + b / 2) / b;
}

// ============================================================================
// TESTS
// ============================================================================

test "generator creation" {
    const generator = Generator.new(2);
    try std.testing.expectEqual(@as(usize, 2), generator.messageModulus());
    try std.testing.expectEqual(params.implementation.trgsw_lv1.N, generator.polyDegree());
    try std.testing.expectEqual(params.implementation.trgsw_lv1.N, generator.lookupTableSize());
}

test "identity function" {
    const generator = Generator.new(2);
    const identity = struct {
        fn call(x: usize) usize {
            return x;
        }
    }.call;

    const lut = generator.generateLookupTable(identity);

    // The lookup table should not be empty
    try std.testing.expect(!lut.isEmpty());
}

test "not function" {
    const generator = Generator.new(2);
    const not_func = struct {
        fn call(x: usize) usize {
            return 1 - x;
        }
    }.call;

    const lut = generator.generateLookupTable(not_func);

    // The lookup table should not be empty
    try std.testing.expect(!lut.isEmpty());
}

test "constant function" {
    const generator = Generator.new(2);
    const constant_one = struct {
        fn call(x: usize) usize {
            _ = x;
            return 1;
        }
    }.call;

    const lut = generator.generateLookupTable(constant_one);

    // The lookup table should not be empty
    try std.testing.expect(!lut.isEmpty());
}

test "4bit function" {
    const generator = Generator.new(4);
    const increment = struct {
        fn call(x: usize) usize {
            return (x + 1) % 4;
        }
    }.call;

    const lut = generator.generateLookupTable(increment);

    // The lookup table should not be empty
    try std.testing.expect(!lut.isEmpty());
}

test "custom scale" {
    const generator = Generator.withScale(2, 0.5);
    const identity = struct {
        fn call(x: usize) usize {
            return x;
        }
    }.call;

    const lut = generator.generateLookupTable(identity);

    // The lookup table should not be empty
    try std.testing.expect(!lut.isEmpty());
}

test "mod switch" {
    const generator = Generator.new(2);

    // Test some values
    const result1 = generator.modSwitch(0);
    const result2 = generator.modSwitch(std.math.maxInt(u32) / 2);
    const result3 = generator.modSwitch(std.math.maxInt(u32));

    try std.testing.expect(result1 < generator.lookupTableSize());
    try std.testing.expect(result2 < generator.lookupTableSize());
    try std.testing.expect(result3 < generator.lookupTableSize());
}

test "div round" {
    try std.testing.expectEqual(@as(usize, 3), divRound(5, 2)); // 5/2 = 2.5 -> 3
    try std.testing.expectEqual(@as(usize, 2), divRound(4, 2)); // 4/2 = 2.0 -> 2
    try std.testing.expectEqual(@as(usize, 2), divRound(3, 2)); // 3/2 = 1.5 -> 2
    try std.testing.expectEqual(@as(usize, 1), divRound(1, 2)); // 1/2 = 0.5 -> 1
    try std.testing.expectEqual(@as(usize, 0), divRound(0, 2)); // 0/2 = 0.0 -> 0
}
