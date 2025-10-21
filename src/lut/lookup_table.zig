//! Lookup table implementation for programmable bootstrapping
//!
//! A lookup table is a TRLWE ciphertext that encodes a function for evaluation
//! during programmable bootstrapping operations.

const std = @import("std");
const params = @import("../params.zig");
const trlwe = @import("../trlwe.zig");

/// Lookup table for programmable bootstrapping.
///
/// A lookup table is a TRLWE ciphertext that encodes a function.
/// for programmable bootstrapping. During blind rotation, the LUT is rotated.
/// based on the encrypted value, effectively evaluating the function on the.
/// encrypted data.
pub const LookupTable = struct {
    const Self = @This();

    /// Polynomial encoding the function values.
    poly: trlwe.TRLWELv1,

    /// Create a new lookup table.
    pub fn new() Self {
        return Self{
            .poly = trlwe.TRLWELv1.new(),
        };
    }

    /// Create a lookup table from an existing TRLWE polynomial.
    ///
    /// # Arguments.
    /// * `poly` - TRLWE polynomial containing the encoded function.
    pub fn fromPoly(poly: trlwe.TRLWELv1) Self {
        return Self{ .poly = poly };
    }

    /// Get a reference to the underlying polynomial.
    pub fn getPoly(self: *const Self) *const trlwe.TRLWELv1 {
        return &self.poly;
    }

    /// Get a mutable reference to the underlying polynomial.
    pub fn getPolyMut(self: *Self) *trlwe.TRLWELv1 {
        return &self.poly;
    }

    /// Copy values from another lookup table.
    ///
    /// # Arguments.
    /// * `other` - Source lookup table to copy from.
    pub fn copyFrom(self: *Self, other: *const LookupTable) void {
        @memcpy(self.poly.a[0..], other.poly.a[0..]);
        @memcpy(self.poly.b[0..], other.poly.b[0..]);
    }

    /// Clear the lookup table (sets all coefficients to 0).
    pub fn clear(self: *Self) void {
        const n = params.implementation.trgsw_lv1.N;
        @memset(self.poly.a[0..n], 0);
        @memset(self.poly.b[0..n], 0);
    }

    /// Check if the lookup table is empty (all coefficients are zero).
    pub fn isEmpty(self: *const Self) bool {
        const n = params.implementation.trgsw_lv1.N;

        for (0..n) |i| {
            if (self.poly.a[i] != 0) return false;
        }

        for (0..n) |i| {
            if (self.poly.b[i] != 0) return false;
        }

        return true;
    }
};

// TESTS

test "lookup table creation" {
    const lut = LookupTable.new();
    try std.testing.expect(lut.isEmpty());
}

test "lookup table from poly" {
    var poly = trlwe.TRLWELv1.new();
    poly.b[0] = 1;

    const lut = LookupTable.fromPoly(poly);
    try std.testing.expect(!lut.isEmpty());
}

test "lookup table copy" {
    var lut1 = LookupTable.new();
    var lut2 = LookupTable.new();

    // Set some values in lut1
    lut1.poly.b[0] = 42;
    lut1.poly.b[1] = 24;

    // Copy to lut2
    lut2.copyFrom(&lut1);

    try std.testing.expectEqual(@as(params.Torus, 42), lut2.poly.b[0]);
    try std.testing.expectEqual(@as(params.Torus, 24), lut2.poly.b[1]);
}

test "lookup table clear" {
    var lut = LookupTable.new();

    // Set some values
    lut.poly.b[0] = 42;
    lut.poly.b[1] = 24;
    try std.testing.expect(!lut.isEmpty());

    // Clear and check
    lut.clear();
    try std.testing.expect(lut.isEmpty());
}

test "lookup table conversions" {
    var poly = trlwe.TRLWELv1.new();
    poly.b[0] = 123;

    // From TRLWELv1 to LookupTable
    const lut = LookupTable.fromPoly(poly);
    try std.testing.expectEqual(@as(params.Torus, 123), lut.poly.b[0]);
}
