//! Bit manipulation utilities for TFHE
//!
//! This module provides utilities for converting between different bit representations
//! and handling bit-level operations needed for TFHE operations.

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");

// Import key module for SecretKey type
const key = @import("key.zig");

// Type alias for SecretKey
pub const SecretKey = key.SecretKey;

// ============================================================================
// BIT CONVERSION FUNCTIONS
// ============================================================================

/// Convert a vector of bits to a number
pub fn convert(comptime T: type, bits: []const bool) T {
    var result: T = 0;
    for (bits, 0..) |bit, i| {
        const bit_value: T = if (bit) 1 else 0;
        result = result | (bit_value << @intCast(i));
    }
    return result;
}

// ============================================================================
// ENCRYPTION HELPERS
// ============================================================================

/// Encrypt a boolean value
fn encryptBool(allocator: std.mem.Allocator, a: bool, secret_key: *const SecretKey) !utils.Ciphertext {
    // This is a placeholder - will be properly implemented when we have the full key and tlwe modules
    _ = allocator;
    return utils.Ciphertext.encryptBool(a, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
}

// ============================================================================
// BIT REPRESENTATION TRAITS
// ============================================================================

/// Trait for types that can be represented as bits
pub fn AsBits(comptime T: type) type {
    return struct {
        /// Represent the bits of the type as an array of boolean values (bits).
        /// Array is in little-endian order, where LSB is the first value of the array.
        pub fn toBits(self: T, allocator: std.mem.Allocator) ![]bool {
            return toBitsImpl(allocator, @as(usize, @intCast(self)), @sizeOf(T) * 8);
        }

        /// Encrypt the bits of the type as an array of Ciphertext values (cipherbits).
        pub fn encrypt(self: T, allocator: std.mem.Allocator, secret_key: *const SecretKey) ![]utils.Ciphertext {
            const bits = try self.toBits(allocator);
            defer allocator.free(bits);

            var result = try allocator.alloc(utils.Ciphertext, bits.len);
            for (bits, 0..) |bit, i| {
                result[i] = try encryptBool(allocator, bit, secret_key);
            }
            return result;
        }
    };
}

/// Internal implementation of toBits to avoid self-reference
fn toBitsImpl(allocator: std.mem.Allocator, val: usize, size: usize) ![]bool {
    var result = try allocator.alloc(bool, size);

    // Extract bits from least significant to most significant
    for (0..size) |i| {
        result[i] = ((val >> @intCast(i)) & 1) != 0;
    }

    return result;
}

// ============================================================================
// TYPE-SPECIFIC IMPLEMENTATIONS
// ============================================================================

/// Implementation for u8
pub const U8AsBits = AsBits(u8);

/// Implementation for u16
pub const U16AsBits = AsBits(u16);

/// Implementation for u32
pub const U32AsBits = AsBits(u32);

/// Implementation for u64
pub const U64AsBits = AsBits(u64);

// ============================================================================
// TESTS
// ============================================================================

test "convert bits to number" {
    const allocator = std.testing.allocator;
    _ = allocator;

    // Test u8 conversion
    const bits_u8 = [_]bool{ true, false, true, false, false, false, false, false }; // 0b00000101 = 5
    const result_u8 = convert(u8, &bits_u8);
    try std.testing.expect(result_u8 == 5);

    // Test u16 conversion
    const bits_u16 = [_]bool{ true, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false }; // 0b0000000000000101 = 5
    const result_u16 = convert(u16, &bits_u16);
    try std.testing.expect(result_u16 == 5);

    // Test u32 conversion
    const bits_u32 = [_]bool{ true, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false }; // 0b00000000000000000000000000000101 = 5
    const result_u32 = convert(u32, &bits_u32);
    try std.testing.expect(result_u32 == 5);
}

test "to bits conversion" {
    const allocator = std.testing.allocator;

    // Test u8 to bits
    const bits_u8 = try toBitsImpl(allocator, 0b10101010, 8);
    defer allocator.free(bits_u8);

    try std.testing.expect(bits_u8[0] == false); // LSB
    try std.testing.expect(bits_u8[1] == true);
    try std.testing.expect(bits_u8[2] == false);
    try std.testing.expect(bits_u8[3] == true);
    try std.testing.expect(bits_u8[4] == false);
    try std.testing.expect(bits_u8[5] == true);
    try std.testing.expect(bits_u8[6] == false);
    try std.testing.expect(bits_u8[7] == true); // MSB

    // Test u16 to bits
    const bits_u16 = try toBitsImpl(allocator, 0b1010101010101010, 16);
    defer allocator.free(bits_u16);

    try std.testing.expect(bits_u16[0] == false); // LSB
    try std.testing.expect(bits_u16[15] == true); // MSB
}

test "as bits trait for u8" {
    const allocator = std.testing.allocator;

    const value: u8 = 0b10101010;
    const bits = try U8AsBits.toBits(value, allocator);
    defer allocator.free(bits);

    try std.testing.expect(bits.len == 8);
    try std.testing.expect(bits[0] == false); // LSB
    try std.testing.expect(bits[7] == true); // MSB
}

test "as bits trait for u16" {
    const allocator = std.testing.allocator;

    const value: u16 = 0b1010101010101010;
    const bits = try U16AsBits.toBits(value, allocator);
    defer allocator.free(bits);

    try std.testing.expect(bits.len == 16);
    try std.testing.expect(bits[0] == false); // LSB
    try std.testing.expect(bits[15] == true); // MSB
}

test "as bits trait for u32" {
    const allocator = std.testing.allocator;

    const value: u32 = 0b10101010101010101010101010101010;
    const bits = try U32AsBits.toBits(value, allocator);
    defer allocator.free(bits);

    try std.testing.expect(bits.len == 32);
    try std.testing.expect(bits[0] == false); // LSB
    try std.testing.expect(bits[31] == true); // MSB
}

test "as bits trait for u64" {
    const allocator = std.testing.allocator;

    const value: u64 = 0b1010101010101010101010101010101010101010101010101010101010101010;
    const bits = try U64AsBits.toBits(value, allocator);
    defer allocator.free(bits);

    try std.testing.expect(bits.len == 64);
    try std.testing.expect(bits[0] == false); // LSB
    try std.testing.expect(bits[63] == true); // MSB
}

test "round trip conversion" {
    const allocator = std.testing.allocator;

    // Test u8 round trip
    const original_u8: u8 = 0b10101010;
    const bits_u8 = try U8AsBits.toBits(original_u8, allocator);
    defer allocator.free(bits_u8);
    const converted_u8 = convert(u8, bits_u8);
    try std.testing.expect(original_u8 == converted_u8);

    // Test u16 round trip
    const original_u16: u16 = 0b1010101010101010;
    const bits_u16 = try U16AsBits.toBits(original_u16, allocator);
    defer allocator.free(bits_u16);
    const converted_u16 = convert(u16, bits_u16);
    try std.testing.expect(original_u16 == converted_u16);

    // Test u32 round trip
    const original_u32: u32 = 0b10101010101010101010101010101010;
    const bits_u32 = try U32AsBits.toBits(original_u32, allocator);
    defer allocator.free(bits_u32);
    const converted_u32 = convert(u32, bits_u32);
    try std.testing.expect(original_u32 == converted_u32);

    // Test u64 round trip
    const original_u64: u64 = 0b1010101010101010101010101010101010101010101010101010101010101010;
    const bits_u64 = try U64AsBits.toBits(original_u64, allocator);
    defer allocator.free(bits_u64);
    const converted_u64 = convert(u64, bits_u64);
    try std.testing.expect(original_u64 == converted_u64);
}
