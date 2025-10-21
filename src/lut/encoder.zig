//! Message encoding for lookup tables
//!
//! This module provides encoding and decoding functions for different message spaces
//! used in programmable bootstrapping.

const std = @import("std");
const params = @import("../params.zig");
const utils = @import("../utils.zig");

/// Encoder for different message spaces in programmable bootstrapping
///
/// The encoder handles the conversion between integer messages and torus values
/// used in the lookup table generation process.
pub const Encoder = struct {
    const Self = @This();

    /// Number of possible messages (e.g., 2 for binary, 4 for 2-bit)
    message_modulus: usize,
    /// Scaling factor for encoding
    scale: f64,

    /// Create a new encoder with the given message modulus
    ///
    /// For binary (boolean) operations, use `message_modulus=2`.
    /// The default encoding uses `1/(2*message_modulus)` to place messages in the torus.
    ///
    /// # Arguments
    /// * `message_modulus` - Number of possible messages (e.g., 2 for binary)
    pub fn new(message_modulus: usize) Self {
        // For TFHE, binary messages are encoded as ±1/8
        // Message 0 (false) -> -1/8 = 7/8 in unsigned representation
        // Message 1 (true) -> +1/8
        //
        // For general case with messageModulus m, we use ±1/(2m)
        // This gives us 1/4 for binary (m=2)
        const scale = 1.0 / (2.0 * @as(f64, @floatFromInt(message_modulus)));

        return Self{
            .message_modulus = message_modulus,
            .scale = scale,
        };
    }

    /// Create a new encoder with custom message modulus and scale
    ///
    /// # Arguments
    /// * `message_modulus` - Number of possible messages
    /// * `scale` - Custom scaling factor for encoding
    pub fn withScale(message_modulus: usize, scale: f64) Self {
        return Self{
            .message_modulus = message_modulus,
            .scale = scale,
        };
    }

    /// Encode an integer message into a torus value
    ///
    /// The message should be in range [0, message_modulus).
    /// For TFHE bootstrapping, the encoding is: `message * scale`
    ///
    /// # Arguments
    /// * `message` - Integer message to encode
    ///
    /// # Returns
    /// Encoded torus value
    pub fn encode(self: *const Self, message: usize) params.Torus {
        // Normalize message to [0, message_modulus)
        const normalized_message = message % self.message_modulus;

        // Encode as message * scale
        const value = @as(f64, @floatFromInt(normalized_message)) * self.scale;
        return utils.f64ToTorus(value);
    }

    /// Encode with a custom scale factor
    ///
    /// # Arguments
    /// * `message` - Integer message to encode
    /// * `scale` - Custom scale factor
    ///
    /// # Returns
    /// Encoded torus value
    pub fn encodeWithScale(self: *const Self, message: usize, scale: f64) params.Torus {
        const normalized_message = message % self.message_modulus;
        const value = @as(f64, @floatFromInt(normalized_message)) * scale;
        return utils.f64ToTorus(value);
    }

    /// Decode a torus value back to an integer message
    ///
    /// # Arguments
    /// * `value` - Torus value to decode
    ///
    /// # Returns
    /// Decoded integer message
    pub fn decode(self: *const Self, value: params.Torus) usize {
        // Convert torus to float
        const f = utils.torusToF64(value);

        // Round to nearest message
        const message = @as(usize, @intFromFloat(f / self.scale + 0.5));

        // Normalize to [0, message_modulus)
        return message % self.message_modulus;
    }

    /// Decode a torus value to a boolean (for binary messages)
    ///
    /// # Arguments
    /// * `value` - Torus value to decode
    ///
    /// # Returns
    /// Decoded boolean value
    pub fn decodeBool(self: *const Self, value: params.Torus) bool {
        return self.decode(value) != 0;
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "binary encoder" {
    const encoder = Encoder.new(2);

    // Test encoding
    const encoded_0 = encoder.encode(0);
    const encoded_1 = encoder.encode(1);

    // Test decoding
    try std.testing.expectEqual(@as(usize, 0), encoder.decode(encoded_0));
    try std.testing.expectEqual(@as(usize, 1), encoder.decode(encoded_1));

    // Test boolean decoding
    try std.testing.expectEqual(false, encoder.decodeBool(encoded_0));
    try std.testing.expectEqual(true, encoder.decodeBool(encoded_1));
}

test "4bit encoder" {
    const encoder = Encoder.new(4);

    for (0..4) |i| {
        const encoded = encoder.encode(i);
        const decoded = encoder.decode(encoded);
        try std.testing.expectEqual(i, decoded);
    }
}

test "custom scale" {
    const encoder = Encoder.withScale(2, 0.5);

    const encoded_0 = encoder.encode(0);
    const encoded_1 = encoder.encode(1);

    try std.testing.expectEqual(@as(usize, 0), encoder.decode(encoded_0));
    try std.testing.expectEqual(@as(usize, 1), encoder.decode(encoded_1));
}
