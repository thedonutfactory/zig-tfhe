const std = @import("std");
const params = @import("params.zig");

/// TRLWE (Torus Ring Learning With Errors) level 1 ciphertext
pub const TRLWELv1 = struct {
    a: [params.implementation.trlwe_lv1.N]params.Torus,
    b: [params.implementation.trlwe_lv1.N]params.Torus,

    const Self = @This();

    /// Initialize a new zero TRLWE ciphertext
    pub fn init() Self {
        return Self{
            .a = [_]params.Torus{0} ** params.implementation.trlwe_lv1.N,
            .b = [_]params.Torus{0} ** params.implementation.trlwe_lv1.N,
        };
    }

    /// Initialize with specific values
    pub fn initWithValues(a: [params.implementation.trlwe_lv1.N]params.Torus, b: [params.implementation.trlwe_lv1.N]params.Torus) Self {
        return Self{ .a = a, .b = b };
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "trlwe initialization" {
    const trlwe = TRLWELv1.init();
    
    // Check that all coefficients are zero
    for (trlwe.a) |coeff| {
        try std.testing.expect(coeff == 0);
    }
    for (trlwe.b) |coeff| {
        try std.testing.expect(coeff == 0);
    }
}
