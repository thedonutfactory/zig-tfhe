//! TFHE Security Parameter Selection
//!
//! This library supports multiple security levels to allow users to choose
//! the right balance between performance and security for their use case.
//!
//! # Available Security Levels
//!
//! - **80-bit**: Fast performance, suitable for development/testing
//! - **110-bit**: Balanced performance and security (original TFHE reference)
//! - **128-bit**: High security, quantum-resistant (default)
//! - **Uint1-Uint8**: Specialized parameters for different message moduli
//!
//! # Security Parameters Explained
//!
//! The security level is determined by several cryptographic parameters:
//! - `N`: LWE dimension (higher = more secure, slower)
//! - `ALPHA`: Noise standard deviation (smaller = often more secure with proper dimension)
//! - `L`: Gadget decomposition levels (more = more secure, slower)
//! - `BGBIT`: Decomposition base bits (smaller = more levels, more secure, slower)
//!
//! # Usage Example
//!
//! ```zig
//! const params = @import("params");
//!
//! // Use 128-bit security (default)
//! const security_params = params.SECURITY_128_BIT;
//! ```

const std = @import("std");

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

pub const Torus = u32;
pub const HalfTorus = i32;
pub const IntTorus = i64;

pub const TORUS_SIZE: usize = @sizeOf(Torus) * 8;
pub const ZERO_TORUS: Torus = 0;

// ============================================================================
// PARAMETER STRUCTURES
// ============================================================================

/// Security parameter set containing all TFHE parameters
pub const SecurityParams = struct {
    security_bits: usize,
    description: []const u8,
    tlwe_lv0: TlweParams,
    tlwe_lv1: TlweParams,
    trlwe_lv1: TrlweParams,
    trgsw_lv1: TrgswParams,
};

pub const TlweParams = struct {
    n: usize,
    alpha: f64,
};

pub const TrlweParams = struct {
    n: usize,
    alpha: f64,
};

pub const TrgswParams = struct {
    n: usize,
    nbit: usize,
    bgbit: u32,
    bg: u32,
    l: usize,
    basebit: usize,
    iks_t: usize,
    alpha: f64,
};

// ============================================================================
// SECURITY PARAMETER CONSTANTS
// ============================================================================

/// 80-bit security parameters (performance-optimized)
pub const SECURITY_80_BIT: SecurityParams = SecurityParams{
    .security_bits = 80,
    .description = "80-bit security (performance-optimized)",
    .tlwe_lv0 = TlweParams{
        .n = 550,
        .alpha = 5.0e-5, // 2^-14.3 approximately
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 3.73e-8, // 2^-24.7 approximately
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 3.73e-8,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 6,
        .bg = 64,
        .l = 3,
        .basebit = 2,
        .iks_t = 7,
        .alpha = 3.73e-8,
    },
};

/// 110-bit security parameters (balanced, original TFHE)
pub const SECURITY_110_BIT: SecurityParams = SecurityParams{
    .security_bits = 110,
    .description = "110-bit security (balanced, original TFHE)",
    .tlwe_lv0 = TlweParams{
        .n = 630,
        .alpha = 3.0517578125e-05, // 2^-15 approximately
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.980_232_238_769_531_3e-8, // 2^-25 approximately
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.980_232_238_769_531_3e-8,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 6,
        .bg = 64,
        .l = 3,
        .basebit = 2,
        .iks_t = 8,
        .alpha = 2.980_232_238_769_531_3e-8,
    },
};

/// Uint1 parameters (1-bit binary/boolean, messageModulus=2)
pub const SECURITY_UINT1: SecurityParams = SecurityParams{
    .security_bits = 1,
    .description = "Uint1 parameters (1-bit binary/boolean, messageModulus=2, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 700,
        .alpha = 2.0e-05,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.0e-08,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.0e-08,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 10,
        .bg = 1024,
        .l = 2,
        .basebit = 2,
        .iks_t = 8,
        .alpha = 2.0e-08,
    },
};

/// Uint2 parameters (2-bit messages, messageModulus=4)
pub const SECURITY_UINT2: SecurityParams = SecurityParams{
    .security_bits = 2,
    .description = "Uint2 parameters (2-bit messages, messageModulus=4, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 687,
        .alpha = 0.00002120846893069971872305794214,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024, // Using 1024 for compatibility with hardcoded TRGSW/TRLWE
        .alpha = 0.00000000000231841227527049948463,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 0.00000000000231841227527049948463,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10, // 1024 = 2^10
        .bgbit = 18, // Base = 1 << 18
        .bg = 262144,
        .l = 1,
        .basebit = 4, // KeySwitch base bits
        .iks_t = 3, // KeySwitch level
        .alpha = 0.00000000000231841227527049948463,
    },
};

/// Uint3 parameters (3-bit messages, messageModulus=8)
pub const SECURITY_UINT3: SecurityParams = SecurityParams{
    .security_bits = 3,
    .description = "Uint3 parameters (3-bit messages, messageModulus=8, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 820,
        .alpha = 0.00000251676160959795544987084234,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 0.00000000000000022204460492503131,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 0.00000000000000022204460492503131,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10, // 1024 = 2^10
        .bgbit = 23, // Base = 1 << 23
        .bg = 8388608,
        .l = 1,
        .basebit = 6, // KeySwitch base bits
        .iks_t = 2, // KeySwitch level
        .alpha = 0.00000000000000022204460492503131,
    },
};

/// Uint4 parameters (4-bit messages, messageModulus=16)
pub const SECURITY_UINT4: SecurityParams = SecurityParams{
    .security_bits = 4,
    .description = "Uint4 parameters (4-bit messages, messageModulus=16, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 820,
        .alpha = 0.00000251676160959795544987084234,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 0.00000000000000022204460492503131,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 0.00000000000000022204460492503131,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10, // 1024 = 2^10
        .bgbit = 22, // Base = 1 << 22
        .bg = 4194304,
        .l = 1,
        .basebit = 5, // KeySwitch base bits
        .iks_t = 3, // KeySwitch level
        .alpha = 0.00000000000000022204460492503131,
    },
};

/// Uint5 parameters (5-bit messages, messageModulus=32) - Recommended for complex arithmetic
pub const SECURITY_UINT5: SecurityParams = SecurityParams{
    .security_bits = 5,
    .description = "Uint5 parameters (5-bit messages, messageModulus=32, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 1071,
        .alpha = 7.088226765410429399593757e-08,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 22,
        .bg = 4194304,
        .l = 1,
        .basebit = 6,
        .iks_t = 3,
        .alpha = 2.2204460492503131e-17,
    },
};

/// Uint6 parameters (6-bit messages, messageModulus=64)
pub const SECURITY_UINT6: SecurityParams = SecurityParams{
    .security_bits = 6,
    .description = "Uint6 parameters (6-bit messages, messageModulus=64, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 1071,
        .alpha = 7.088226765410429399593757e-08,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 22,
        .bg = 4194304,
        .l = 1,
        .basebit = 6,
        .iks_t = 3,
        .alpha = 2.2204460492503131e-17,
    },
};

/// Uint7 parameters (7-bit messages, messageModulus=128)
pub const SECURITY_UINT7: SecurityParams = SecurityParams{
    .security_bits = 7,
    .description = "Uint7 parameters (7-bit messages, messageModulus=128, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 1160,
        .alpha = 1.966220007498402695211596e-08,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 22,
        .bg = 4194304,
        .l = 1,
        .basebit = 7,
        .iks_t = 3,
        .alpha = 2.2204460492503131e-17,
    },
};

/// Uint8 parameters (8-bit messages, messageModulus=256)
pub const SECURITY_UINT8: SecurityParams = SecurityParams{
    .security_bits = 8,
    .description = "Uint8 parameters (8-bit messages, messageModulus=256, N=1024)",
    .tlwe_lv0 = TlweParams{
        .n = 1160,
        .alpha = 1.966220007498402695211596e-08,
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.2204460492503131e-17,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 22,
        .bg = 4194304,
        .l = 1,
        .basebit = 7,
        .iks_t = 3,
        .alpha = 2.2204460492503131e-17,
    },
};

/// 128-bit security parameters (default, high security, quantum-resistant)
pub const SECURITY_128_BIT: SecurityParams = SecurityParams{
    .security_bits = 128,
    .description = "128-bit security (high security, quantum-resistant)",
    .tlwe_lv0 = TlweParams{
        .n = 700,
        .alpha = 2.0e-5, // 2^-15.6 approximately
    },
    .tlwe_lv1 = TlweParams{
        .n = 1024,
        .alpha = 2.0e-8, // 2^-25.6 approximately
    },
    .trlwe_lv1 = TrlweParams{
        .n = 1024,
        .alpha = 2.0e-8,
    },
    .trgsw_lv1 = TrgswParams{
        .n = 1024,
        .nbit = 10,
        .bgbit = 6,
        .bg = 64,
        .l = 3,
        .basebit = 2,
        .iks_t = 9,
        .alpha = 2.0e-8,
    },
};

// ============================================================================
// DEFAULT PARAMETER SELECTION
// ============================================================================

/// Default security parameters (128-bit)
pub const DEFAULT_SECURITY: SecurityParams = SECURITY_128_BIT;

/// Get a description of the current security level
pub fn securityInfo(allocator: std.mem.Allocator, params: SecurityParams) ![]u8 {
    return std.fmt.allocPrint(allocator, "Security level: {} bits ({s})", .{ params.security_bits, params.description });
}

// ============================================================================
// COMPATIBILITY ALIASES - For backwards compatibility with existing code
// ============================================================================

/// Compatibility module for existing code that expects the old parameter structure
pub const implementation = struct {
    // Use 128-bit parameters as default for compatibility
    pub const SECURITY_BITS: usize = SECURITY_128_BIT.security_bits;
    pub const SECURITY_DESCRIPTION: []const u8 = SECURITY_128_BIT.description;

    pub const tlwe_lv0 = struct {
        pub const N: usize = SECURITY_128_BIT.tlwe_lv0.n;
        pub const ALPHA: f64 = SECURITY_128_BIT.tlwe_lv0.alpha;
    };

    pub const tlwe_lv1 = struct {
        pub const N: usize = SECURITY_128_BIT.tlwe_lv1.n;
        pub const ALPHA: f64 = SECURITY_128_BIT.tlwe_lv1.alpha;
    };

    pub const trlwe_lv1 = struct {
        pub const N: usize = SECURITY_128_BIT.trlwe_lv1.n;
        pub const ALPHA: f64 = SECURITY_128_BIT.trlwe_lv1.alpha;
    };

    pub const trgsw_lv1 = struct {
        pub const N: usize = SECURITY_128_BIT.trgsw_lv1.n;
        pub const NBIT: usize = SECURITY_128_BIT.trgsw_lv1.nbit;
        pub const BGBIT: u32 = SECURITY_128_BIT.trgsw_lv1.bgbit;
        pub const BG: u32 = SECURITY_128_BIT.trgsw_lv1.bg;
        pub const L: usize = SECURITY_128_BIT.trgsw_lv1.l;
        pub const BASEBIT: usize = SECURITY_128_BIT.trgsw_lv1.basebit;
        pub const IKS_T: usize = SECURITY_128_BIT.trgsw_lv1.iks_t;
        pub const ALPHA: f64 = SECURITY_128_BIT.trgsw_lv1.alpha;
    };
};

// Additional compatibility constants
pub const KSK_ALPHA: f64 = SECURITY_128_BIT.tlwe_lv0.alpha;
pub const BSK_ALPHA: f64 = SECURITY_128_BIT.tlwe_lv1.alpha;

// ============================================================================
// TESTS
// ============================================================================

test "security info" {
    const allocator = std.testing.allocator;
    const info = try securityInfo(allocator, SECURITY_128_BIT);
    defer allocator.free(info);
    try std.testing.expect(std.mem.indexOf(u8, info, "128") != null);
}

test "parameter sanity" {
    // Test all parameter sets
    const params = [_]SecurityParams{
        SECURITY_80_BIT,
        SECURITY_110_BIT,
        SECURITY_128_BIT,
        SECURITY_UINT1,
        SECURITY_UINT2,
        SECURITY_UINT3,
        SECURITY_UINT4,
        SECURITY_UINT5,
        SECURITY_UINT6,
        SECURITY_UINT7,
        SECURITY_UINT8,
    };

    for (params) |param| {
        // Basic sanity checks on parameters
        try std.testing.expect(param.tlwe_lv0.n > 0);
        try std.testing.expect(param.tlwe_lv1.n > 0);
        try std.testing.expect(param.tlwe_lv0.alpha > 0.0);
        try std.testing.expect(param.tlwe_lv1.alpha > 0.0);
        try std.testing.expect(param.trgsw_lv1.l > 0);
        try std.testing.expect(param.trgsw_lv1.bgbit > 0);
    }
}

test "parameter constants" {
    // Test that all constants are accessible
    try std.testing.expect(SECURITY_80_BIT.security_bits == 80);
    try std.testing.expect(SECURITY_110_BIT.security_bits == 110);
    try std.testing.expect(SECURITY_128_BIT.security_bits == 128);
    try std.testing.expect(SECURITY_UINT1.security_bits == 1);
    try std.testing.expect(SECURITY_UINT5.security_bits == 5);
    try std.testing.expect(SECURITY_UINT8.security_bits == 8);
}
