const std = @import("std");
const tfhe = @import("../src/main.zig");

/// Example: Compare different security levels
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Security Levels Comparison ===", .{});

    // Test different security levels
    const security_levels = [_]struct { name: []const u8, params: tfhe.params.SecurityParams }{
        .{ .name = "80-bit", .params = tfhe.params.SECURITY_80_BIT },
        .{ .name = "110-bit", .params = tfhe.params.SECURITY_110_BIT },
        .{ .name = "128-bit", .params = tfhe.params.SECURITY_128_BIT },
        .{ .name = "Uint1", .params = tfhe.params.SECURITY_UINT1 },
        .{ .name = "Uint4", .params = tfhe.params.SECURITY_UINT4 },
        .{ .name = "Uint8", .params = tfhe.params.SECURITY_UINT8 },
    };

    for (security_levels) |level| {
        std.log.info("--- {} Security ---", .{level.name});
        
        const info = try tfhe.params.securityInfo(level.params, allocator);
        defer allocator.free(info);
        std.log.info("Info: {s}", .{info});
        
        std.log.info("TLWE Lv0: N={}, alpha={e}", .{ level.params.tlwe_lv0.n, level.params.tlwe_lv0.alpha });
        std.log.info("TLWE Lv1: N={}, alpha={e}", .{ level.params.tlwe_lv1.n, level.params.tlwe_lv1.alpha });
        std.log.info("TRGSW: N={}, L={}, bgbit={}", .{ level.params.trgsw_lv1.n, level.params.trgsw_lv1.l, level.params.trgsw_lv1.bgbit });
        
        // Test key generation with this security level
        const secret_key = try tfhe.key.SecretKey.init(allocator);
        std.log.info("Key generation successful", .{});
        
        std.log.info("", .{});
    }

    std.log.info("=== Security Levels Comparison Complete ===", .{});
}
