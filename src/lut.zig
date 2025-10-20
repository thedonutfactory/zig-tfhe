const std = @import("std");
const params = @import("params.zig");

/// Lookup table for LUT bootstrapping
pub const LookupTable = struct {
    data: []params.Torus,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize lookup table
    pub fn init(allocator: std.mem.Allocator, size: usize) !Self {
        const data = try allocator.alloc(params.Torus, size);
        return Self{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Deinitialize lookup table
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }
};

/// LUT generator for creating lookup tables
pub const Generator = struct {
    message_modulus: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize generator
    pub fn init(allocator: std.mem.Allocator, message_modulus: usize) Self {
        return Self{
            .message_modulus = message_modulus,
            .allocator = allocator,
        };
    }

    /// Generate lookup table from function
    pub fn generateLookupTable(self: *Self, func: fn(usize) usize) !LookupTable {
        var lut = try LookupTable.init(self.allocator, self.message_modulus);
        
        for (0..self.message_modulus) |i| {
            lut.data[i] = @intCast(func(i));
        }
        
        return lut;
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "lookup table operations" {
    const allocator = std.testing.allocator;
    var lut = try LookupTable.init(allocator, 8);
    defer lut.deinit();
    
    // Test initialization
    try std.testing.expect(lut.data.len == 8);
}

test "lut generator" {
    const allocator = std.testing.allocator;
    var generator = Generator.init(allocator, 8);
    
    const square_func = struct {
        fn call(x: usize) usize {
            return (x * x) % 8;
        }
    }.call;
    
    var lut = try generator.generateLookupTable(square_func);
    defer lut.deinit();
    
    // Test that lookup table was generated
    try std.testing.expect(lut.data.len == 8);
}
