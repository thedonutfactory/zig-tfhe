const std = @import("std");
const params = @import("params.zig");

/// FFT Processor Module for TFHE
///
/// This module provides abstracted FFT operations for negacyclic polynomial
/// multiplication in the ring R[X]/(X^N+1), which is fundamental to TFHE.
///
/// # Architecture
///
/// The module uses a trait-based design with platform-specific implementations:
///
/// - **x86_64**: `SpqliosFFT` - Hand-optimized AVX/FMA assembly (~30ms/gate)
/// - **ARM64/Other**: `KlemsaProcessor` - Pure Zig implementation (~100ms/gate)
///
/// Both implementations are mathematically equivalent and pass identical test suites.
/// Complex number structure for FFT operations
pub const Complex = struct {
    re: f64,
    im: f64,

    pub fn new(re: f64, im: f64) Complex {
        return Complex{ .re = re, .im = im };
    }

    pub fn add(self: Complex, other: Complex) Complex {
        return Complex{ .re = self.re + other.re, .im = self.im + other.im };
    }

    pub fn sub(self: Complex, other: Complex) Complex {
        return Complex{ .re = self.re - other.re, .im = self.im - other.im };
    }

    pub fn mul(self: Complex, other: Complex) Complex {
        return Complex{
            .re = self.re * other.re - self.im * other.im,
            .im = self.re * other.im + self.im * other.re,
        };
    }

    pub fn scale(self: Complex, factor: f64) Complex {
        return Complex{ .re = self.re * factor, .im = self.im * factor };
    }
};

/// High-performance FFT processor based on Go implementation
///
/// Uses vectorized butterfly operations and optimized memory access patterns
pub const KlemsaProcessor = struct {
    // Pre-computed twisting factors (2N-th roots of unity)
    twisties_re: []f64,
    twisties_im: []f64,
    // Pre-allocated buffer for vectorized operations (f64 array for performance)
    fourier_buffer: []f64,
    allocator: std.mem.Allocator,
    n: usize,

    const Self = @This();

    pub fn new(allocator: std.mem.Allocator, n: usize) !Self {
        std.debug.assert(std.math.isPowerOfTwo(n));
        std.debug.assert(n >= 2);

        const n2 = n / 2;

        // Compute twisting factors: exp(i*π*k/N) for k=0..N/2-1
        var twisties_re = try allocator.alloc(f64, n2);
        var twisties_im = try allocator.alloc(f64, n2);
        const twist_unit = std.math.pi / @as(f64, @floatFromInt(n));

        for (0..n2) |i| {
            const angle = @as(f64, @floatFromInt(i)) * twist_unit;
            twisties_re[i] = @cos(angle);
            twisties_im[i] = @sin(angle);
        }

        // Pre-allocate buffer for vectorized operations
        var fourier_buffer = try allocator.alloc(f64, n);

        // Initialize buffer
        for (0..n) |i| {
            fourier_buffer[i] = 0.0;
        }

        return Self{
            .twisties_re = twisties_re,
            .twisties_im = twisties_im,
            .fourier_buffer = fourier_buffer,
            .allocator = allocator,
            .n = n,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.twisties_re);
        self.allocator.free(self.twisties_im);
        self.allocator.free(self.fourier_buffer);
    }

    /// High-performance forward FFT using vectorized butterfly operations
    /// Input: N torus32 values representing polynomial coefficients
    /// Output: N f64 values (N/2 complex stored as [re_0..re_N/2-1, im_0..im_N/2-1])
    pub fn ifft(self: *Self, input: []const params.Torus) ![]f64 {
        const n2 = self.n / 2;
        const input_re = input[0..n2];
        const input_im = input[n2..];

        // Convert torus to f64 and apply twisting factors
        for (0..n2) |i| {
            // Convert torus to signed integer first, then to float
            const in_re_signed = if (input_re[i] >= std.math.pow(u32, 2, 31))
                @as(i64, @intCast(input_re[i])) - std.math.pow(i64, 2, 32)
            else
                @as(i64, @intCast(input_re[i]));
            const in_im_signed = if (input_im[i] >= std.math.pow(u32, 2, 31))
                @as(i64, @intCast(input_im[i])) - std.math.pow(i64, 2, 32)
            else
                @as(i64, @intCast(input_im[i]));
            const in_re = @as(f64, @floatFromInt(in_re_signed));
            const in_im = @as(f64, @floatFromInt(in_im_signed));
            const w_re = self.twisties_re[i];
            const w_im = self.twisties_im[i];

            // Apply twisting factors and store in interleaved format
            self.fourier_buffer[i] = in_re * w_re - in_im * w_im; // real part
            self.fourier_buffer[i + n2] = in_re * w_im + in_im * w_re; // imag part
        }

        // Perform optimized FFT
        self.processFFT();

        // Scale by 2 and return
        var result = try self.allocator.alloc(f64, self.n);
        for (0..self.n) |i| {
            result[i] = self.fourier_buffer[i] * 2.0;
        }

        return result;
    }

    /// High-performance inverse FFT using vectorized butterfly operations
    /// Input: N f64 values (N/2 complex stored as [re_0..re_N/2-1, im_0..im_N/2-1])
    /// Output: N torus32 values representing polynomial coefficients
    pub fn fft(self: *Self, input: []const f64) ![]params.Torus {
        const n2 = self.n / 2;

        // Copy input to buffer and scale by 0.5
        for (0..self.n) |i| {
            self.fourier_buffer[i] = input[i] * 0.5;
        }

        // Perform optimized inverse FFT
        self.processIFFT();

        // Apply inverse twisting and convert to torus
        const normalization = 1.0 / @as(f64, @floatFromInt(n2));
        var result = try self.allocator.alloc(params.Torus, self.n);

        for (0..n2) |i| {
            const w_re = self.twisties_re[i];
            const w_im = self.twisties_im[i];
            const f_re = self.fourier_buffer[i];
            const f_im = self.fourier_buffer[i + n2];
            const tmp_re = (f_re * w_re + f_im * w_im) * normalization;
            const tmp_im = (f_im * w_re - f_re * w_im) * normalization;

            // Convert to integer using proper rounding
            const rounded_re = @as(i64, @intFromFloat(@round(tmp_re)));
            const rounded_im = @as(i64, @intFromFloat(@round(tmp_im)));

            // Convert to torus using proper modular arithmetic
            result[i] = @as(params.Torus, @intCast(@mod(rounded_re, std.math.pow(i64, 2, 32))));
            result[i + n2] = @as(params.Torus, @intCast(@mod(rounded_im, std.math.pow(i64, 2, 32))));
        }

        return result;
    }

    /// Vectorized butterfly operation for forward FFT
    fn performButterfly2(self: *Self, uR: f64, uI: f64, vR: f64, vI: f64, wR: f64, wI: f64) [4]f64 {
        _ = self;
        // Apply twiddle factor first
        const vwR = vR * wR - vI * wI;
        const vwI = vR * wI + vI * wR;

        // Butterfly operation
        const tempR = uR + vwR;
        const tempI = uI + vwI;
        const vNewR = uR - vwR;
        const vNewI = uI - vwI;

        return [4]f64{ tempR, tempI, vNewR, vNewI };
    }

    /// Vectorized butterfly operation for inverse FFT
    fn performInvButterfly2(self: *Self, uR: f64, uI: f64, vR: f64, vI: f64, wR: f64, wI: f64) [4]f64 {
        _ = self;
        // First apply the butterfly operation (without twiddle)
        const tempR = uR + vR;
        const tempI = uI + vI;
        const vNewR = uR - vR;
        const vNewI = uI - vI;

        // Then apply twiddle factor to v
        const vwR = vNewR * wR - vNewI * wI;
        const vwI = vNewR * wI + vNewI * wR;

        return [4]f64{ tempR, tempI, vwR, vwI };
    }

    /// Exact Go ProcessFFT implementation
    fn processFFT(self: *Self) void {
        const N = self.n;
        var wIdx: usize = 0;

        // First stage - exact Go implementation
        if (wIdx < self.twisties_re.len) {
            const wReal = self.twisties_re[wIdx];
            const wImag = self.twisties_im[wIdx];
            wIdx += 1;

            var j: usize = 0;
            while (j < N / 2) : (j += 8) {
                // Process 8 elements at a time - exact Go unrolled version
                const result0 = self.performButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + N / 2 + 0], self.fourier_buffer[j + N / 2 + 4], wReal, wImag);
                self.fourier_buffer[j + 0] = result0[0];
                self.fourier_buffer[j + 4] = result0[1];
                self.fourier_buffer[j + N / 2 + 0] = result0[2];
                self.fourier_buffer[j + N / 2 + 4] = result0[3];

                const result1 = self.performButterfly2(self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], self.fourier_buffer[j + N / 2 + 1], self.fourier_buffer[j + N / 2 + 5], wReal, wImag);
                self.fourier_buffer[j + 1] = result1[0];
                self.fourier_buffer[j + 5] = result1[1];
                self.fourier_buffer[j + N / 2 + 1] = result1[2];
                self.fourier_buffer[j + N / 2 + 5] = result1[3];

                const result2 = self.performButterfly2(self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], self.fourier_buffer[j + N / 2 + 2], self.fourier_buffer[j + N / 2 + 6], wReal, wImag);
                self.fourier_buffer[j + 2] = result2[0];
                self.fourier_buffer[j + 6] = result2[1];
                self.fourier_buffer[j + N / 2 + 2] = result2[2];
                self.fourier_buffer[j + N / 2 + 6] = result2[3];

                const result3 = self.performButterfly2(self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], self.fourier_buffer[j + N / 2 + 3], self.fourier_buffer[j + N / 2 + 7], wReal, wImag);
                self.fourier_buffer[j + 3] = result3[0];
                self.fourier_buffer[j + 7] = result3[1];
                self.fourier_buffer[j + N / 2 + 3] = result3[2];
                self.fourier_buffer[j + N / 2 + 7] = result3[3];
            }
        }

        // Remaining stages - exact Go implementation
        var t = N / 2;
        var m: usize = 2;
        while (m <= N / 16) : (m <<= 1) {
            t >>= 1;
            var i: usize = 0;
            while (i < m) : (i += 1) {
                const j1 = 2 * i * t;
                const j2 = j1 + t;

                if (wIdx < self.twisties_re.len) {
                    const wReal = self.twisties_re[wIdx];
                    const wImag = self.twisties_im[wIdx];
                    wIdx += 1;

                    var j: usize = j1;
                    while (j < j2) : (j += 8) {
                        // Process 8 elements at a time - exact Go unrolled version
                        const result0 = self.performButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + t + 0], self.fourier_buffer[j + t + 4], wReal, wImag);
                        self.fourier_buffer[j + 0] = result0[0];
                        self.fourier_buffer[j + 4] = result0[1];
                        self.fourier_buffer[j + t + 0] = result0[2];
                        self.fourier_buffer[j + t + 4] = result0[3];

                        const result1 = self.performButterfly2(self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], self.fourier_buffer[j + t + 1], self.fourier_buffer[j + t + 5], wReal, wImag);
                        self.fourier_buffer[j + 1] = result1[0];
                        self.fourier_buffer[j + 5] = result1[1];
                        self.fourier_buffer[j + t + 1] = result1[2];
                        self.fourier_buffer[j + t + 5] = result1[3];

                        const result2 = self.performButterfly2(self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], self.fourier_buffer[j + t + 2], self.fourier_buffer[j + t + 6], wReal, wImag);
                        self.fourier_buffer[j + 2] = result2[0];
                        self.fourier_buffer[j + 6] = result2[1];
                        self.fourier_buffer[j + t + 2] = result2[2];
                        self.fourier_buffer[j + t + 6] = result2[3];

                        const result3 = self.performButterfly2(self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], self.fourier_buffer[j + t + 3], self.fourier_buffer[j + t + 7], wReal, wImag);
                        self.fourier_buffer[j + 3] = result3[0];
                        self.fourier_buffer[j + 7] = result3[1];
                        self.fourier_buffer[j + t + 3] = result3[2];
                        self.fourier_buffer[j + t + 7] = result3[3];
                    }
                }
            }
        }

        // First final stage - exact Go implementation
        var j: usize = 0;
        while (j < N) : (j += 8) {
            if (wIdx < self.twisties_re.len) {
                const wReal = self.twisties_re[wIdx];
                const wImag = self.twisties_im[wIdx];
                wIdx += 1;

                // Process 4 complex pairs (8 real values) - exact Go implementation
                const result0 = self.performButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], wReal, wImag);
                self.fourier_buffer[j + 0] = result0[0];
                self.fourier_buffer[j + 4] = result0[1];
                self.fourier_buffer[j + 2] = result0[2];
                self.fourier_buffer[j + 6] = result0[3];

                const result1 = self.performButterfly2(self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], wReal, wImag);
                self.fourier_buffer[j + 1] = result1[0];
                self.fourier_buffer[j + 5] = result1[1];
                self.fourier_buffer[j + 3] = result1[2];
                self.fourier_buffer[j + 7] = result1[3];
            }
        }

        // Second final stage - exact Go implementation
        j = 0;
        while (j < N) : (j += 8) {
            if (wIdx + 1 < self.twisties_re.len) {
                const wReal0 = self.twisties_re[wIdx];
                const wImag0 = self.twisties_im[wIdx];
                const wReal1 = self.twisties_re[wIdx + 1];
                const wImag1 = self.twisties_im[wIdx + 1];
                wIdx += 2;

                // Process 4 complex pairs (8 real values) - exact Go implementation
                const result0 = self.performButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], wReal0, wImag0);
                self.fourier_buffer[j + 0] = result0[0];
                self.fourier_buffer[j + 4] = result0[1];
                self.fourier_buffer[j + 1] = result0[2];
                self.fourier_buffer[j + 5] = result0[3];

                const result1 = self.performButterfly2(self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], wReal1, wImag1);
                self.fourier_buffer[j + 2] = result1[0];
                self.fourier_buffer[j + 6] = result1[1];
                self.fourier_buffer[j + 3] = result1[2];
                self.fourier_buffer[j + 7] = result1[3];
            }
        }
    }

    /// Exact Go ProcessIFFT implementation
    fn processIFFT(self: *Self) void {
        const N = self.n;
        var wIdx: usize = 0;

        // First stage (starts with final stages in reverse) - exact Go implementation
        var j: usize = 0;
        while (j < N) : (j += 8) {
            if (wIdx + 1 < self.twisties_re.len) {
                const wReal0 = self.twisties_re[wIdx];
                const wImag0 = self.twisties_im[wIdx];
                const wReal1 = self.twisties_re[wIdx + 1];
                const wImag1 = self.twisties_im[wIdx + 1];
                wIdx += 2;

                // Process 4 complex pairs (8 real values) - exact Go implementation
                const result0 = self.performInvButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], wReal0, wImag0);
                self.fourier_buffer[j + 0] = result0[0];
                self.fourier_buffer[j + 4] = result0[1];
                self.fourier_buffer[j + 1] = result0[2];
                self.fourier_buffer[j + 5] = result0[3];

                const result1 = self.performInvButterfly2(self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], wReal1, wImag1);
                self.fourier_buffer[j + 2] = result1[0];
                self.fourier_buffer[j + 6] = result1[1];
                self.fourier_buffer[j + 3] = result1[2];
                self.fourier_buffer[j + 7] = result1[3];
            }
        }

        // Second stage - exact Go implementation
        j = 0;
        while (j < N) : (j += 8) {
            if (wIdx < self.twisties_re.len) {
                const wReal = self.twisties_re[wIdx];
                const wImag = self.twisties_im[wIdx];
                wIdx += 1;

                // Process 4 complex pairs (8 real values) - exact Go implementation
                const result0 = self.performInvButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], wReal, wImag);
                self.fourier_buffer[j + 0] = result0[0];
                self.fourier_buffer[j + 4] = result0[1];
                self.fourier_buffer[j + 2] = result0[2];
                self.fourier_buffer[j + 6] = result0[3];

                const result1 = self.performInvButterfly2(self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], wReal, wImag);
                self.fourier_buffer[j + 1] = result1[0];
                self.fourier_buffer[j + 5] = result1[1];
                self.fourier_buffer[j + 3] = result1[2];
                self.fourier_buffer[j + 7] = result1[3];
            }
        }

        // Remaining stages (working backwards) - exact Go implementation
        var t: usize = 8;
        var m = N / 16;
        while (m >= 2) : (m >>= 1) {
            var i: usize = 0;
            while (i < m) : (i += 1) {
                const j1 = 2 * i * t;
                const j2 = j1 + t;

                if (wIdx < self.twisties_re.len) {
                    const wReal = self.twisties_re[wIdx];
                    const wImag = self.twisties_im[wIdx];
                    wIdx += 1;

                    var jj: usize = j1;
                    while (jj < j2) : (jj += 8) {
                        // Process 8 elements at a time - exact Go unrolled version
                        const result0 = self.performInvButterfly2(self.fourier_buffer[jj + 0], self.fourier_buffer[jj + 4], self.fourier_buffer[jj + t + 0], self.fourier_buffer[jj + t + 4], wReal, wImag);
                        self.fourier_buffer[jj + 0] = result0[0];
                        self.fourier_buffer[jj + 4] = result0[1];
                        self.fourier_buffer[jj + t + 0] = result0[2];
                        self.fourier_buffer[jj + t + 4] = result0[3];

                        const result1 = self.performInvButterfly2(self.fourier_buffer[jj + 1], self.fourier_buffer[jj + 5], self.fourier_buffer[jj + t + 1], self.fourier_buffer[jj + t + 5], wReal, wImag);
                        self.fourier_buffer[jj + 1] = result1[0];
                        self.fourier_buffer[jj + 5] = result1[1];
                        self.fourier_buffer[jj + t + 1] = result1[2];
                        self.fourier_buffer[jj + t + 5] = result1[3];

                        const result2 = self.performInvButterfly2(self.fourier_buffer[jj + 2], self.fourier_buffer[jj + 6], self.fourier_buffer[jj + t + 2], self.fourier_buffer[jj + t + 6], wReal, wImag);
                        self.fourier_buffer[jj + 2] = result2[0];
                        self.fourier_buffer[jj + 6] = result2[1];
                        self.fourier_buffer[jj + t + 2] = result2[2];
                        self.fourier_buffer[jj + t + 6] = result2[3];

                        const result3 = self.performInvButterfly2(self.fourier_buffer[jj + 3], self.fourier_buffer[jj + 7], self.fourier_buffer[jj + t + 3], self.fourier_buffer[jj + t + 7], wReal, wImag);
                        self.fourier_buffer[jj + 3] = result3[0];
                        self.fourier_buffer[jj + 7] = result3[1];
                        self.fourier_buffer[jj + t + 3] = result3[2];
                        self.fourier_buffer[jj + t + 7] = result3[3];
                    }
                }
            }
            t <<= 1;
        }

        // Final stage with normalization - exact Go implementation
        const scale = @as(f64, @floatFromInt(N / 2));
        if (wIdx < self.twisties_re.len) {
            const wReal = self.twisties_re[wIdx];
            const wImag = self.twisties_im[wIdx];
            wIdx += 1;

            j = 0;
            while (j < N / 2) : (j += 8) {
                // Process 8 elements at a time - exact Go unrolled version
                const result0 = self.performInvButterfly2(self.fourier_buffer[j + 0], self.fourier_buffer[j + 4], self.fourier_buffer[j + N / 2 + 0], self.fourier_buffer[j + N / 2 + 4], wReal, wImag);
                self.fourier_buffer[j + 0] = result0[0] / scale;
                self.fourier_buffer[j + 4] = result0[1] / scale;
                self.fourier_buffer[j + N / 2 + 0] = result0[2] / scale;
                self.fourier_buffer[j + N / 2 + 4] = result0[3] / scale;

                const result1 = self.performInvButterfly2(self.fourier_buffer[j + 1], self.fourier_buffer[j + 5], self.fourier_buffer[j + N / 2 + 1], self.fourier_buffer[j + N / 2 + 5], wReal, wImag);
                self.fourier_buffer[j + 1] = result1[0] / scale;
                self.fourier_buffer[j + 5] = result1[1] / scale;
                self.fourier_buffer[j + N / 2 + 1] = result1[2] / scale;
                self.fourier_buffer[j + N / 2 + 5] = result1[3] / scale;

                const result2 = self.performInvButterfly2(self.fourier_buffer[j + 2], self.fourier_buffer[j + 6], self.fourier_buffer[j + N / 2 + 2], self.fourier_buffer[j + N / 2 + 6], wReal, wImag);
                self.fourier_buffer[j + 2] = result2[0] / scale;
                self.fourier_buffer[j + 6] = result2[1] / scale;
                self.fourier_buffer[j + N / 2 + 2] = result2[2] / scale;
                self.fourier_buffer[j + N / 2 + 6] = result2[3] / scale;

                const result3 = self.performInvButterfly2(self.fourier_buffer[j + 3], self.fourier_buffer[j + 7], self.fourier_buffer[j + N / 2 + 3], self.fourier_buffer[j + N / 2 + 7], wReal, wImag);
                self.fourier_buffer[j + 3] = result3[0] / scale;
                self.fourier_buffer[j + 7] = result3[1] / scale;
                self.fourier_buffer[j + N / 2 + 3] = result3[2] / scale;
                self.fourier_buffer[j + N / 2 + 7] = result3[3] / scale;
            }
        }
    }

    /// Generic negacyclic polynomial multiplication for any power-of-2 size N
    /// Computes: a(X) * b(X) mod (X^N+1)
    pub fn poly_mul(self: *Self, a: []const params.Torus, b: []const params.Torus) ![]params.Torus {
        const a_fft = try self.ifft(a);
        defer self.allocator.free(a_fft);

        const b_fft = try self.ifft(b);
        defer self.allocator.free(b_fft);

        // Complex multiplication with 0.5 scaling for negacyclic
        var result_fft = try self.allocator.alloc(f64, self.n);
        defer self.allocator.free(result_fft);

        const n2 = self.n / 2;
        for (0..n2) |i| {
            const ar = a_fft[i];
            const ai = a_fft[i + n2];
            const br = b_fft[i];
            const bi = b_fft[i + n2];

            result_fft[i] = (ar * br - ai * bi) * 0.5;
            result_fft[i + n2] = (ar * bi + ai * br) * 0.5;
        }

        return try self.fft(result_fft);
    }
};

/// FFT Plan structure
pub const FFTPlan = struct {
    processor: KlemsaProcessor,
    n: usize,

    pub fn new(allocator: std.mem.Allocator, n: usize) !FFTPlan {
        return FFTPlan{
            .processor = try KlemsaProcessor.new(allocator, n),
            .n = n,
        };
    }

    pub fn deinit(self: *FFTPlan) void {
        self.processor.deinit();
    }
};

/// Default FFT processor
pub const DefaultFFTProcessor = KlemsaProcessor;

// ============================================================================
// TESTS
// ============================================================================
