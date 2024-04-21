const std = @import("std");
const testing = std.testing;

/// A representation of the Hash
pub const Multihash = struct {
    hash_func: UnsignedVarInt,
    digest_size: UnsignedVarInt,
    digest: std.ArrayList(u8),

    /// Decodes the struct to the hash
    pub fn decode(self: Multihash, allocator: std.mem.Allocator) !std.ArrayList(u8) {
        const total_size = self.hash_func.minimal_size() + self.digest_size.minimal_size() + self.digest.len();
        var result = try std.ArrayListAligned(u8).initCapacity(allocator, total_size);
        const func_bytes = self.hash_func.decode()[0..self.hash_func.minimal_size()];
        const size_bytes = self.digest_size.decode()[0..self.digest_size.minimal_size()];
        while (func_bytes) |byte| {
            result.append(byte);
        }
        while (size_bytes) |byte| {
            result.append(byte);
        }
        try result.appendSlice(self.digest.items);
        return result;
    }

    pub fn encode(bytes: []const u8, allocator: std.mem.Allocator) !Multihash {
        var offset: usize = 0;
        const hash_func = try UnsignedVarInt.encode(bytes[offset .. offset + 9]);
        offset = hash_func.minimal_size();
        const hash_size = try UnsignedVarInt.encode(bytes[offset .. offset + 9]);
        offset += hash_size.minimal_size();
        var hash = std.ArrayList(u8).init(allocator);
        try hash.appendSlice(bytes[offset .. offset + hash_size._inner]);

        return .{ .hash_func = hash_func, .digest_size = hash_size, .digest = hash };
    }

    pub fn deinit(self: Multihash) void {
        self.digest.deinit();
    }

    test "enocde" {
        const input = [_]u8{ 0x12, 0x20, 0x41, 0xdd, 0x7b, 0x64, 0x43, 0x54, 0x2e, 0x75, 0x70, 0x1a, 0xa9, 0x8a, 0x0c, 0x23, 0x59, 0x51, 0xa2, 0x8a, 0x0d, 0x85, 0x1b, 0x11, 0x56, 0x4d, 0x20, 0x02, 0x2a, 0xb1, 0x1d, 0x25, 0x89, 0xa8 };
        var hash = std.ArrayList(u8).init(std.testing.allocator);

        try hash.appendSlice("\x41\xdd\x7b\x64\x43\x54\x2e\x75\x70\x1a\xa9\x8a\x0c\x23\x59\x51\xa2\x8a\x0d\x85\x1b\x11\x56\x4d\x20\x02\x2a\xb1\x1d\x25\x89\xa8");
        const m: Multihash = .{
            .hash_func = UnsignedVarInt{ ._inner = 0x12 },
            .digest_size = UnsignedVarInt{ ._inner = 0x20 },
            .digest = hash,
        };
        defer m.deinit();
        const result = try Multihash.encode(&input, testing.allocator);
        defer result.deinit();
        try std.testing.expectEqualDeep(m, result);
    }
};

/// Variable Sized Integer. Required for use in the Multihash spec.
/// Based off of the schema here https://github.com/multiformats/unsigned-varint
const UnsignedVarInt = struct {
    const CONT_BIT_MASK: u8 = 0b0111_1111;
    // Per the specification, only 7 bits of the value are used
    // to encode the value, the 8th bit is use to flag a  continuation
    // bit.
    const BASE_SHIFT_VALUE: u3 = 7;
    // The VarInt spec limits the integer size to 9 bytes, for realistic space limits
    // This means that the maximum encodable value is a u63 (The varint spec uses 1 bit
    // to encode continuations bits)
    _inner: u63,

    /// Encode Bytes into a UnsinedVarInt
    pub fn encode(bytes: []const u8) !UnsignedVarInt {
        if (bytes.len > 9) {
            return error.TooManyBytes;
        }
        var result: u64 = 0;
        for (bytes, 0..) |byte, i| {
            const masked: u64 = CONT_BIT_MASK & byte;
            result |= masked << (BASE_SHIFT_VALUE * @as(u6, @truncate(i)));
            // Check if Continuation Bit is set
            if (byte & ~CONT_BIT_MASK == 0) {
                break;
            }
        }
        // SAFTEY: We can truncate the result to 63 bits because we only shifted
        // at a max 9 * 7 = 63 bits.
        return .{ ._inner = @truncate(result) };
    }

    /// Give the minimal number of bytes need to represent
    pub fn minimal_size(self: UnsignedVarInt) u8 {
        inline for (1..9) |i| {
            if (self._inner < (1 << 7 * i)) {
                return i;
            }
        }
        return 9;
    }

    fn decode(self: UnsignedVarInt) [9]?u8 {
        var buffer = [_]?u8{null} ** 9;
        const max_len = self.minimal_size();
        for (0..9) |i| {
            // SAFTEY: We can truncate here as `i` will never be greater than 9
            const byte: u8 = @truncate(self._inner >> @as(u6, @truncate(i)) * 7);
            if (i == max_len - 1) {
                buffer[i] = byte;
            } else {
                buffer[i] = byte | 0b1000_0000;
            }
        }
        return buffer;
    }

    test "encode" {
        try std.testing.expectEqual(
            @as(u63, 1),
            (try UnsignedVarInt.encode(&[_]u8{0x1}))._inner,
        );
        try std.testing.expectEqual(
            @as(u63, 127),
            (try UnsignedVarInt.encode(&[_]u8{0x7f}))._inner,
        );
        try std.testing.expectEqual(
            @as(u63, 128),
            (try UnsignedVarInt.encode(&[_]u8{ 0x80, 0x01 }))._inner,
        );
        try std.testing.expectEqual(
            @as(u63, 255),
            (try UnsignedVarInt.encode(&[_]u8{ 0xff, 0x01 }))._inner,
        );
        try std.testing.expectEqual(
            @as(u63, 300),
            (try UnsignedVarInt.encode(&[_]u8{ 0xac, 0x02 }))._inner,
        );
        try std.testing.expectEqual(
            @as(u63, 16384),
            (try UnsignedVarInt.encode(&[_]u8{ 0x80, 0x80, 0x01 }))._inner,
        );
    }

    test "mimimal bytes" {
        try std.testing.expectEqual(1, (UnsignedVarInt{ ._inner = 1 }).minimal_size());
        try std.testing.expectEqual(3, (UnsignedVarInt{ ._inner = 16384 }).minimal_size());
        try std.testing.expectEqual(9, (UnsignedVarInt{ ._inner = 1 << 62 }).minimal_size());
    }

    test "decode" {
        const int = UnsignedVarInt{ ._inner = 0x1 };
        try std.testing.expectEqualSlices(
            ?u8,
            &[_]?u8{0x1},
            int.decode()[0..int.minimal_size()],
        );
        const int2 = UnsignedVarInt{ ._inner = 16384 };
        try std.testing.expectEqualSlices(
            ?u8,
            &[_]?u8{
                0x80,
                0x80,
                0x01,
            },
            int2.decode()[0..int2.minimal_size()],
        );
    }
};

test {
    testing.refAllDecls(@This());
}
