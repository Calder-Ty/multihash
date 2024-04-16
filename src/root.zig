const std = @import("std");
const testing = std.testing;

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
};

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
