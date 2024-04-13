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
};

test "encode" {
    try std.testing.expectEqual(@as(u63, 1), (try UnsignedVarInt.encode(&[_]u8{0x1}))._inner);
    try std.testing.expectEqual(@as(u63, 127), (try UnsignedVarInt.encode(&[_]u8{0x7f}))._inner);
    try std.testing.expectEqual(@as(u63, 128), (try UnsignedVarInt.encode(&[_]u8{ 0x80, 0x01 }))._inner);
    try std.testing.expectEqual(@as(u63, 255), (try UnsignedVarInt.encode(&[_]u8{ 0xff, 0x01 }))._inner);
    try std.testing.expectEqual(@as(u63, 300), (try UnsignedVarInt.encode(&[_]u8{ 0xac, 0x02 }))._inner);
    try std.testing.expectEqual(@as(u63, 16384), (try UnsignedVarInt.encode(&[_]u8{ 0x80, 0x80, 0x01 }))._inner);
}
