# Multihash
A Library for creating, serializing and deserializing [multihashes](https://multiformats.io/multihash/).

# Contents:

## multihash

`multihash` is the package for creating, serializing and deserializing multihashes. Exposes two structs:
`Multihash`, and `UnsignedVarInt`.

### Examples:
```zig
// Bytes for MultiHash
const input = [_]u8{
    0x12, 0x20, 0x41, 0xdd, 0x7b, 0x64, 0x43, 0x54, 0x2e, 0x75, 0x70,
    0x1a, 0xa9, 0x8a, 0x0c, 0x23, 0x59, 0x51, 0xa2, 0x8a, 0x0d, 0x85,
    0x1b, 0x11, 0x56, 0x4d, 0x20, 0x02, 0x2a, 0xb1, 0x1d, 0x25, 0x89,
    0xa8,
};

const result = try Multihash.deserialize(&input, testing.allocator);
defer result.deinit();
```

## pkghash

`pkghash` is a tool for generating hashes for zig packages. It is forked from the pkghash utility
in [zap](https://github.com/zigzap/zap). The main purpose of forking was to add the ability to
specify the exact files that would be included in the hash.

### usage
```
Usage: pkghash [options]

Options: 
  -h --help           Print this help and exit.
  -g --git            Use git ls-files
  -f --file <file list>           List Files to include in hash. Directories are included recursively. Does not work with `-g`

Sub-options: 
  --allow-directory : calc hash even if no build.zig is present
                      applies in no-git mode only

Sub-options for --git: 
  --tag=<tag>          : specify git tag to use in template
                         defaults to tag pointing to HEAD
  --template=<file.md> : specify markdown template to render
```

### Example:
```bash
pkghash -f LICENSE src/* README.md build.zig build.zig.zon
```

# Acknowledgments
Portion of this code use code licensed by others:

main.zig: Copyright (c) 2023 Rene Schallner, MIT License

