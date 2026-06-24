const std = @import("std");
const Io = std.Io;
const hash = @import("hash.zig");

const Algorithm = hash.Algorithm;
const OutputFormat = enum { hex, base64, binary };

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(allocator);

    var algo: Algorithm = .sha256;
    var format: OutputFormat = .hex;
    var files: std.ArrayListUnmanaged([]const u8) = .empty;
    var strings: std.ArrayListUnmanaged([]const u8) = .empty;
    var stdin_flag = false;
    var list_flag = false;
    var tag_flag = false;
    var check_quiet = false;
    var check_status = false;
    var check_file: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg: []const u8 = args[i];
        if (std.mem.startsWith(u8, arg, "-")) {
            if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--algorithm")) {
                i += 1;
                if (i >= args.len) return error.MissingAlgorithm;
                algo = Algorithm.parse(args[i]) orelse {
                    std.debug.print("unknown algorithm: {s}\n", .{args[i]});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
                i += 1;
                if (i >= args.len) return error.MissingFile;
                try files.append(allocator, args[i]);
            } else if (std.mem.eql(u8, arg, "--stdin")) {
                stdin_flag = true;
            } else if (std.mem.eql(u8, arg, "--format")) {
                i += 1;
                if (i >= args.len) return error.MissingFormat;
                if (std.ascii.eqlIgnoreCase(args[i], "hex")) {
                    format = .hex;
                } else if (std.ascii.eqlIgnoreCase(args[i], "base64")) {
                    format = .base64;
                } else {
                    std.debug.print("unknown format: {s} (use hex or base64)\n", .{args[i]});
                    std.process.exit(1);
                }
            } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--list")) {
                list_flag = true;
            } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--check")) {
                i += 1;
                if (i >= args.len) return error.MissingCheckFile;
                check_file = args[i];
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tag")) {
                tag_flag = true;
            } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--binary")) {
                format = .binary;
            } else if (std.mem.eql(u8, arg, "--quiet")) {
                check_quiet = true;
            } else if (std.mem.eql(u8, arg, "--status")) {
                check_status = true;
            } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                printHelp(io);
                return;
            } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
                std.debug.print("bhash 0.1.0\n", .{});
                return;
            } else {
                std.debug.print("unknown flag: {s}\n", .{arg});
                std.process.exit(1);
            }
        } else {
            try strings.append(allocator, arg);
        }
    }

    if (format == .binary and tag_flag) {
        std.debug.print("error: --binary and --tag are mutually exclusive\n", .{});
        std.process.exit(1);
    }

    if (list_flag) {
        std.debug.print("Available algorithms:\n", .{});
        for (Algorithm.all()) |a| {
            std.debug.print("  {s:20}  {} bytes\n", .{ a.name(), a.outputSize() });
        }
        return;
    }

    if (check_file) |cf| {
        try verifyChecksums(allocator, io, cf, algo, check_quiet, check_status);
        return;
    }

    if (tag_flag) {
        if (strings.items.len > 0) {
            for (strings.items) |s| {
                const h = try algo.hash(s, allocator);
                defer allocator.free(h);
                const out = formatHash(h, format, allocator);
                defer allocator.free(out);
                try stdoutPrint(io, "{s} (\"{s}\") = {s}\n", .{ algoNameUpper(algo), s, out });
            }
            return;
        }
        if (files.items.len > 0) {
            for (files.items) |path| {
                const data = readFile(allocator, io, path) catch |err| {
                    try stderrPrint(io, "{s}: {s}\n", .{ path, @errorName(err) });
                    std.process.exit(1);
                };
                defer allocator.free(data);
                const h = try algo.hash(data, allocator);
                defer allocator.free(h);
                const out = formatHash(h, format, allocator);
                defer allocator.free(out);
                try stdoutPrint(io, "{s} ({s}) = {s}\n", .{ algoNameUpper(algo), path, out });
            }
            return;
        }
    }

    if (strings.items.len > 0) {
        for (strings.items) |s| {
            const h = try algo.hash(s, allocator);
            defer allocator.free(h);
            const out = formatHash(h, format, allocator);
            defer allocator.free(out);
            if (format == .binary) {
                try stdoutWrite(io, h);
            } else {
                try stdoutPrint(io, "{s}  \"{s}\"\n", .{ out, s });
            }
        }
        return;
    }

    if (files.items.len > 0) {
        for (files.items) |path| {
            const data = readFile(allocator, io, path) catch |err| {
                try stderrPrint(io, "{s}: {s}\n", .{ path, @errorName(err) });
                std.process.exit(1);
            };
            defer allocator.free(data);
            const h = try algo.hash(data, allocator);
            defer allocator.free(h);
            const out = formatHash(h, format, allocator);
            defer allocator.free(out);
            if (format == .binary) {
                try stdoutWrite(io, h);
            } else {
                try stdoutPrint(io, "{s}  {s}\n", .{ out, path });
            }
        }
        return;
    }

    const stdin_is_tty = Io.File.isTty(.stdin(), io) catch false;
    if (stdin_flag or !stdin_is_tty) {
    var buf: [8192]u8 = undefined;
    var reader = Io.File.reader(.stdin(), io, &buf);
    const data = reader.interface.allocRemaining(allocator, Io.Limit.limited(std.math.maxInt(usize))) catch |err| {
            try stderrPrint(io, "stdin: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer allocator.free(data);
        if (data.len == 0 and stdin_flag) return;
        const h = try algo.hash(data, allocator);
        defer allocator.free(h);
        const out = formatHash(h, format, allocator);
        defer allocator.free(out);
        if (format == .binary) {
            try stdoutWrite(io, h);
            try stdoutWrite(io, "\n");
        } else {
            try stdoutPrint(io, "{s}\n", .{out});
        }
    } else {
        try stderrPrint(io, "No input provided. Pipe data, pass strings/files, or use --help.\n", .{});
        std.process.exit(1);
    }
}

fn algoNameUpper(a: Algorithm) []const u8 {
    return switch (a) {
        .fnv32 => "FNV32",
        .fnv64 => "FNV64",
        .fnv128 => "FNV128",
        .sha1 => "SHA1",
        .sha224 => "SHA224",
        .sha256 => "SHA256",
        .sha384 => "SHA384",
        .sha512 => "SHA512",
        .sha512_224 => "SHA512-224",
        .sha512_256 => "SHA512-256",
        .md5 => "MD5",
        .blake2b => "BLAKE2B",
        .blake2b_256 => "BLAKE2B-256",
        .blake2b_384 => "BLAKE2B-384",
        .blake2b_512 => "BLAKE2B-512",
        .blake2s => "BLAKE2S",
        .blake2s_256 => "BLAKE2S-256",
        .blake3 => "BLAKE3",
        .crc32 => "CRC32",
        .crc32c => "CRC32C",
        .crc64_ecma => "CRC64-ECMA",
        .crc64_iso => "CRC64-ISO",
        .xxh32 => "XXH32",
        .xxh64 => "XXH64",
        .xxh3_64 => "XXH3-64",
        .xxh3_128 => "XXH3-128",
    };
}

fn stdoutWrite(io: Io, bytes: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var writer = Io.File.Writer.init(.stdout(), io, &buf);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn stdoutPrint(io: Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var writer = Io.File.Writer.init(.stdout(), io, &buf);
    try writer.interface.print(fmt, args);
    try writer.interface.flush();
}

fn stderrPrint(io: Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var writer = Io.File.Writer.init(.stderr(), io, &buf);
    try writer.interface.print(fmt, args);
    try writer.interface.flush();
}

fn printHelp(io: Io) void {
    var buf: [4096]u8 = undefined;
    var writer = Io.File.Writer.init(.stdout(), io, &buf);
    writer.interface.print(
        \\bhash - Universal hash tool — multiple algorithms, strings, files, and stdin
        \\
        \\Usage: bhash [OPTIONS] [STRINGS]...
        \\
        \\Modes:
        \\  Hash strings:   bhash -a sha256 "hello" "world"
        \\  Hash files:     bhash -a md5 -f file1.bin -f file2.bin
        \\  Hash stdin:     echo "data" | bhash -a blake3
        \\  Verify sums:    bhash -a sha256 --check SHA256SUMS
        \\  Tagged output:  bhash -a sha256 --tag -f file.bin
        \\  List algos:     bhash --list
        \\
        \\Options:
        \\  -a, --algorithm   Hash algorithm (default: sha256)
        \\  -f, --file        File(s) to hash
        \\      --stdin       Read from stdin explicitly
        \\      --format      Output format: hex (default) or base64
        \\  -b, --binary      Output raw binary bytes
        \\  -t, --tag         BSD-style tagged output (ALGO (file) = hash)
        \\  -l, --list        List all available algorithms
        \\  -c, --check       Verify checksums from a sums-file
        \\      --quiet       In --check mode, only print summary
        \\      --status      In --check mode, suppress all output (exit only)
        \\  -h, --help        Print help
        \\  -V, --version     Print version
        \\
    , .{}) catch {};
    writer.interface.flush() catch {};
}

fn readFile(allocator: std.mem.Allocator, io: Io, path: []const u8) ![]u8 {
    const file = try Io.Dir.openFile(.cwd(), io, path, .{ .mode = .read_only });
    defer file.close(io);
    var buf: [8192]u8 = undefined;
    var reader = Io.File.reader(file, io, &buf);
    return reader.interface.allocRemaining(allocator, Io.Limit.limited(std.math.maxInt(usize)));
}

fn formatHash(h: []const u8, fmt: OutputFormat, allocator: std.mem.Allocator) []u8 {
    switch (fmt) {
        .hex => return hexEncode(allocator, h),
        .base64 => {
            const encoder = std.base64.standard.Encoder;
            const encoded = allocator.alloc(u8, encoder.calcSize(h.len)) catch @panic("OOM");
            _ = encoder.encode(encoded, h);
            return encoded;
        },
        .binary => return allocator.dupe(u8, h) catch @panic("OOM"),
    }
}

fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) []u8 {
    const hex_chars = "0123456789abcdef";
    const result = allocator.alloc(u8, bytes.len * 2) catch @panic("OOM");
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0xf];
    }
    return result;
}

fn verifyChecksums(allocator: std.mem.Allocator, io: Io, path: []const u8, algo: Algorithm, quiet: bool, status: bool) !void {
    const data = readFile(allocator, io, path) catch |err| {
        std.debug.print("{s}: {s}\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer allocator.free(data);

    var ok: u64 = 0;
    var failed: u64 = 0;

    var lines = std.mem.splitScalar(u8, data, '\n');
    var line_no: usize = 0;

    while (lines.next()) |line_raw| {
        line_no += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        const sep = std.mem.indexOfAny(u8, line, " \t") orelse {
            if (!status) try stderrPrint(io, "{s}:{}: malformed line\n", .{ path, line_no });
            continue;
        };
        const expected_hex = line[0..sep];
        const remaining = std.mem.trim(u8, line[sep + 1 ..], " \t");
        // Strip binary marker '*' if present (sha256sum compat)
        const filename = if (remaining.len > 0 and remaining[0] == '*') remaining[1..] else remaining;

        const file_data = readFile(allocator, io, filename) catch |err| {
            if (!quiet and !status) try stdoutPrint(io, "{s}: FAILED ({s})\n", .{ filename, @errorName(err) });
            failed += 1;
            continue;
        };
        defer allocator.free(file_data);

        const actual = try algo.hash(file_data, allocator);
        defer allocator.free(actual);

        const actual_hex = hexEncode(allocator, actual);
        defer allocator.free(actual_hex);

        if (std.ascii.eqlIgnoreCase(actual_hex, expected_hex)) {
            if (!quiet and !status) try stdoutPrint(io, "{s}: OK\n", .{filename});
            ok += 1;
        } else {
            if (!quiet and !status) try stdoutPrint(io, "{s}: FAILED\n", .{filename});
            failed += 1;
        }
    }

    if (!status) {
        try stderrPrint(io, "\n{} OK, {} FAILED\n", .{ ok, failed });
    }
    if (failed > 0) std.process.exit(1);
}
