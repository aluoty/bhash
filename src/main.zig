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
    var check_mode = false;
    var check_file: ?[]const u8 = null;
    var check_quiet = false;
    var check_status = false;
    var check_ignore_missing = false;
    var check_warn = false;
    var check_strict = false;
    var hmac_key: ?[]const u8 = null;

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
                check_mode = true;
                if (i + 1 < args.len and !std.mem.startsWith(u8, args[i + 1], "-")) {
                    i += 1;
                    check_file = args[i];
                }
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tag")) {
                tag_flag = true;
            } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--binary")) {
                format = .binary;
            } else if (std.mem.eql(u8, arg, "--quiet") or std.mem.eql(u8, arg, "--silent")) {
                check_quiet = true;
            } else if (std.mem.eql(u8, arg, "--status")) {
                check_status = true;
            } else if (std.mem.eql(u8, arg, "--ignore-missing")) {
                check_ignore_missing = true;
            } else if (std.mem.eql(u8, arg, "--warn")) {
                check_warn = true;
            } else if (std.mem.eql(u8, arg, "--strict")) {
                check_strict = true;
            } else if (std.mem.eql(u8, arg, "--hmac")) {
                i += 1;
                if (i >= args.len) return error.MissingKey;
                hmac_key = args[i];
            } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                printHelp(io);
                return;
            } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "--V")) {
                std.debug.print("bhash {s}\n", .{@import("build_config").version});
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
        listAlgorithms(io);
        return;
    }

    if (check_mode) {
        const cf = check_file orelse if (strings.items.len > 0) strings.items[0] else null;
        try verifyChecksums(allocator, io, cf, algo, check_quiet, check_status, check_ignore_missing, check_warn, check_strict);
        return;
    }

    if (tag_flag) {
        const base_name = algoNameUpper(algo);
        var tag_buf: [64]u8 = undefined;
        const tag_name = if (hmac_key != null) blk: {
            const len = 5 + base_name.len;
            @memcpy(tag_buf[0..5], "HMAC-");
            @memcpy(tag_buf[5..len], base_name);
            break :blk tag_buf[0..len];
        } else base_name;

        if (strings.items.len > 0) {
            for (strings.items) |s| {
                const out = try computeHash(algo, s, hmac_key, allocator);
                defer allocator.free(out);
                const formatted = formatIfNeeded(out, format, allocator);
                defer allocator.free(formatted);
                try stdoutPrint(io, "{s} (\"{s}\") = {s}\n", .{ tag_name, s, formatted });
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
                const out = try computeHash(algo, data, hmac_key, allocator);
                defer allocator.free(out);
                const formatted = formatIfNeeded(out, format, allocator);
                defer allocator.free(formatted);
                try stdoutPrint(io, "{s} ({s}) = {s}\n", .{ tag_name, path, formatted });
            }
            return;
        }
    }

    if (strings.items.len > 0) {
        for (strings.items) |s| {
            const h = try computeHash(algo, s, hmac_key, allocator);
            defer allocator.free(h);
            if (format == .binary) {
                try stdoutWrite(io, h);
            } else {
                const formatted = formatHash(h, format, allocator);
                defer allocator.free(formatted);
                try stdoutPrint(io, "{s}  \"{s}\"\n", .{ formatted, s });
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
            const h = try computeHash(algo, data, hmac_key, allocator);
            defer allocator.free(h);
            if (format == .binary) {
                try stdoutWrite(io, h);
            } else {
                const formatted = formatHash(h, format, allocator);
                defer allocator.free(formatted);
                try stdoutPrint(io, "{s}  {s}\n", .{ formatted, path });
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
        const h = try computeHash(algo, data, hmac_key, allocator);
        defer allocator.free(h);
        if (format == .binary) {
            try stdoutWrite(io, h);
        } else {
            const formatted = formatHash(h, format, allocator);
            defer allocator.free(formatted);
            try stdoutPrint(io, "{s}\n", .{formatted});
        }
    } else {
        try stderrPrint(io, "No input provided. Pipe data, pass strings/files, or use --help.\n", .{});
        std.process.exit(1);
    }
}

fn computeHash(algo: Algorithm, data: []const u8, key: ?[]const u8, allocator: std.mem.Allocator) ![]u8 {
    if (key) |k| {
        return algo.hmac(data, k, allocator) catch |err| switch (err) {
            error.HmacNotSupported => {
                std.debug.print("error: {s} does not support HMAC (use a cryptographic hash like sha256)\n", .{algo.name()});
                std.process.exit(1);
            },
            else => |e| return e,
        };
    }
    return try algo.hash(data, allocator);
}

fn formatIfNeeded(h: []const u8, fmt: OutputFormat, allocator: std.mem.Allocator) []u8 {
    if (fmt == .binary) {
        return allocator.dupe(u8, h) catch @panic("OOM");
    }
    return formatHash(h, fmt, allocator);
}

fn algoNameUpper(algo: Algorithm) []const u8 {
    return switch (algo) {
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

fn listAlgorithms(io: Io) void {
    var buf: [4096]u8 = undefined;
    var writer = Io.File.Writer.init(.stdout(), io, &buf);
    writer.interface.print("Available algorithms:\n", .{}) catch {};
    for (Algorithm.all()) |a| {
        writer.interface.print("  {s:20}  {} bytes\n", .{ a.name(), a.outputSize() }) catch {};
    }
    writer.interface.flush() catch {};
}

fn printHelp(io: Io) void {
    var buf: [4096]u8 = undefined;
    var writer = Io.File.Writer.init(.stdout(), io, &buf);
    writer.interface.print(
        \\bhash {s} — Universal hash tool — 26 algorithms, strings, files, stdin
    , .{@import("build_config").version}) catch {};
    writer.interface.print(
        \\
        \\Usage: bhash [OPTIONS] [STRINGS]...
        \\
        \\Modes:
        \\  Hash strings:   bhash -a sha256 "hello" "world"
        \\  Hash files:     bhash -a md5 -f file1.bin -f file2.bin
        \\  Hash stdin:     echo "data" | bhash -a blake3
        \\  Verify sums:    bhash -a sha256 -c SHA256SUMS
        \\  Verify stdin:   bhash -a sha256 -c < SHA256SUMS
        \\  Tagged output:  bhash -a sha256 --tag -f file.bin
        \\  HMAC auth:      bhash -a sha256 --hmac "secret" "message"
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
        \\  -c, --check       Verify checksums from a sums-file (stdin if no file)
        \\      --quiet       In --check mode, only print summary
        \\      --silent      Alias for --quiet
        \\      --status      In --check mode, suppress all output (exit only)
        \\      --ignore-missing  Don't fail on missing files in --check mode
        \\      --warn        Warn about malformed checksum lines
        \\      --strict      Exit non-zero on malformed checksum lines
        \\      --hmac <key>  Compute HMAC with given key
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

fn readStdin(allocator: std.mem.Allocator, io: Io) ![]u8 {
    var buf: [8192]u8 = undefined;
    var reader = Io.File.reader(.stdin(), io, &buf);
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

fn verifyChecksums(allocator: std.mem.Allocator, io: Io, path: ?[]const u8, algo: Algorithm, quiet: bool, status: bool, ignore_missing: bool, warn: bool, strict: bool) !void {
    const data: []u8 = if (path) |p|
        readFile(allocator, io, p) catch |err| {
            std.debug.print("{s}: {s}\n", .{ p, @errorName(err) });
            std.process.exit(1);
        }
    else
        readStdin(allocator, io) catch |err| {
            try stderrPrint(io, "stdin: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    defer allocator.free(data);

    var ok: u64 = 0;
    var failed: u64 = 0;
    var missing: u64 = 0;
    var malformed: u64 = 0;
    const source_name: []const u8 = path orelse "(stdin)";

    var lines = std.mem.splitScalar(u8, data, '\n');
    var line_no: usize = 0;

    while (lines.next()) |line_raw| {
        line_no += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        const sep = std.mem.indexOfAny(u8, line, " \t") orelse {
            if (warn) try stderrPrint(io, "{s}:{}: malformed line\n", .{ source_name, line_no });
            malformed += 1;
            if (strict) {
                if (!status and !quiet) try stdoutPrint(io, "{s}:{}: FAILED (malformed)\n", .{ source_name, line_no });
                failed += 1;
            }
            continue;
        };
        const expected_hex = line[0..sep];
        const remaining = std.mem.trim(u8, line[sep + 1 ..], " \t");
        const filename = if (remaining.len > 0 and remaining[0] == '*') remaining[1..] else remaining;

        const file_data = readFile(allocator, io, filename) catch |err| {
            if (ignore_missing) {
                missing += 1;
                continue;
            }
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
        if (malformed > 0 and warn) {
            try stderrPrint(io, "\n{} line(s) malformed\n", .{malformed});
        }
        try stderrPrint(io, "\n{} OK, {} FAILED", .{ ok, failed });
        if (ignore_missing and missing > 0) {
            try stderrPrint(io, ", {} MISSING", .{missing});
        }
        try stderrPrint(io, "\n", .{});
    }
    if (failed > 0 or (strict and malformed > 0)) std.process.exit(1);
}
