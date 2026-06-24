const std = @import("std");

fn writeLittleInt(comptime T: type, buf: []u8, value: T) void {
    const size: comptime_int = @divExact(@typeInfo(T).int.bits, 8);
    std.mem.writeInt(T, @as(*[size]u8, @ptrCast(buf.ptr)), value, .little);
}

fn readLittleInt(comptime T: type, bytes: []const u8) T {
    const size: comptime_int = @divExact(@typeInfo(T).int.bits, 8);
    return std.mem.readInt(T, @as(*const [size]u8, @ptrCast(bytes.ptr)), .little);
}

pub const Algorithm = enum {
    fnv32,
    fnv64,
    fnv128,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
    md5,
    blake2b,
    blake2b_256,
    blake2b_384,
    blake2b_512,
    blake2s,
    blake2s_256,
    blake3,
    crc32,
    crc32c,
    crc64_ecma,
    crc64_iso,
    xxh32,
    xxh64,
    xxh3_64,
    xxh3_128,

    pub fn name(self: Algorithm) []const u8 {
        return switch (self) {
            .fnv32 => "fnv32",
            .fnv64 => "fnv64",
            .fnv128 => "fnv128",
            .sha1 => "sha1",
            .sha224 => "sha224",
            .sha256 => "sha256",
            .sha384 => "sha384",
            .sha512 => "sha512",
            .sha512_224 => "sha512-224",
            .sha512_256 => "sha512-256",
            .md5 => "md5",
            .blake2b => "blake2b",
            .blake2b_256 => "blake2b-256",
            .blake2b_384 => "blake2b-384",
            .blake2b_512 => "blake2b-512",
            .blake2s => "blake2s",
            .blake2s_256 => "blake2s-256",
            .blake3 => "blake3",
            .crc32 => "crc32",
            .crc32c => "crc32c",
            .crc64_ecma => "crc64-ecma",
            .crc64_iso => "crc64-iso",
            .xxh32 => "xxh32",
            .xxh64 => "xxh64",
            .xxh3_64 => "xxh3-64",
            .xxh3_128 => "xxh3-128",
        };
    }

    pub fn outputSize(self: Algorithm) usize {
        return switch (self) {
            .fnv32 => 4,
            .fnv64 => 8,
            .fnv128 => 16,
            .sha1 => 20,
            .sha224 => 28,
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
            .sha512_224 => 28,
            .sha512_256 => 32,
            .md5 => 16,
            .blake2b => 64,
            .blake2b_256 => 32,
            .blake2b_384 => 48,
            .blake2b_512 => 64,
            .blake2s => 32,
            .blake2s_256 => 32,
            .blake3 => 32,
            .crc32 => 4,
            .crc32c => 4,
            .crc64_ecma => 8,
            .crc64_iso => 8,
            .xxh32 => 4,
            .xxh64 => 8,
            .xxh3_64 => 8,
            .xxh3_128 => 16,
        };
    }

    pub fn parse(s: []const u8) ?Algorithm {
        inline for (std.meta.tags(Algorithm)) |algo| {
            if (std.ascii.eqlIgnoreCase(s, algo.name())) return algo;
        }
        return aliasMap(s);
    }

    pub fn hash(self: Algorithm, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const out_size = self.outputSize();
        const out = try allocator.alloc(u8, out_size);
        errdefer allocator.free(out);

        switch (self) {
            .fnv32 => writeLittleInt(u32, out[0..4], fnv1a32(data)),
            .fnv64 => writeLittleInt(u64, out[0..8], fnv1a64(data)),
            .fnv128 => {
                const result = fnv1a128(data);
                @memcpy(out[0..16], &result);
            },
            .sha1 => finalize(std.crypto.hash.Sha1, data, out),
            .sha224 => finalize(std.crypto.hash.sha2.Sha224, data, out),
            .sha256 => finalize(std.crypto.hash.sha2.Sha256, data, out),
            .sha384 => finalize(std.crypto.hash.sha2.Sha384, data, out),
            .sha512 => finalize(std.crypto.hash.sha2.Sha512, data, out),
            .sha512_224 => finalize(std.crypto.hash.sha2.Sha512_224, data, out),
            .sha512_256 => finalize(std.crypto.hash.sha2.Sha512_256, data, out),
            .md5 => finalize(std.crypto.hash.Md5, data, out),
            .blake2b => finalize(std.crypto.hash.blake2.Blake2b512, data, out),
            .blake2b_256 => finalize(std.crypto.hash.blake2.Blake2b256, data, out),
            .blake2b_384 => finalize(std.crypto.hash.blake2.Blake2b384, data, out),
            .blake2b_512 => finalize(std.crypto.hash.blake2.Blake2b512, data, out),
            .blake2s => finalize(std.crypto.hash.blake2.Blake2s256, data, out),
            .blake2s_256 => finalize(std.crypto.hash.blake2.Blake2s256, data, out),
            .blake3 => finalize(std.crypto.hash.Blake3, data, out),
            .crc32 => writeLittleInt(u32, out[0..4], crc32(data, crc32_table, 0xFFFFFFFF) ^ 0xFFFFFFFF),
            .crc32c => writeLittleInt(u32, out[0..4], crc32(data, crc32c_table, 0xFFFFFFFF) ^ 0xFFFFFFFF),
            .crc64_ecma => writeLittleInt(u64, out[0..8], crc64Normal(data, crc64_ecma_table, 0)),
            .crc64_iso => writeLittleInt(u64, out[0..8], crc64(data, crc64_iso_table, 0xFFFFFFFFFFFFFFFF) ^ 0xFFFFFFFFFFFFFFFF),
            .xxh32 => writeLittleInt(u32, out[0..4], xxh32(data, 0)),
            .xxh64 => writeLittleInt(u64, out[0..8], xxh64(data, 0)),
            .xxh3_64 => {
                const result = xxh3_64(data);
                writeLittleInt(u64, out[0..8], result);
            },
            .xxh3_128 => {
                const result = xxh3_128(data);
                @memcpy(out[0..16], &result);
            },
        }

        return out;
    }

    pub fn all() []const Algorithm {
        return std.meta.tags(Algorithm);
    }
};

fn aliasMap(s: []const u8) ?Algorithm {
    if (std.ascii.eqlIgnoreCase(s, "sha-1")) return .sha1;
    if (std.ascii.eqlIgnoreCase(s, "sha-224")) return .sha224;
    if (std.ascii.eqlIgnoreCase(s, "sha-256")) return .sha256;
    if (std.ascii.eqlIgnoreCase(s, "sha-384")) return .sha384;
    if (std.ascii.eqlIgnoreCase(s, "sha-512")) return .sha512;
    if (std.ascii.eqlIgnoreCase(s, "sha512/224")) return .sha512_224;
    if (std.ascii.eqlIgnoreCase(s, "sha512/256")) return .sha512_256;
    if (std.ascii.eqlIgnoreCase(s, "md-5")) return .md5;
    if (std.ascii.eqlIgnoreCase(s, "blake-3")) return .blake3;
    if (std.ascii.eqlIgnoreCase(s, "crc-32")) return .crc32;
    if (std.ascii.eqlIgnoreCase(s, "crc-32c")) return .crc32c;
    if (std.ascii.eqlIgnoreCase(s, "crc64/ecma")) return .crc64_ecma;
    if (std.ascii.eqlIgnoreCase(s, "crc64/iso")) return .crc64_iso;
    if (std.ascii.eqlIgnoreCase(s, "xxh3/64")) return .xxh3_64;
    if (std.ascii.eqlIgnoreCase(s, "xxh3/128")) return .xxh3_128;
    return null;
}

fn finalize(comptime H: type, data: []const u8, out: []u8) void {
    H.hash(data, @as(*[H.digest_length]u8, @ptrCast(out.ptr)), .{});
}

fn fnv1a32(data: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (data) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

fn fnv1a64(data: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (data) |b| {
        h ^= b;
        h *%= 0x00000100000001B3;
    }
    return h;
}

fn fnv1a128(data: []const u8) [16]u8 {
    var h_hi: u64 = 0x6c62272e07bb0142;
    var h_lo: u64 = 0x62b821756295c58d;
    const prime_hi: u64 = 0x0000000001000000;
    const prime_lo: u64 = 0x000000000000013B;

    for (data) |b| {
        h_lo ^= b;
        const result = mul128(h_hi, h_lo, prime_hi, prime_lo);
        h_hi = result.hi;
        h_lo = result.lo;
    }

    var out: [16]u8 = undefined;
    writeLittleInt(u64, out[0..8], h_lo);
    writeLittleInt(u64, out[8..16], h_hi);
    return out;
}

fn mul128(a_hi: u64, a_lo: u64, b_hi: u64, b_lo: u64) struct { hi: u64, lo: u64 } {
    const a = (@as(u128, a_hi) << 64) | a_lo;
    const b = (@as(u128, b_hi) << 64) | b_lo;
    const r = a *% b;
    return .{ .hi = @intCast(r >> 64), .lo = @intCast(r & 0xFFFFFFFFFFFFFFFF) };
}

fn crc32Table(comptime poly: u32) [256]u32 {
    @setEvalBranchQuota(5000);
    var table: [256]u32 = undefined;
    for (&table, 0..) |*entry, i| {
        var crc: u32 = @intCast(i);
        for (0..8) |_| {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        entry.* = crc;
    }
    return table;
}

fn crc64Table(comptime poly: u64) [256]u64 {
    @setEvalBranchQuota(5000);
    var table: [256]u64 = undefined;
    for (&table, 0..) |*entry, i| {
        var crc: u64 = @intCast(i);
        for (0..8) |_| {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        entry.* = crc;
    }
    return table;
}

fn crc64NormalTable(comptime poly: u64) [256]u64 {
    @setEvalBranchQuota(5000);
    var table: [256]u64 = undefined;
    for (&table, 0..) |*entry, i| {
        var crc: u64 = @as(u64, @intCast(i)) << 56;
        for (0..8) |_| {
            if (crc & (1 << 63) != 0) {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
        }
        entry.* = crc;
    }
    return table;
}

const crc32_table: [256]u32 = crc32Table(0xEDB88320);
const crc32c_table: [256]u32 = crc32Table(0x82F63B78);
const crc64_ecma_table: [256]u64 = crc64NormalTable(0x42F0E1EBA9EA3693);
const crc64_iso_table: [256]u64 = crc64Table(0xD800000000000000);

fn crc32(data: []const u8, table: [256]u32, init: u32) u32 {
    var crc = init;
    for (data) |b| {
        crc = table[@intCast((crc ^ b) & 0xFF)] ^ (crc >> 8);
    }
    return crc;
}

fn crc64(data: []const u8, table: [256]u64, init: u64) u64 {
    var crc = init;
    for (data) |b| {
        crc = table[@intCast((crc ^ b) & 0xFF)] ^ (crc >> 8);
    }
    return crc;
}

fn crc64Normal(data: []const u8, table: [256]u64, init: u64) u64 {
    var crc = init;
    for (data) |b| {
        crc = (crc << 8) ^ table[@intCast(((crc >> 56) ^ b) & 0xFF)];
    }
    return crc;
}

const XXH32_PRIME1: u32 = 0x9E3779B1;
const XXH32_PRIME2: u32 = 0x85EBCA77;
const XXH32_PRIME3: u32 = 0xC2B2AE3D;
const XXH32_PRIME4: u32 = 0x27D4EB2F;
const XXH32_PRIME5: u32 = 0x165667B1;

fn xxh32_round(acc: u32, input: u32) u32 {
    var h = acc +% input *% XXH32_PRIME2;
    h = std.math.rotl(u32, h, 13);
    h *%= XXH32_PRIME1;
    return h;
}

fn xxh32(data: []const u8, seed: u32) u32 {
    const len = data.len;
    var p: usize = 0;

    var h: u32 = undefined;
    if (len >= 16) {
        var v1 = seed +% XXH32_PRIME1 +% XXH32_PRIME2;
        var v2 = seed +% XXH32_PRIME2;
        var v3 = seed;
        var v4 = seed -% XXH32_PRIME1;

        const limit = len - 16;
        while (p <= limit) : (p += 16) {
            v1 = xxh32_round(v1, readLittleInt(u32, data[p + 0..][0..4]));
            v2 = xxh32_round(v2, readLittleInt(u32, data[p + 4..][0..4]));
            v3 = xxh32_round(v3, readLittleInt(u32, data[p + 8..][0..4]));
            v4 = xxh32_round(v4, readLittleInt(u32, data[p + 12..][0..4]));
        }

        h = std.math.rotl(u32, v1, 1) +% std.math.rotl(u32, v2, 7) +% std.math.rotl(u32, v3, 12) +% std.math.rotl(u32, v4, 18);
    } else {
        h = seed +% XXH32_PRIME5;
    }

    h +%= @as(u32, @intCast(len));

    while (p + 4 <= len) : (p += 4) {
        h +%= readLittleInt(u32, data[p..][0..4]) *% XXH32_PRIME3;
        h = std.math.rotl(u32, h, 17) *% XXH32_PRIME4;
    }

    while (p < len) : (p += 1) {
        h +%= @as(u32, data[p]) *% XXH32_PRIME5;
        h = std.math.rotl(u32, h, 11) *% XXH32_PRIME1;
    }

    h ^= h >> 15;
    h *%= XXH32_PRIME2;
    h ^= h >> 13;
    h *%= XXH32_PRIME3;
    h ^= h >> 16;

    return h;
}

const XXH64_PRIME1: u64 = 0x9E3779B185EBCA87;
const XXH64_PRIME2: u64 = 0xC2B2AE3D27D4EB4F;
const XXH64_PRIME3: u64 = 0x165667B19E3779F9;
const XXH64_PRIME4: u64 = 0x85EBCA77C2B2AE63;
const XXH64_PRIME5: u64 = 0x27D4EB2F165667C5;

fn xxh64_round(acc: u64, input: u64) u64 {
    var h = acc +% input *% XXH64_PRIME2;
    h = std.math.rotl(u64, h, 31);
    h *%= XXH64_PRIME1;
    return h;
}

fn xxh64_merge_round(acc: u64, val: u64) u64 {
    var h = acc ^ xxh64_round(0, val);
    h = h *% XXH64_PRIME1 +% XXH64_PRIME4;
    return h;
}

fn xxh64(data: []const u8, seed: u64) u64 {
    const len = data.len;
    var p: usize = 0;

    var h: u64 = undefined;
    if (len >= 32) {
        var v1 = seed +% XXH64_PRIME1 +% XXH64_PRIME2;
        var v2 = seed +% XXH64_PRIME2;
        var v3 = seed;
        var v4 = seed -% XXH64_PRIME1;

        const limit = len - 32;
        while (p <= limit) : (p += 32) {
            v1 = xxh64_round(v1, readLittleInt(u64, data[p + 0..][0..8]));
            v2 = xxh64_round(v2, readLittleInt(u64, data[p + 8..][0..8]));
            v3 = xxh64_round(v3, readLittleInt(u64, data[p + 16..][0..8]));
            v4 = xxh64_round(v4, readLittleInt(u64, data[p + 24..][0..8]));
        }

        h = std.math.rotl(u64, v1, 1) +% std.math.rotl(u64, v2, 7) +% std.math.rotl(u64, v3, 12) +% std.math.rotl(u64, v4, 18);

        v1 = xxh64_merge_round(0, v1);
        v2 = xxh64_merge_round(0, v2);
        v3 = xxh64_merge_round(0, v3);
        v4 = xxh64_merge_round(0, v4);
        h ^= v1 ^ v2 ^ v3 ^ v4;
    } else {
        h = seed +% XXH64_PRIME5;
    }

    h +%= @as(u64, @intCast(len));

    while (p + 8 <= len) : (p += 8) {
        const val = readLittleInt(u64, data[p..][0..8]);
        h ^= xxh64_round(0, val);
        h = std.math.rotl(u64, h, 27) *% XXH64_PRIME1 +% XXH64_PRIME4;
    }

    while (p + 4 <= len) : (p += 4) {
        h ^= @as(u64, readLittleInt(u32, data[p..][0..4])) *% XXH64_PRIME1;
        h = std.math.rotl(u64, h, 23) *% XXH64_PRIME2 +% XXH64_PRIME3;
    }

    while (p < len) : (p += 1) {
        h ^= @as(u64, data[p]) *% XXH64_PRIME5;
        h = std.math.rotl(u64, h, 11) *% XXH64_PRIME1;
    }

    h ^= h >> 33;
    h *%= XXH64_PRIME2;
    h ^= h >> 29;
    h *%= XXH64_PRIME3;
    h ^= h >> 32;

    return h;
}

fn xxh3Av(x: u64) u64 {
    var h = x;
    h ^= h >> 37;
    h *%= 0x165667919E3779F9;
    h ^= h >> 32;
    return h;
}

fn xxh3StrongAv(x: u64, len: u64) u64 {
    var h = x;
    h ^= std.math.rotl(u64, h, 49) ^ std.math.rotl(u64, h, 24);
    h *%= 0x9FB21C651E98DF25;
    h ^= (h >> 35) +% len;
    h *%= 0x9FB21C651E98DF25;
    h ^= h >> 28;
    return h;
}

fn mul128Fold64(a: u64, b: u64) u64 {
    const r = @as(u128, a) *% @as(u128, b);
    return @intCast((r >> 64) ^ (r & 0xFFFFFFFFFFFFFFFF));
}

const XXH3_ACC_INIT: [8]u64 = .{
    @as(u64, @bitCast(@as(i64, 0xC2B2AE3D))),
    @as(u64, 0x9E3779B185EBCA87),
    @as(u64, 0xC2B2AE3D27D4EB4F),
    @as(u64, 0x165667B19E3779F9),
    @as(u64, 0x85EBCA77C2B2AE63),
    @as(u64, @bitCast(@as(i64, 0x85EBCA77))),
    @as(u64, 0x27D4EB2F165667C5),
    @as(u64, @bitCast(@as(i64, 0x9E3779B1))),
};

const XXH3_STRIPE_LEN: usize = 64;
const XXH3_SECRET_CONSUME: usize = 8;
const XXH3_SECRET_MERGE: usize = 11;
const XXH3_SECRET_LAST: usize = 7;
const XXH3_MID_SIZE: usize = 240;

fn xxh3Accumulate512(acc: *[8]u64, input: []const u8, secret: []const u8) void {
    for (0..8) |idx| {
        const data_val = readLittleInt(u64, input[idx * 8 ..][0..8]);
        const data_key = data_val ^ readLittleInt(u64, secret[idx * 8 ..][0..8]);
        acc[idx ^ 1] +%= data_val;
        acc[idx] +%= @as(u64, @intCast(data_key & 0xFFFFFFFF)) *% @as(u64, @intCast(data_key >> 32));
    }
}

fn xxh3ScrambleAcc(acc: *[8]u64, secret: []const u8) void {
    for (0..8) |idx| {
        const key = readLittleInt(u64, secret[idx * 8 ..][0..8]);
        var acc_val = acc[idx] ^ (acc[idx] >> 47);
        acc_val ^= key;
        acc[idx] = acc_val *% @as(u64, XXH32_PRIME1);
    }
}

fn xxh3AccumulateLoop(acc: *[8]u64, input: []const u8, secret: []const u8, nb_stripes: usize) void {
    var i: usize = 0;
    while (i < nb_stripes) : (i += 1) {
        xxh3Accumulate512(acc, input[i * XXH3_STRIPE_LEN ..], secret[i * XXH3_SECRET_CONSUME ..]);
    }
}

fn xxh3LongInternalLoop(acc: *[8]u64, input: []const u8, secret: []const u8) void {
    const nb_stripes = (secret.len - XXH3_STRIPE_LEN) / XXH3_SECRET_CONSUME;
    const block_len = XXH3_STRIPE_LEN * nb_stripes;
    const nb_blocks = (input.len - 1) / block_len;

    var i: usize = 0;
    while (i < nb_blocks) : (i += 1) {
        xxh3AccumulateLoop(acc, input[i * block_len ..], secret, nb_stripes);
        xxh3ScrambleAcc(acc, secret[secret.len - XXH3_STRIPE_LEN ..]);
    }

    const nb_stripes_last = ((input.len - 1) - (block_len * nb_blocks)) / XXH3_STRIPE_LEN;
    xxh3AccumulateLoop(acc, input[nb_blocks * block_len ..], secret, nb_stripes_last);
    xxh3Accumulate512(acc, input[input.len - XXH3_STRIPE_LEN ..], secret[secret.len - XXH3_STRIPE_LEN - XXH3_SECRET_LAST ..]);
}

fn xxh3MergeAccs(acc: *[8]u64, secret: []const u8, result: u64) u64 {
    var r = result;
    var idx: usize = 0;
    while (idx < 8) : (idx += 2) {
        const a = acc[idx] ^ readLittleInt(u64, secret[idx * 8 ..][0..8]);
        const b = acc[idx + 1] ^ readLittleInt(u64, secret[(idx + 1) * 8 ..][0..8]);
        r +%= mul128Fold64(a, b);
    }
    return xxh3Av(r);
}

fn xxh3_64_long(input: []const u8, secret: []const u8) u64 {
    var acc = XXH3_ACC_INIT;
    xxh3LongInternalLoop(&acc, input, secret);
    return xxh3MergeAccs(&acc, secret[XXH3_SECRET_MERGE ..][0..64], @as(u64, @intCast(input.len)) *% XXH64_PRIME1);
}

fn xxh3Mix16B(input_lo: u64, input_hi: u64, secret_lo: u64, secret_hi: u64, seed: u64) u64 {
    const il = input_lo ^ (secret_lo +% seed);
    const ih = input_hi ^ (secret_hi -% seed);
    return mul128Fold64(il, ih);
}

fn xxh3_64_1to3(data: []const u8, seed: u64, secret: []const u8) u64 {
    const c1 = data[0];
    const c2 = data[data.len >> 1];
    const c3 = data[data.len - 1];
    const combo = (@as(u32, @intCast(c1)) << 16) | (@as(u32, @intCast(c2)) << 24) | (@as(u32, @intCast(c3)) << 0) | (@as(u32, @intCast(data.len)) << 8);
    const flip = (readLittleInt(u32, secret[0..4]) ^ readLittleInt(u32, secret[4..8])) +% seed;
    const res = @as(u64, @intCast(combo)) ^ @as(u64, @intCast(flip));
    return xxh3Av(res);
}

fn xxh3_64_4to8(data: []const u8, seed: u64, secret: []const u8) u64 {
    const s = seed ^ (@as(u64, @intCast(@byteSwap(@as(u32, @intCast(seed & 0xFFFFFFFF))))) << 32);
    const input1 = readLittleInt(u32, data[0..4]);
    const input2 = readLittleInt(u32, data[data.len - 4 ..][0..4]);
    const flip = (readLittleInt(u64, secret[8..16]) ^ readLittleInt(u64, secret[16..24])) -% s;
    const input64 = @as(u64, @intCast(input2)) +% (@as(u64, @intCast(input1)) << 32);
    const keyed = input64 ^ flip;
    return xxh3StrongAv(keyed, @as(u64, @intCast(data.len)));
}

fn xxh3_64_9to16(data: []const u8, seed: u64, secret: []const u8) u64 {
    const flip1 = (readLittleInt(u64, secret[24..32]) ^ readLittleInt(u64, secret[32..40])) +% seed;
    const flip2 = (readLittleInt(u64, secret[40..48]) ^ readLittleInt(u64, secret[48..56])) -% seed;
    const input_lo = readLittleInt(u64, data[0..8]) ^ flip1;
    const input_hi = readLittleInt(u64, data[data.len - 8 ..][0..8]) ^ flip2;
    const acc = @as(u64, @intCast(data.len)) +% @byteSwap(input_lo) +% input_hi +% mul128Fold64(input_lo, input_hi);
    return xxh3Av(acc);
}

fn xxh3_64_0to16(data: []const u8, seed: u64, secret: []const u8) u64 {
    if (data.len > 8) return xxh3_64_9to16(data, seed, secret);
    if (data.len >= 4) return xxh3_64_4to8(data, seed, secret);
    if (data.len > 0) return xxh3_64_1to3(data, seed, secret);
    return xxh3Av(seed ^ (readLittleInt(u64, secret[56..64]) ^ readLittleInt(u64, secret[64..72])));
}

fn xxh3_64_7to128(data: []const u8, seed: u64, secret: []const u8) u64 {
    var acc = @as(u64, @intCast(data.len)) *% XXH64_PRIME1;
    if (data.len > 32) {
        if (data.len > 64) {
            if (data.len > 96) {
                acc +%= xxh3Mix16B(
                    readLittleInt(u64, data[48..56]),
                    readLittleInt(u64, data[56..64]),
                    readLittleInt(u64, secret[96..104]),
                    readLittleInt(u64, secret[104..112]),
                    seed,
                );
                acc +%= xxh3Mix16B(
                    readLittleInt(u64, data[data.len - 64 ..][0..8]),
                    readLittleInt(u64, data[data.len - 56 ..][0..8]),
                    readLittleInt(u64, secret[112..120]),
                    readLittleInt(u64, secret[120..128]),
                    seed,
                );
            }
            acc +%= xxh3Mix16B(
                readLittleInt(u64, data[32..40]),
                readLittleInt(u64, data[40..48]),
                readLittleInt(u64, secret[64..72]),
                readLittleInt(u64, secret[72..80]),
                seed,
            );
            acc +%= xxh3Mix16B(
                readLittleInt(u64, data[data.len - 48 ..][0..8]),
                readLittleInt(u64, data[data.len - 40 ..][0..8]),
                readLittleInt(u64, secret[80..88]),
                readLittleInt(u64, secret[88..96]),
                seed,
            );
        }
        acc +%= xxh3Mix16B(
            readLittleInt(u64, data[16..24]),
            readLittleInt(u64, data[24..32]),
            readLittleInt(u64, secret[32..40]),
            readLittleInt(u64, secret[40..48]),
            seed,
        );
        acc +%= xxh3Mix16B(
            readLittleInt(u64, data[data.len - 32 ..][0..8]),
            readLittleInt(u64, data[data.len - 24 ..][0..8]),
            readLittleInt(u64, secret[48..56]),
            readLittleInt(u64, secret[56..64]),
            seed,
        );
    }
    acc +%= xxh3Mix16B(
        readLittleInt(u64, data[0..8]),
        readLittleInt(u64, data[8..16]),
        readLittleInt(u64, secret[0..8]),
        readLittleInt(u64, secret[8..16]),
        seed,
    );
    acc +%= xxh3Mix16B(
        readLittleInt(u64, data[data.len - 16 ..][0..8]),
        readLittleInt(u64, data[data.len - 8 ..][0..8]),
        readLittleInt(u64, secret[16..24]),
        readLittleInt(u64, secret[24..32]),
        seed,
    );
    return xxh3Av(acc);
}

fn xxh3_64_129to240(data: []const u8, seed: u64, secret: []const u8) u64 {
    var acc = @as(u64, @intCast(data.len)) *% XXH64_PRIME1;
    const nb_rounds = data.len / 16;
    var idx: usize = 0;
    while (idx < 8) : (idx += 1) {
        acc +%= xxh3Mix16B(
            readLittleInt(u64, data[16 * idx ..][0..8]),
            readLittleInt(u64, data[16 * idx + 8 ..][0..8]),
            readLittleInt(u64, secret[16 * idx ..][0..8]),
            readLittleInt(u64, secret[16 * idx + 8 ..][0..8]),
            seed,
        );
    }
    acc = xxh3Av(acc);
    while (idx < nb_rounds) : (idx += 1) {
        const secret_off = 16 * (idx - 8) + 3;
        acc +%= xxh3Mix16B(
            readLittleInt(u64, data[16 * idx ..][0..8]),
            readLittleInt(u64, data[16 * idx + 8 ..][0..8]),
            readLittleInt(u64, secret[secret_off ..][0..8]),
            readLittleInt(u64, secret[secret_off + 8 ..][0..8]),
            seed,
        );
    }
    acc +%= xxh3Mix16B(
        readLittleInt(u64, data[data.len - 16 ..][0..8]),
        readLittleInt(u64, data[data.len - 8 ..][0..8]),
        readLittleInt(u64, secret[119..127]),
        readLittleInt(u64, secret[127..135]),
        seed,
    );
    return xxh3Av(acc);
}

fn xxh3_64_internal(data: []const u8, seed: u64, secret: []const u8) u64 {
    if (data.len <= 16) return xxh3_64_0to16(data, seed, secret);
    if (data.len <= 128) return xxh3_64_7to128(data, seed, secret);
    if (data.len <= XXH3_MID_SIZE) return xxh3_64_129to240(data, seed, secret);
    return xxh3_64_long(data, secret);
}

fn xxh3_64(data: []const u8) u64 {
    return xxh3_64_internal(data, 0, &XXH3_SECRET);
}

fn xxh3Mix32B(lo: *u64, hi: *u64, input1_lo: u64, input1_hi: u64, input2_lo: u64, input2_hi: u64, secret1_lo: u64, secret1_hi: u64, secret2_lo: u64, secret2_hi: u64, seed: u64) void {
    lo.* +%= xxh3Mix16B(input1_lo, input1_hi, secret1_lo, secret1_hi, seed);
    lo.* ^= input2_lo +% input2_hi;
    hi.* +%= xxh3Mix16B(input2_lo, input2_hi, secret2_lo, secret2_hi, seed);
    hi.* ^= input1_lo +% input1_hi;
}

fn xxh3_128_long(data: []const u8, secret: []const u8) [16]u8 {
    var acc = XXH3_ACC_INIT;
    xxh3LongInternalLoop(&acc, data, secret);
    const lo = xxh3MergeAccs(&acc, secret[XXH3_SECRET_MERGE ..][0..64], @as(u64, @intCast(data.len)) *% XXH64_PRIME1);
    const hi = xxh3MergeAccs(&acc, secret[secret.len - 64 - XXH3_SECRET_MERGE ..][0..64], ~@as(u64, @intCast(data.len)) *% XXH64_PRIME2);
    var result: [16]u8 = undefined;
    writeLittleInt(u64, result[0..8], lo);
    writeLittleInt(u64, result[8..16], hi);
    return result;
}

fn xxh3_128_1to3(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    const c1 = data[0];
    const c2 = data[data.len >> 1];
    const c3 = data[data.len - 1];
    const input_lo = @as(u32, @intCast(c1)) << 16 | @as(u32, @intCast(c2)) << 24 | @as(u32, @intCast(c3)) << 0 | @as(u32, @intCast(data.len)) << 8;
    const input_hi = @byteSwap(input_lo) | (input_lo << 13) | (input_lo >> 19);
    const flip_lo = @as(u64, readLittleInt(u32, secret[0..4]) ^ readLittleInt(u32, secret[4..8])) +% seed;
    const flip_hi = @as(u64, readLittleInt(u32, secret[8..12]) ^ readLittleInt(u32, secret[12..16])) -% seed;
    const keyed_lo = @as(u64, @intCast(input_lo)) ^ flip_lo;
    const keyed_hi = @as(u64, @intCast(input_hi)) ^ flip_hi;
    var result: [16]u8 = undefined;
    writeLittleInt(u64, result[0..8], xxh3Av(keyed_lo));
    writeLittleInt(u64, result[8..16], xxh3Av(keyed_hi));
    return result;
}

fn xxh3_128_4to8(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    const s = seed ^ (@as(u64, @intCast(@byteSwap(@as(u32, @intCast(seed & 0xFFFFFFFF))))) << 32);
    const lo = readLittleInt(u32, data[0..4]);
    const hi = readLittleInt(u32, data[data.len - 4 ..][0..4]);
    const input_64 = @as(u64, @intCast(lo)) +% (@as(u64, @intCast(hi)) << 32);
    const flip = (readLittleInt(u64, secret[16..24]) ^ readLittleInt(u64, secret[24..32])) +% s;
    const keyed = input_64 ^ flip;
    var mul_lo: u64 = undefined;
    var mul_hi: u64 = undefined;
    {
        const r = @as(u128, keyed) *% @as(u128, XXH64_PRIME1 +% (@as(u64, @intCast(data.len)) << 2));
        mul_lo = @intCast(r & 0xFFFFFFFFFFFFFFFF);
        mul_hi = @intCast(r >> 64);
    }
    mul_hi +%= mul_lo << 1;
    mul_lo ^= mul_hi >> 3;
    var h_lo = mul_lo;
    h_lo ^= h_lo >> 35;
    h_lo *%= 0x9FB21C651E98DF25;
    h_lo ^= h_lo >> 28;
    var result: [16]u8 = undefined;
    writeLittleInt(u64, result[0..8], h_lo);
    writeLittleInt(u64, result[8..16], xxh3Av(mul_hi));
    return result;
}

fn xxh3_128_9to16(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    const flip_lo = (readLittleInt(u64, secret[32..40]) ^ readLittleInt(u64, secret[40..48])) -% seed;
    const flip_hi = (readLittleInt(u64, secret[48..56]) ^ readLittleInt(u64, secret[56..64])) +% seed;
    const input_lo = readLittleInt(u64, data[0..8]);
    var input_hi = readLittleInt(u64, data[data.len - 8 ..][0..8]);
    var mul_lo: u64 = undefined;
    var mul_hi: u64 = undefined;
    {
        const r = @as(u128, input_lo ^ input_hi ^ flip_lo) *% @as(u128, XXH64_PRIME1);
        mul_lo = @intCast(r & 0xFFFFFFFFFFFFFFFF);
        mul_hi = @intCast(r >> 64);
    }
    mul_lo +%= (@as(u64, @intCast(data.len)) -% 1) << 54;
    input_hi ^= flip_hi;
    mul_hi +%= input_hi +% @as(u64, @intCast(@as(u32, @intCast(input_hi & 0xFFFFFFFF)))) *% @as(u64, XXH32_PRIME2 - 1);
    mul_lo ^= @byteSwap(mul_hi);
    const r2 = @as(u128, mul_lo) *% @as(u128, XXH64_PRIME2);
    const result_lo: u64 = @intCast(r2 & 0xFFFFFFFFFFFFFFFF);
    var result_hi: u64 = @intCast(r2 >> 64);
    result_hi +%= mul_hi *% XXH64_PRIME2;
    var out: [16]u8 = undefined;
    writeLittleInt(u64, out[0..8], xxh3Av(result_lo));
    writeLittleInt(u64, out[8..16], xxh3Av(result_hi));
    return out;
}

fn xxh3_128_0to16(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    if (data.len > 8) return xxh3_128_9to16(data, seed, secret);
    if (data.len >= 4) return xxh3_128_4to8(data, seed, secret);
    if (data.len > 0) return xxh3_128_1to3(data, seed, secret);
    const flip_lo = readLittleInt(u64, secret[64..72]) ^ readLittleInt(u64, secret[72..80]);
    const flip_hi = readLittleInt(u64, secret[80..88]) ^ readLittleInt(u64, secret[88..96]);
    var out: [16]u8 = undefined;
    writeLittleInt(u64, out[0..8], xxh3Av(seed ^ flip_lo));
    writeLittleInt(u64, out[8..16], xxh3Av(seed ^ flip_hi));
    return out;
}

fn xxh3_128_7to128(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    var lo = @as(u64, @intCast(data.len)) *% XXH64_PRIME1;
    var hi: u64 = 0;
    if (data.len > 32) {
        if (data.len > 64) {
            if (data.len > 96) {
                xxh3Mix32B(&lo, &hi,
                    readLittleInt(u64, data[48..56]), readLittleInt(u64, data[56..64]),
                    readLittleInt(u64, data[data.len - 64 ..][0..8]), readLittleInt(u64, data[data.len - 56 ..][0..8]),
                    readLittleInt(u64, secret[96..104]), readLittleInt(u64, secret[104..112]),
                    readLittleInt(u64, secret[112..120]), readLittleInt(u64, secret[120..128]),
                    seed,
                );
            }
            xxh3Mix32B(&lo, &hi,
                readLittleInt(u64, data[32..40]), readLittleInt(u64, data[40..48]),
                readLittleInt(u64, data[data.len - 48 ..][0..8]), readLittleInt(u64, data[data.len - 40 ..][0..8]),
                readLittleInt(u64, secret[64..72]), readLittleInt(u64, secret[72..80]),
                readLittleInt(u64, secret[80..88]), readLittleInt(u64, secret[88..96]),
                seed,
            );
        }
        xxh3Mix32B(&lo, &hi,
            readLittleInt(u64, data[16..24]), readLittleInt(u64, data[24..32]),
            readLittleInt(u64, data[data.len - 32 ..][0..8]), readLittleInt(u64, data[data.len - 24 ..][0..8]),
            readLittleInt(u64, secret[32..40]), readLittleInt(u64, secret[40..48]),
            readLittleInt(u64, secret[48..56]), readLittleInt(u64, secret[56..64]),
            seed,
        );
    }
    xxh3Mix32B(&lo, &hi,
        readLittleInt(u64, data[0..8]), readLittleInt(u64, data[8..16]),
        readLittleInt(u64, data[data.len - 16 ..][0..8]), readLittleInt(u64, data[data.len - 8 ..][0..8]),
        readLittleInt(u64, secret[0..8]), readLittleInt(u64, secret[8..16]),
        readLittleInt(u64, secret[16..24]), readLittleInt(u64, secret[24..32]),
        seed,
    );
    var out: [16]u8 = undefined;
    const av_lo = xxh3Av(lo +% hi);
    const av_hi = 0 -% xxh3Av(lo *% XXH64_PRIME1 +% hi *% XXH64_PRIME4 +% (@as(u64, @intCast(data.len)) -% seed) *% XXH64_PRIME2);
    writeLittleInt(u64, out[0..8], av_lo);
    writeLittleInt(u64, out[8..16], av_hi);
    return out;
}

fn xxh3_128_129to240(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    const nb_rounds = data.len / 32;
    var lo = @as(u64, @intCast(data.len)) *% XXH64_PRIME1;
    var hi: u64 = 0;
    var idx: usize = 0;
    while (idx < 4) : (idx += 1) {
        xxh3Mix32B(&lo, &hi,
            readLittleInt(u64, data[32 * idx ..][0..8]), readLittleInt(u64, data[32 * idx + 8 ..][0..8]),
            readLittleInt(u64, data[32 * idx + 16 ..][0..8]), readLittleInt(u64, data[32 * idx + 24 ..][0..8]),
            readLittleInt(u64, secret[32 * idx ..][0..8]), readLittleInt(u64, secret[32 * idx + 8 ..][0..8]),
            readLittleInt(u64, secret[32 * idx + 16 ..][0..8]), readLittleInt(u64, secret[32 * idx + 24 ..][0..8]),
            seed,
        );
    }
    lo = xxh3Av(lo);
    hi = xxh3Av(hi);
    while (idx < nb_rounds) : (idx += 1) {
        const secret_off = 3 + 32 * (idx - 4);
        xxh3Mix32B(&lo, &hi,
            readLittleInt(u64, data[32 * idx ..][0..8]), readLittleInt(u64, data[32 * idx + 8 ..][0..8]),
            readLittleInt(u64, data[32 * idx + 16 ..][0..8]), readLittleInt(u64, data[32 * idx + 24 ..][0..8]),
            readLittleInt(u64, secret[secret_off ..][0..8]), readLittleInt(u64, secret[secret_off + 8 ..][0..8]),
            readLittleInt(u64, secret[secret_off + 16 ..][0..8]), readLittleInt(u64, secret[secret_off + 24 ..][0..8]),
            seed,
        );
    }
    xxh3Mix32B(&lo, &hi,
        readLittleInt(u64, data[data.len - 16 ..][0..8]), readLittleInt(u64, data[data.len - 8 ..][0..8]),
        readLittleInt(u64, data[data.len - 32 ..][0..8]), readLittleInt(u64, data[data.len - 24 ..][0..8]),
        readLittleInt(u64, secret[119..127]), readLittleInt(u64, secret[127..135]),
        readLittleInt(u64, secret[103..111]), readLittleInt(u64, secret[111..119]),
        seed,
    );
    var out: [16]u8 = undefined;
    writeLittleInt(u64, out[0..8], xxh3Av(lo +% hi));
    writeLittleInt(u64, out[8..16], 0 -% xxh3Av(lo *% XXH64_PRIME1 +% hi *% XXH64_PRIME4 +% (@as(u64, @intCast(data.len)) -% seed) *% XXH64_PRIME2));
    return out;
}

fn xxh3_128(data: []const u8) [16]u8 {
    return xxh3_128_internal(data, 0, &XXH3_SECRET);
}

fn xxh3_128_internal(data: []const u8, seed: u64, secret: []const u8) [16]u8 {
    if (data.len <= 16) return xxh3_128_0to16(data, seed, secret);
    if (data.len <= 128) return xxh3_128_7to128(data, seed, secret);
    if (data.len <= XXH3_MID_SIZE) return xxh3_128_129to240(data, seed, secret);
    return xxh3_128_long(data, secret);
}

const XXH3_SECRET: [192]u8 = .{
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};
