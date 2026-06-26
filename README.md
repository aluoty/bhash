# bhash

A fast, universal hashing tool with **26 algorithms, HMAC support, and checksum verification** — written in pure Zig.

Hash strings, files, and stdin; verify checksums; compute HMACs; output in hex, base64, or raw binary.

## Usage

```text
bhash [OPTIONS] [STRINGS]...
```

### Modes

| Mode | Example |
|------|---------|
| **Hash strings** | `bhash -a sha256 "hello" "world"` |
| **Hash files** | `bhash -a md5 -f file1.bin -f file2.bin` |
| **Hash stdin** | `echo "data" \| bhash -a blake3` |
| | `bhash -a xxh64 --stdin < data.bin` |
| **Verify checksums** | `bhash -a sha256 -c SHA256SUMS` |
| | `cat SHA256SUMS \| bhash -a sha256 -c` |
| **Tagged output** | `bhash -a sha256 --tag -f file.bin` |
| **HMAC auth** | `bhash -a sha256 --hmac "secret" "message"` |
| **List algorithms** | `bhash --list` |

### Options

| Flag | Description |
|------|-------------|
| `-a`, `--algorithm` | Hash algorithm (default: `sha256`) |
| `-f`, `--file` | File(s) to hash |
| `--stdin` | Read from stdin explicitly |
| `--format` | Output format: `hex` (default) or `base64` |
| `-b`, `--binary` | Output raw binary bytes |
| `-t`, `--tag` | BSD-style tagged output (`ALGO (file) = hash`) |
| `-l`, `--list` | List all available algorithms |
| `-c`, `--check` | Verify checksums (read file, or stdin if omitted) |
| `--quiet` / `--silent` | In check mode, only print summary |
| `--status` | In check mode, suppress all output (exit only) |
| `--ignore-missing` | Don't fail on missing files in check mode |
| `--warn` | Warn about malformed checksum lines |
| `--strict` | Exit non-zero on malformed checksum lines |
| `--hmac <key>` | Compute HMAC with given key |
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print version |

### Examples

```bash
# Hash strings
bhash -a sha256 "hello world"
bhash -a blake3 "hello"

# Hash files
bhash -a sha256 -f document.pdf
bhash -a sha256 -f file1.txt -f file2.txt

# Pipe data via stdin
cat file.bin | bhash -a sha256

# Base64 output
bhash -a sha256 --format base64 "hello"

# Raw binary output (for piping into other tools)
bhash -a sha256 --binary -f file.bin | other-tool

# Tagged output (BSD / OpenSSL style)
bhash -a sha256 --tag -f file.bin
bhash -a blake3 --tag "my string"

# HMAC authentication (RFC 2104)
bhash -a sha256 --hmac "mykey" "message"
echo -n "message" | bhash -a sha256 --hmac "mykey"

# Generate and verify checksums
bhash -a sha256 -f file.bin > file.sha256
bhash -a sha256 -c file.sha256

# Verify checksums from stdin
cat file.sha256 | bhash -a sha256 -c

# Quiet / strict verification
bhash -a sha256 -c --quiet file.sha256
bhash -a sha256 -c --status file.sha256 && echo "all good"

# Warn on malformed checksum lines, exit non-zero
bhash -a sha256 -c --warn --strict file.sha256

# Ignore missing files during verification
bhash -a sha256 -c --ignore-missing file.sha256

# List all algorithms
bhash --list
```

### HMAC support

HMAC (Hash-based Message Authentication Code, RFC 2104) is available for all
cryptographic hash algorithms using `--hmac <key>`:

```bash
# HMAC-SHA256
bhash -a sha256 --hmac "mykey" "hello"

# HMAC-BLAKE3
bhash -a blake3 --hmac "key" "data"

# HMAC with tagged output
bhash -a sha256 --hmac "secret" --tag -f file.bin
```

Non-cryptographic algorithms (CRC, FNV, XXH) return an error when used with `--hmac`.

### Checksum file format

Compatible with standard Unix `sha256sum` / `md5sum` format:

```
<hash>  <filename>
<hash> <filename>
<hash> *<filename>
```

Lines starting with `#` or `;` are skipped. The `*` prefix marks binary-mode entries.

## Algorithms

| Algorithm | Output size | HMAC | Source |
|-----------|-------------|------|--------|
| `fnv32` | 4 B | no | built-in |
| `fnv64` | 8 B | no | built-in |
| `fnv128` | 16 B | no | built-in |
| `sha1` | 20 B | yes | std.crypto |
| `sha224` | 28 B | yes | std.crypto |
| `sha256` | 32 B | yes | std.crypto |
| `sha384` | 48 B | yes | std.crypto |
| `sha512` | 64 B | yes | std.crypto |
| `sha512-224` | 28 B | yes | std.crypto |
| `sha512-256` | 32 B | yes | std.crypto |
| `md5` | 16 B | yes | std.crypto |
| `blake2b` | 64 B | yes | std.crypto |
| `blake2b-256` | 32 B | yes | std.crypto |
| `blake2b-384` | 48 B | yes | std.crypto |
| `blake2b-512` | 64 B | yes | std.crypto |
| `blake2s` | 32 B | yes | std.crypto |
| `blake2s-256` | 32 B | yes | std.crypto |
| `blake3` | 32 B | yes | std.crypto |
| `crc32` | 4 B | no | built-in |
| `crc32c` | 4 B | no | built-in |
| `crc64-ecma` | 8 B | no | built-in |
| `crc64-iso` | 8 B | no | built-in |
| `xxh32` | 4 B | no | built-in |
| `xxh64` | 8 B | no | built-in |
| `xxh3-64` | 8 B | no | built-in |
| `xxh3-128` | 16 B | no | built-in |

## Build

```bash
zig build
```

The binary will be at `zig-out/bin/bhash`.

Run with `zig build run -- [args]` or directly:

```bash
zig-out/bin/bhash -a blake3 "hello"
```

## Notes

All hashing algorithms are either from Zig's standard library (`std.crypto`) or
implemented directly in Zig. No external C dependencies.
