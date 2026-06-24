# bhash

A fast, universal hashing tool with support for **26 hash algorithms**, written in pure Zig.

Hash strings, files, and stdin — verify checksums — choose your output format.

## Usage

```text
bhash [OPTIONS] [STRINGS]...
```

### Modes

| Mode | Example |
|------|---------|
| **Hash strings** | `bhash --algorithm sha256 "hello" "world"` |
| **Hash files** | `bhash -a md5 -f file1.bin -f file2.bin` |
| **Hash stdin** | `echo "data" \| bhash -a blake3` |
| | `bhash -a xxh64 --stdin < data.bin` |
| **Verify checksums** | `bhash -a sha256 --check SHA256SUMS` |
| **Tagged output** | `bhash -a sha256 --tag -f file.bin` |
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
| `-c`, `--check` | Verify checksums from a sums-file |
| `--quiet` | In `--check` mode, only print summary |
| `--status` | In `--check` mode, suppress all output (exit only) |
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print version |

### Examples

```bash
# Hash a string with SHA-256
bhash -a sha256 "hello world"

# Hash with multiple algorithms
bhash -a md5 "hello"
bhash -a blake3 "hello"

# Hash a file
bhash -a sha256 -f document.pdf

# Hash multiple files
bhash -a sha256 -f file1.txt -f file2.txt

# Pipe data via stdin
cat file.bin | bhash -a sha256

# Base64 output
bhash -a sha256 --format base64 "hello"

# Generate checksums file and verify
bhash -a sha256 -f file.bin > file.sha256
bhash -a sha256 --check file.sha256

# Tagged output (BSD / OpenSSL style)
bhash -a sha256 --tag -f file.bin
bhash -a blake3 --tag "my string"

# Raw binary output
bhash -a sha256 --binary -f file.bin | other-tool

# Quiet/strict verification
bhash -a sha256 --check --quiet file.sha256
bhash -a sha256 --check --status file.sha256 && echo "all good"

# List all algorithms
bhash --list
```

## Algorithms

| Algorithm | Output size | Source |
|-----------|-------------|--------|
| `fnv32` | 4 B | built-in |
| `fnv64` | 8 B | built-in |
| `fnv128` | 16 B | built-in |
| `sha1` | 20 B | std.crypto |
| `sha224` | 28 B | std.crypto |
| `sha256` | 32 B | std.crypto |
| `sha384` | 48 B | std.crypto |
| `sha512` | 64 B | std.crypto |
| `sha512-224` | 28 B | std.crypto |
| `sha512-256` | 32 B | std.crypto |
| `md5` | 16 B | std.crypto |
| `blake2b` | 64 B | std.crypto |
| `blake2b-256` | 32 B | std.crypto |
| `blake2b-384` | 48 B | std.crypto |
| `blake2b-512` | 64 B | std.crypto |
| `blake2s` | 32 B | std.crypto |
| `blake2s-256` | 32 B | std.crypto |
| `blake3` | 32 B | std.crypto |
| `crc32` | 4 B | built-in |
| `crc32c` | 4 B | built-in |
| `crc64-ecma` | 8 B | built-in |
| `crc64-iso` | 8 B | built-in |
| `xxh32` | 4 B | built-in |
| `xxh64` | 8 B | built-in |
| `xxh3-64` | 8 B | built-in |
| `xxh3-128` | 16 B | built-in |

## Build

```bash
zig build
```

The binary will be at `zig-out/bin/bhash`.

Run with `zig build run -- [args]` or directly:

```bash
zig-out/bin/bhash -a blake3 "hello"
```

## Checksum file format

Compatible with standard Unix `sha256sum` / `md5sum` format (both text and binary markers):

```
<hash>  <filename>
<hash> <filename>
<hash> *<filename>
```

Lines starting with `#` or `;` are skipped.

## Notes

All hashing algorithms are either from Zig's standard library (`std.crypto`) or
implemented directly in Zig. No external C dependencies.

You defined your own Bhash name
+ Bin Hash
+ Byte Hash
+ Bit Hash
+ Bye Hash
+ Best Hash
+ Bad Hash(when it doesn't work)

## License

See [LICENSE](LICENSE)
