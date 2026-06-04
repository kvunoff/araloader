# AraLoader

A self-decrypting executable builder — takes a C byte array payload, encrypts it, and compiles a standalone Windows `.exe` that decrypts and executes the payload entirely in memory.

Also works in reverse: extract any binary file into a C array for embedding in other projects.

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌────────────────────┐
│  C array     │     │  Encrypted   │     │  Windows .exe      │
│  (payload)   │ ──► │  stub source │ ──► │  (self-decrypting) │
│  .c file     │     │  generated   │     │  via rustc cross   │
└──────────────┘     └──────────────┘     └────────────────────┘
```

1. **Parse** — reads hex bytes from a C-style array (`\x90\x90\xde\xad...`)
2. **Encrypt** — XOR or RC4 with a provided or randomly generated key
3. **Generate** — produces a Rust stub with the encrypted payload embedded as base64 and the decryptor inlined
4. **Compile** — cross-compiles the stub via `rustc --target x86_64-pc-windows-gnu` into a statically linked `.exe`
5. **At runtime (Windows)** — the stub decrypts the payload into RWX memory, then jumps to it

No external dependencies at runtime — the resulting binary is fully self-contained.

## Requirements

- **Rust toolchain** (`rustup`)
- **Windows cross-compiler** (for `.exe` output on Linux):
  ```bash
  rustup target add x86_64-pc-windows-gnu

  # Arch Linux
  sudo pacman -S mingw-w64-gcc

  # Ubuntu/Debian
  sudo apt install mingw-w64
  ```

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/araloader`.

## Usage

### Build a self-decrypting executable

```bash
# RC4 encryption (default) with random key
araloader --input payload.c --output payload.exe

# XOR encryption with a custom key
araloader --input payload.c --output payload.exe --encrypt xor --key MySecretKey

# Save the encryption key to a file
araloader --input payload.c --output payload.exe --encrypt rc4 --keyfile key.txt
```

### Extract a binary to a C array

```bash
araloader --input binary.dll --extract --output output.c
```

Reverse of the build mode — converts any file into a `unsigned char buf[] = "\x..\x..";` C array.

## Options

| Flag | Description |
|------|-------------|
| `-i, --input FILE` | Input file (C array for build, binary for `--extract`) |
| `-o, --output FILE` | Output file (default: `payload.exe`) |
| `-e, --encrypt MODE` | Encryption: `xor` or `rc4` (default: `rc4`) |
| `-k, --key STRING` | Custom encryption key (random 32-byte hex key if omitted) |
| `--keyfile FILE` | Write the encryption key to a file |
| `--extract` | Extract mode: convert a binary file to a C byte array |

## Input Format

The input C file should contain hex byte literals like:

```c
unsigned char buf[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00...";
```

The parser extracts every `\xHH` sequence. Any surrounding text, variable names, or comments are ignored — only the hex escapes matter.

## Technical Details

- **Encryption**: XOR (repeating-key) or RC4, both implemented without external crypto libraries
- **Stub size**: the generated Rust stub is typically under 200 lines and compiles to a few hundred KB
- **Memory execution**: uses `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` to allocate executable memory for the decoded payload
- **No std dependency**: the stub uses `#![windows_subsystem = "windows"]` — no console window on execution
- **Static linking**: compiled with `-static-libgcc` and `-mwindows` for a self-contained binary

## License

MIT
