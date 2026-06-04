# AraLoader

A self-decrypting executable builder — takes a C byte array, encrypts it, and compiles a standalone Windows `.exe` that decrypts and executes the original code entirely in memory.

Also works in reverse: extract any binary file into a C array for embedding in other projects.

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌────────────────────┐
│  C array     │     │  Encrypted   │     │  Windows .exe      │
│  (data)      │ ──► │  stub source │ ──► │  (self-decrypting) │
│  .c file     │     │  generated   │     │  via rustc cross   │
└──────────────┘     └──────────────┘     └────────────────────┘
```

1. **Parse** — reads hex bytes from a C-style array (`\x90\x90\xde\xad...`)
2. **Encrypt** — XOR, RC4, or AES-256-CTR with a provided or randomly generated key
3. **Generate** — produces a Rust stub with the encrypted data embedded as base64 and the decryptor inlined
4. **Compile** — cross-compiles the stub via `rustc --target x86_64-pc-windows-gnu` into a statically linked `.exe`
5. **At runtime (Windows)** — the stub decrypts the data into RWX memory and executes it

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

### Arch Linux (AUR)

```bash
paru -S araloader
# or
yay -S araloader
```

### Cargo (from Git)

```bash
cargo install --git https://github.com/kvunoff/AraLoader
```

### Build from source

```bash
git clone https://github.com/kvunoff/AraLoader
cd AraLoader
cargo build --release
```

The binary will be at `target/release/araloader`.

## Usage

### Build a self-decrypting executable

```bash
# RC4 encryption (default) with random key
araloader --input data.c --output output.exe

# XOR encryption with a custom key
araloader --input data.c --output output.exe --encrypt xor --key MySecretKey

# AES-256-CTR encryption with a random key
araloader --input data.c --output output.exe --encrypt aes

# Save the encryption key to a file
araloader --input data.c --output output.exe --encrypt rc4 --keyfile key.txt
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
| `-o, --output FILE` | Output file (default: `output.exe`) |
| `-e, --encrypt MODE` | Encryption: `xor`, `rc4`, or `aes` (default: `rc4`) |
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

- **Encryption**: XOR (repeating-key), RC4, or AES-256-CTR — all decryptors are embedded in the stub without external dependencies
- **Stub size**: the generated Rust stub is typically under 200 lines and compiles to a few hundred KB
- **Memory execution**: uses `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` to allocate executable memory for the decoded data
- **No console window**: the stub uses `#![windows_subsystem = "windows"]` — no terminal pops up on execution
- **Static linking**: compiled with `-static-libgcc` and `-mwindows` for a fully self-contained binary

## License

MIT
