// pifcrypt: integrity-bound sealing of the module configuration seed.
//
// The encryption key is derived at runtime from the byte content of a fixed,
// ordered set of module files (the "manifest") plus this binary itself. The
// key is never stored. Sealing occurs at build time; unsealing occurs on
// device. Reproduction of the key requires the manifest inputs to be
// byte-identical to their build-time state. Any modification alters the derived
// key, and AES-256-GCM authentication then fails on unseal, yielding no output.
//
// The construction is a key-derivation binding, not an integrity check: there
// is no stored digest to compare and therefore no branch to bypass. Deriving
// the correct key is only possible from unmodified inputs.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::process::exit;

// Container header: 8-byte magic, 1-byte version, 12-byte GCM nonce, then
// ciphertext with appended 16-byte authentication tag.
const MAGIC: &[u8; 8] = b"PIFCRYP1";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + NONCE_LEN;

// Domain-separation label for the key-derivation transcript. A change to this
// label changes every derived key.
const KDF_LABEL: &[u8] = b"pifcrypt-key-v1\0";

// Ordered manifest of files bound into the key, expressed relative to the
// module directory. Selection criteria: each entry must be present and
// byte-stable at the moment the runtime unseal executes.
//
// Excluded by design:
//   - module.prop        : rewritten by the module manager at runtime.
//   - action.sh          : renamed to action.sh.old by post-fs-data.sh under
//                          KernelSU/APatch; not stable at runtime.
//   - pif.prop / *.enc   : the payload, not a binding input.
//   - customize.sh       : install-time only; not guaranteed present at runtime.
//
// Order and path strings are part of the transcript; reordering or renaming any
// entry changes the derived key.
const MANIFEST: &[&str] = &[
    "post-fs-data.sh",
    "service.sh",
    "autopif.sh",
    "common_func.sh",
    "security_patch.sh",
    "bin/pifcrypt",
];

fn die(msg: &str) -> ! {
    eprintln!("pifcrypt: {msg}");
    exit(1);
}

// Derives the 32-byte key by folding a length-prefixed transcript of each
// manifest file's relative path and content digest into an outer SHA-256.
// Length prefixes on both the path and the per-file digest remove concatenation
// ambiguity between adjacent entries.
fn derive_key(moddir: &str) -> [u8; 32] {
    let mut outer = Sha256::new();
    outer.update(KDF_LABEL);
    outer.update((MANIFEST.len() as u64).to_le_bytes());
    for rel in MANIFEST {
        let path = format!("{moddir}/{rel}");
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => die(&format!("read {path}: {e}")),
        };
        let fh = Sha256::digest(&bytes);
        outer.update((rel.len() as u64).to_le_bytes());
        outer.update(rel.as_bytes());
        outer.update((fh.len() as u64).to_le_bytes());
        outer.update(fh);
    }
    let out = outer.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn cipher_for(moddir: &str) -> Aes256Gcm {
    let key = derive_key(moddir);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
}

fn cmd_encrypt(moddir: &str, infile: &str, outfile: &str) {
    let pt = std::fs::read(infile).unwrap_or_else(|e| die(&format!("read {infile}: {e}")));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).unwrap_or_else(|e| die(&format!("rng: {e}")));
    let ct = cipher_for(moddir)
        .encrypt(Nonce::from_slice(&nonce), pt.as_ref())
        .unwrap_or_else(|_| die("encrypt failed"));
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    std::fs::write(outfile, out).unwrap_or_else(|e| die(&format!("write {outfile}: {e}")));
}

fn cmd_decrypt(moddir: &str, infile: &str, outfile: &str) {
    let blob = std::fs::read(infile).unwrap_or_else(|e| die(&format!("read {infile}: {e}")));
    if blob.len() < HEADER_LEN + TAG_LEN || &blob[0..8] != MAGIC {
        die("malformed container");
    }
    if blob[8] != VERSION {
        die("unsupported container version");
    }
    let nonce = &blob[9..9 + NONCE_LEN];
    let ct = &blob[HEADER_LEN..];
    // GCM verifies the authentication tag prior to returning plaintext; a
    // derived-key mismatch or ciphertext tamper produces an error and no bytes.
    let pt = cipher_for(moddir)
        .decrypt(Nonce::from_slice(nonce), ct)
        .unwrap_or_else(|_| die("authentication failed"));
    // Output is written only after successful authenticated decryption, via a
    // temporary file and atomic rename, so a consumer never observes a partial
    // or unauthenticated result.
    let tmp = format!("{outfile}.tmp");
    std::fs::write(&tmp, &pt).unwrap_or_else(|e| die(&format!("write {tmp}: {e}")));
    std::fs::rename(&tmp, outfile).unwrap_or_else(|e| die(&format!("rename {tmp}: {e}")));
}

fn cmd_derive_key(moddir: &str) {
    println!("{}", hex::encode(derive_key(moddir)));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Usage:
    //   pifcrypt encrypt    --moddir DIR IN OUT
    //   pifcrypt decrypt    --moddir DIR IN OUT
    //   pifcrypt derive-key --moddir DIR
    let mut moddir: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--moddir" {
            i += 1;
            if i >= args.len() {
                die("--moddir requires a value");
            }
            moddir = Some(args[i].clone());
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let moddir = moddir.unwrap_or_else(|| die("--moddir is required"));
    match cmd {
        "encrypt" => {
            if positional.len() != 2 {
                die("encrypt requires IN and OUT");
            }
            cmd_encrypt(&moddir, &positional[0], &positional[1]);
        }
        "decrypt" => {
            if positional.len() != 2 {
                die("decrypt requires IN and OUT");
            }
            cmd_decrypt(&moddir, &positional[0], &positional[1]);
        }
        "derive-key" => cmd_derive_key(&moddir),
        _ => die("usage: pifcrypt <encrypt|decrypt|derive-key> --moddir DIR [IN OUT]"),
    }
}
