//! PDF decryption support (Standard Security Handler, R2-R4).
//!
//! Implements password verification and key derivation per the PDF spec,
//! plus per-object decryption using RC4 or AES-128-CBC.

use md5::{Digest, Md5};
use rc4::{KeyInit, Rc4, StreamCipher};

/// PDF encryption parameters parsed from the /Encrypt dictionary.
#[derive(Debug, Clone)]
pub struct EncryptionParams {
    /// /V — algorithm version (1, 2, or 4 for R2-R4).
    pub version: u32,
    /// /R — Standard security handler revision (2, 3, or 4).
    pub revision: u32,
    /// /Length — encryption key length in bits (default 40).
    pub key_length: u32,
    /// /O — owner password hash (32 bytes for R2-R4).
    pub owner_hash: Vec<u8>,
    /// /U — user password hash (32 bytes for R2-R4).
    pub user_hash: Vec<u8>,
    /// /P — permissions flags.
    pub permissions: i32,
    /// First element of trailer /ID array.
    pub file_id: Vec<u8>,
    /// Whether to use AES (true for R4 with /StmF or /StrF = /AESV2).
    pub use_aes: bool,
    /// Whether document metadata is encrypted (/EncryptMetadata, default true).
    pub encrypt_metadata: bool,
}

/// The standard 32-byte padding used in PDF encryption (ISO 32000-1, Table 20).
const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// Derive the file encryption key from a user password (Algorithm 2, PDF spec).
/// Works for Standard Security Handler R2-R4.
pub fn compute_encryption_key(params: &EncryptionParams, password: &[u8]) -> Vec<u8> {
    let key_len = (params.key_length / 8) as usize;

    // Step a: Pad or truncate password to exactly 32 bytes
    let mut padded = Vec::with_capacity(32);
    let take = password.len().min(32);
    padded.extend_from_slice(&password[..take]);
    if padded.len() < 32 {
        padded.extend_from_slice(&PADDING[..32 - padded.len()]);
    }

    // Steps b-f: MD5(padded || O || P || fileID [|| 0xFFFFFFFF])
    let mut hasher = Md5::new();
    hasher.update(&padded);
    hasher.update(&params.owner_hash);
    hasher.update(params.permissions.to_le_bytes());
    hasher.update(&params.file_id);
    // Step f (R>=4): when metadata is not encrypted, append 4 bytes of 0xFF
    if params.revision >= 4 && !params.encrypt_metadata {
        hasher.update([0xFFu8; 4]);
    }

    let mut hash = hasher.finalize().to_vec();

    // Step g: For R >= 3, re-hash 50 times (using only key_len bytes)
    if params.revision >= 3 {
        for _ in 0..50 {
            let mut h = Md5::new();
            h.update(&hash[..key_len]);
            hash = h.finalize().to_vec();
        }
    }

    hash.truncate(key_len);
    hash
}

/// Verify user password and return the encryption key if correct.
/// Algorithm 6 (R2) / Algorithm 7 (R3-R4) from the PDF spec.
pub fn authenticate_user_password(params: &EncryptionParams, password: &[u8]) -> Option<Vec<u8>> {
    let key = compute_encryption_key(params, password);

    if params.revision == 2 {
        // Algorithm 4: RC4-encrypt the 32-byte padding with the key
        let encrypted = rc4_crypt(&key, &PADDING);
        if encrypted[..] == params.user_hash[..32.min(params.user_hash.len())] {
            return Some(key);
        }
    } else if params.revision >= 3 && params.revision <= 4 {
        // Algorithm 5: MD5(padding || fileID), then 20 rounds of RC4
        let mut hasher = Md5::new();
        hasher.update(PADDING);
        hasher.update(&params.file_id);
        let hash = hasher.finalize();

        let mut encrypted = hash.to_vec();
        encrypted = rc4_crypt(&key, &encrypted);

        // 19 additional RC4 passes with XOR-modified keys
        for i in 1..=19u8 {
            let modified_key: Vec<u8> = key.iter().map(|&b| b ^ i).collect();
            encrypted = rc4_crypt(&modified_key, &encrypted);
        }

        // Compare first 16 bytes only (rest is random padding)
        if encrypted.len() >= 16
            && params.user_hash.len() >= 16
            && encrypted[..16] == params.user_hash[..16]
        {
            return Some(key);
        }
    }

    None
}

/// RC4 encrypt/decrypt (symmetric operation).
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cipher = Rc4::new_from_slice(key).expect("RC4 key length 1-256");
    let mut output = data.to_vec();
    cipher.apply_keystream(&mut output);
    output
}

/// Compute per-object decryption key (Algorithm 1 from the PDF spec).
///
/// file_key + obj_num (3 LE bytes) + gen_num (2 LE bytes) [+ "sAlT" for AES]
/// hashed with MD5, truncated to min(file_key.len()+5, 16).
pub fn object_key(file_key: &[u8], obj_num: u32, gen_num: u16, use_aes: bool) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(file_key);
    hasher.update(&obj_num.to_le_bytes()[..3]);
    hasher.update(&gen_num.to_le_bytes()[..2]);
    if use_aes {
        // AES salt per spec
        hasher.update(b"sAlT");
    }
    let hash = hasher.finalize();
    let key_len = (file_key.len() + 5).min(16);
    hash[..key_len].to_vec()
}

/// Decrypt a byte sequence using RC4.
pub fn decrypt_rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    rc4_crypt(key, data)
}

/// Decrypt a byte sequence using AES-128-CBC.
/// The first 16 bytes of `data` are the IV; the remainder is ciphertext.
pub fn decrypt_aes128(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use aes::Aes128;
    use cbc::cipher::{block_padding, BlockModeDecrypt, KeyIvInit};

    if data.len() < 16 || !data.len().is_multiple_of(16) {
        return None;
    }

    let iv = &data[..16];
    let ciphertext = &data[16..];

    if ciphertext.is_empty() {
        return Some(vec![]);
    }

    type Aes128CbcDec = cbc::Decryptor<Aes128>;

    // `object_key` truncates to `min(file_key.len() + 5, 16)`, so a document whose file key is
    // shorter than 11 bytes yields a key this cipher cannot take. Building the decryptor from
    // slices reports that as a length error, which this function already has a way to express;
    // converting the slice directly would panic on it instead, on a path fed by untrusted input.
    let decrypt_with = |padded: &mut Vec<u8>, pkcs7: bool| -> Option<Vec<u8>> {
        let decryptor = Aes128CbcDec::new_from_slices(key, iv).ok()?;
        let plaintext = if pkcs7 {
            decryptor.decrypt_padded::<block_padding::Pkcs7>(padded)
        } else {
            decryptor.decrypt_padded::<block_padding::NoPadding>(padded)
        };
        plaintext.ok().map(<[u8]>::to_vec)
    };

    // Try PKCS7 first
    let mut buf = ciphertext.to_vec();
    if let Some(plaintext) = decrypt_with(&mut buf, true) {
        return Some(plaintext);
    }

    // Fallback: no padding (some PDFs omit PKCS7)
    let mut buf2 = ciphertext.to_vec();
    decrypt_with(&mut buf2, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit pair"))
            .collect()
    }

    /// NIST SP 800-38A, F.2.2 (CBC-AES128.Decrypt), first two blocks.
    ///
    /// A known answer rather than a round-trip: encrypting and decrypting with the same crate
    /// agrees with itself even when both halves are wrong, which is exactly what a dependency
    /// upgrade could break without anything noticing.
    #[test]
    fn aes_128_cbc_matches_the_nist_known_answer() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let ciphertext = hex("7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2");
        let expected = hex("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51");

        // The function takes the IV prepended to the ciphertext, as PDF stores it.
        let mut data = iv;
        data.extend_from_slice(&ciphertext);

        // These blocks carry no PKCS7 padding, so the no-padding fallback is what answers.
        assert_eq!(decrypt_aes128(&key, &data), Some(expected));
    }

    #[test]
    fn a_pkcs7_padded_payload_comes_back_without_its_padding() {
        // Same key/IV; ciphertext produced from "unparser" padded to one block under PKCS7.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");

        use aes::Aes128;
        use cbc::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
        let plaintext = b"unparser";
        let mut buf = [0u8; 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct = cbc::Encryptor::<Aes128>::new_from_slices(&key, &iv)
            .expect("16-byte key and iv")
            .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
            .expect("one block of room")
            .to_vec();

        let mut data = iv;
        data.extend_from_slice(&ct);

        assert_eq!(decrypt_aes128(&key, &data).as_deref(), Some(&plaintext[..]));
    }

    /// `object_key` truncates to `min(file_key.len() + 5, 16)`, so a document whose file key is
    /// shorter than 11 bytes produces a key AES-128 cannot take. Before the cipher 0.5 migration
    /// this reached a slice-to-array conversion that panics on a length mismatch -- on a path
    /// whose input is an untrusted file.
    #[test]
    fn a_key_the_cipher_cannot_take_is_refused_rather_than_panicking() {
        let short_key = object_key(&[0xAB; 4], 1, 0, true);
        assert!(
            short_key.len() < 16,
            "the truncation rule should yield 9 bytes here"
        );

        let data = vec![0u8; 32]; // a well-formed IV + one ciphertext block
        assert_eq!(decrypt_aes128(&short_key, &data), None);
    }

    #[test]
    fn a_payload_that_is_not_a_whole_number_of_blocks_is_refused() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(decrypt_aes128(&key, &[0u8; 20]), None);
        assert_eq!(decrypt_aes128(&key, &[0u8; 8]), None);
    }

    #[test]
    fn an_iv_with_no_ciphertext_after_it_decrypts_to_nothing() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(decrypt_aes128(&key, &[0u8; 16]), Some(vec![]));
    }
}
