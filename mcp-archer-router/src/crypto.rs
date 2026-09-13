//! Primitive crittografiche del pannello TP-Link Archer ("GDPR encrypt").
//!
//! Vedi PROTOCOL.md nella root del repository per la descrizione completa
//! del protocollo, ricostruita con reverse engineering della WebUI. Riassunto:
//! RSA 512 bit "raw" (nessun padding PKCS#1, blocchi da 64 byte riempiti di
//! zeri a destra) per firmare le richieste e scambiare la chiave di sessione,
//! AES-128-CBC/PKCS7 per cifrare il payload applicativo.

use aes::Aes128;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use num_traits::Num;
use rand::RngExt;

const RSA_BITS: usize = 512;
const BLOCK_BYTES: usize = RSA_BITS / 8; // 64 byte per blocco RSA senza padding
const HEX_BYTES_PER_BLOCK: usize = BLOCK_BYTES; // output zero-paddato a 64 byte (128 hex) per blocco

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub fn md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}

/// Replica `$.rsa.encrypt(text, nn, ee, 512, 0)` di encrypt.js: nessun
/// padding PKCS#1, blocchi da 64 byte riempiti di zeri a destra, `m^e mod n`,
/// output esadecimale zero-paddato a 128 caratteri per blocco.
pub fn rsa_raw_encrypt(plaintext: &str, n_hex: &str, e_hex: &str) -> Result<String, String> {
    let n =
        BigUint::from_str_radix(n_hex, 16).map_err(|e| format!("modulo RSA non valido: {e}"))?;
    let e =
        BigUint::from_str_radix(e_hex, 16).map_err(|e| format!("esponente RSA non valido: {e}"))?;
    let data = plaintext.as_bytes();
    let mut out = String::new();
    for chunk in data.chunks(BLOCK_BYTES).collect::<Vec<_>>().iter().copied() {
        let mut buf = [0u8; BLOCK_BYTES];
        buf[..chunk.len()].copy_from_slice(chunk);
        let m = BigUint::from_bytes_be(&buf);
        let c = m.modpow(&e, &n);
        let mut c_bytes = c.to_bytes_be();
        if c_bytes.len() < HEX_BYTES_PER_BLOCK {
            let mut padded = vec![0u8; HEX_BYTES_PER_BLOCK - c_bytes.len()];
            padded.extend_from_slice(&c_bytes);
            c_bytes = padded;
        }
        out.push_str(&hex::encode(c_bytes));
    }
    // Anche un plaintext vuoto (non dovrebbe capitare) produrrebbe zero
    // blocchi: non è un caso previsto dal protocollo, ma non vale la pena
    // farlo fallire esplicitamente qui.
    Ok(out)
}

pub fn aes_encrypt(plaintext: &str, key: &str, iv: &str) -> String {
    let key: &[u8; 16] = key
        .as_bytes()
        .try_into()
        .expect("chiave AES-128 deve essere lunga 16 byte");
    let iv: &[u8; 16] = iv
        .as_bytes()
        .try_into()
        .expect("IV AES-128 deve essere lungo 16 byte");
    let ct: Vec<u8> =
        Aes128CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext.as_bytes());
    B64.encode(ct)
}

pub fn aes_decrypt(b64_ciphertext: &str, key: &str, iv: &str) -> String {
    let trimmed = b64_ciphertext.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let Ok(ct) = B64.decode(trimmed) else {
        return String::new();
    };
    let (Ok(key), Ok(iv)) = (
        <&[u8; 16]>::try_from(key.as_bytes()),
        <&[u8; 16]>::try_from(iv.as_bytes()),
    ) else {
        return String::new();
    };
    let Ok(pt) = Aes128CbcDec::new(key.into(), iv.into()).decrypt_padded_vec::<Pkcs7>(&ct) else {
        return String::new();
    };
    String::from_utf8_lossy(&pt)
        .trim_end_matches('\0')
        .to_string()
}

/// Riproduce `genKey()` di tpEncrypt.js: 16 byte ASCII "casuali" (nel
/// client originale sono cifre di timestamp+random; qui basta una stringa
/// ASCII di 16 caratteri qualunque, dato che viene comunque scambiata
/// cifrata via RSA e usata solo per la sessione corrente - vedi PROTOCOL.md
/// §2.2).
pub fn random_token16_pair() -> (String, String) {
    (random_token16(), random_token16())
}

fn random_token16() -> String {
    let mut rng = rand::rng();
    (0..16)
        .map(|_| char::from(b'0' + rng.random_range(0..10)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_known_vector() {
        assert_eq!(md5_hex("userpassword"), "d440aed189a13ff970dac7e7e8f987b2");
    }

    #[test]
    fn aes_roundtrip() {
        let key = "1234567890123456";
        let iv = "6543210987654321";
        let plaintext = r#"{"data":{"a":1},"operation":"go","oid":"X"}"#;
        let ct = aes_encrypt(plaintext, key, iv);
        let pt = aes_decrypt(&ct, key, iv);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn rsa_raw_roundtrip_via_known_keypair() {
        // Chiave RSA 512 bit generata al volo con `openssl genrsa 512` solo
        // per questo test (non ha nulla a che fare con un router reale):
        // verifica che il blocking/padding "zeri a destra, 64 byte" e la
        // codifica esadecimale del risultato siano quelli attesi, cifrando
        // con la chiave pubblica e decifrando manualmente con la privata
        // corrispondente (m^e mod n, poi c^d mod n = m).
        let n_hex = "b651027704b0c1ce7fd43af867176ddd4d3532b5893fded548e44860ae549dda5ba0abbd89aa97b933511d662a46ae6cc9a55c090ab69fa4880caf7fa392a7e3";
        let e_hex = "010001";
        let d_hex = "b444254bc9377c69d1bae713f5db14a65c50dd72e1e265523e6079b01eaf4be390ab219729be6df89bc6f90dac1fcbcda1ca81ab3a9279d2c19d6fea51f52501";

        let plaintext = "key=1234567890123456&iv=6543210987654321&h=deadbeef&s=42";
        let sign_hex = rsa_raw_encrypt(plaintext, n_hex, e_hex).unwrap();
        assert_eq!(
            sign_hex.len(),
            128,
            "un blocco da 64 byte = 128 caratteri hex"
        );

        let n = BigUint::from_str_radix(n_hex, 16).unwrap();
        let d = BigUint::from_str_radix(d_hex, 16).unwrap();
        let c = BigUint::from_bytes_be(&hex::decode(&sign_hex).unwrap());
        let m = c.modpow(&d, &n);
        let mut recovered = m.to_bytes_be();
        while recovered.len() < BLOCK_BYTES {
            recovered.insert(0, 0);
        }

        let mut expected = vec![0u8; BLOCK_BYTES];
        expected[..plaintext.len()].copy_from_slice(plaintext.as_bytes());
        assert_eq!(recovered, expected);
    }
}
