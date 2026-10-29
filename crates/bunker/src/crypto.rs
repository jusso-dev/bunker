use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub fn random<const N: usize>() -> [u8; N] {
    let mut value = [0; N];
    OsRng.fill_bytes(&mut value);
    value
}

pub fn derive(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    if passphrase.len() < 12 {
        bail!("passphrase must contain at least 12 bytes");
    }
    let mut key = Zeroizing::new([0; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| anyhow!("key derivation failed"))?;
    Ok(key)
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<24>();
    let cipher = XChaCha20Poly1305::new(key.into());
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut output = nonce.to_vec();
    output.extend(encrypted);
    Ok(output)
}

pub fn open(key: &[u8; 32], ciphertext: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let nonce = ciphertext.get(..24).context("truncated encrypted object")?;
    let payload = ciphertext.get(24..).context("truncated encrypted object")?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: payload,
                aad: context,
            },
        )
        .map_err(|_| anyhow!("authentication failed: wrong key or damaged object"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_and_context_bound() {
        let key = random();
        let mut encrypted = seal(&key, b"private", b"chunk:1").unwrap();
        assert_eq!(&**open(&key, &encrypted, b"chunk:1").unwrap(), b"private");
        assert!(open(&key, &encrypted, b"chunk:2").is_err());
        encrypted[25] ^= 1;
        assert!(open(&key, &encrypted, b"chunk:1").is_err());
        for len in 0..40 {
            assert!(open(&key, &vec![0; len], b"chunk:1").is_err());
        }
    }
}
