//! # AES-CBC
//!
//! Implementation of CBC-mode AES cipher/decipher.
//!

use crate::aes::{AESError, AES, BLOCK_SIZE};
use crate::pkcs7;

use std::error::Error;
use std::fmt;
use std::fmt::Display;

///
/// Main AES-CBC Cipher structure.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use dumb_crypto::aes::BLOCK_SIZE;
/// use dumb_crypto::aes_cbc::Cipher;
///
/// let iv = [
///     0x4c, 0xb4, 0x52, 0xd6, 0x78, 0xca, 0x94, 0x61,
///     0x92, 0xcd, 0xc6, 0x91, 0xb7, 0xab, 0x61, 0x76,
/// ];
/// let key: [u8; 16] = [
///     0x69, 0xc2, 0xa9, 0xe6, 0x2b, 0x61, 0x30, 0x60,
///     0xc9, 0x79, 0x7b, 0xdc, 0xe4, 0xf6, 0x40, 0x8e,
/// ];
/// let mut cipher = Cipher::new(iv);
/// cipher.init(&key).unwrap();
///
/// let mut ciphertext = cipher.write("aes-cbc with iv".as_bytes()).unwrap();
/// ciphertext.append(&mut cipher.flush().unwrap());
/// ```
///
pub struct Cipher {
    aes: AES,
    pad: pkcs7::Pad,
    iv: [u8; BLOCK_SIZE],
}

impl Cipher {
    /// Create new instance of AES-CBC Cipher
    ///
    /// `iv` - Initialization Vector (this better be a very random value)
    pub fn new(iv: [u8; BLOCK_SIZE]) -> Self {
        Cipher {
            aes: AES::new(),
            pad: pkcs7::Pad::new(BLOCK_SIZE),
            iv,
        }
    }

    /// Initialize instance of AES-CBC Cipher
    ///
    /// `key` - AES Key. Must be either 128, 192, or 256 bits.
    pub fn init(&mut self, key: &[u8]) -> Result<(), AESError> {
        self.aes.init(key)?;
        Ok(())
    }

    /// Encrypt data
    pub fn write(&mut self, b: &[u8]) -> Result<Vec<u8>, AESError> {
        let blocks = match self.pad.write(b) {
            None => {
                return Ok(vec![]);
            }
            Some(block) => block,
        };

        let mut result: Vec<u8> = Vec::with_capacity(blocks.len());
        for block in blocks.chunks(BLOCK_SIZE) {
            let mut ciphertext = self.encrypt_block(block)?;
            result.append(&mut ciphertext);
        }
        Ok(result)
    }

    /// Encrypt and return final cipher block
    pub fn flush(&mut self) -> Result<Vec<u8>, AESError> {
        let block = self.pad.flush();
        Ok(self.encrypt_block(&block)?)
    }

    fn encrypt_block(&mut self, b: &[u8]) -> Result<Vec<u8>, AESError> {
        let mut block = [0; BLOCK_SIZE];
        block.copy_from_slice(&b);

        for (elem, iv_elem) in block.iter_mut().zip(self.iv.iter()) {
            *elem ^= iv_elem;
        }

        match self.aes.encrypt(&block) {
            Ok(new_iv) => {
                self.iv = new_iv;
                Ok(new_iv.to_vec())
            }
            Err(err) => Err(err),
        }
    }
}

///
/// Main AES-CBC Decipher structure.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use::dumb_crypto::aes::BLOCK_SIZE;
/// use::dumb_crypto::aes_cbc::Decipher;
///
/// let iv = [
///     0x4c, 0xb4, 0x52, 0xd6, 0x78, 0xca, 0x94, 0x61,
///     0x92, 0xcd, 0xc6, 0x91, 0xb7, 0xab, 0x61, 0x76,
/// ];
/// let key: [u8; 16] = [
///     0x69, 0xc2, 0xa9, 0xe6, 0x2b, 0x61, 0x30, 0x60,
///     0xc9, 0x79, 0x7b, 0xdc, 0xe4, 0xf6, 0x40, 0x8e,
/// ];
/// let mut decipher = Decipher::new(iv);
/// decipher.init(&key).unwrap();
///
/// let mut cleartext = decipher.write(&[
///     0x98, 0xba, 0x8e, 0x07, 0x5b, 0xcf, 0xa7, 0xb9,
///     0x3a, 0xbe, 0x45, 0x3a, 0xb1, 0x84, 0xdc, 0x68,
/// ]).unwrap();
/// cleartext.append(&mut decipher.flush().unwrap());
/// ```
///
pub struct Decipher {
    aes: AES,
    unpad: pkcs7::Unpad,
    iv: [u8; BLOCK_SIZE],
    buffer: pkcs7::Pad,
}

/// Possible decipher errors
#[derive(Debug, PartialEq)]
pub enum DecipherError {
    /// Returned on AES-specific errors
    AES(AESError),
    /// Returned on PKCS7-specific padding errors
    PKCS7(pkcs7::UnpadError),
}

impl Display for DecipherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DecipherError: {}", self.description())
    }
}

impl Error for DecipherError {
    fn description(&self) -> &str {
        // TODO(indutny): prefix description
        match self {
            DecipherError::AES(err) => err.description(),
            DecipherError::PKCS7(err) => err.description(),
        }
    }
}

impl Decipher {
    /// Create new instance of AES-CBC Decipher
    ///
    /// `iv` - Initialization Vector (this better be a very random value)
    pub fn new(iv: [u8; BLOCK_SIZE]) -> Self {
        Decipher {
            aes: AES::new(),
            unpad: pkcs7::Unpad::new(BLOCK_SIZE),
            iv,
            buffer: pkcs7::Pad::new(BLOCK_SIZE),
        }
    }

    /// Initialize instance of AES-CBC Decipher
    ///
    /// `key` - AES Key. Must be either 128, 192, or 256 bits.
    pub fn init(&mut self, key: &[u8]) -> Result<(), AESError> {
        self.aes.init(key)?;
        Ok(())
    }

    /// Decrypt data
    pub fn write(&mut self, b: &[u8]) -> Result<Vec<u8>, DecipherError> {
        let blocks = match self.buffer.write(b) {
            Some(blocks) => blocks,
            None => {
                return Ok(vec![]);
            }
        };

        let mut padded_result = Vec::with_capacity(blocks.len());
        for ciphertext in blocks.chunks(BLOCK_SIZE) {
            let mut block = [0; BLOCK_SIZE];
            block.copy_from_slice(&ciphertext);

            let mut cleartext = match self.aes.decrypt(&block) {
                Err(err) => return Err(DecipherError::AES(err)),
                Ok(out) => out,
            };

            for (elem, iv_elem) in cleartext.iter_mut().zip(self.iv.iter()) {
                *elem ^= iv_elem;
            }

            self.iv = block;
            padded_result.append(&mut cleartext.to_vec());
        }

        Ok(self.unpad.write(&padded_result).unwrap_or_default())
    }

    /// Decrypt and return final cleartext data
    pub fn flush(&mut self) -> Result<Vec<u8>, DecipherError> {
        match self.unpad.flush() {
            Err(err) => Err(DecipherError::PKCS7(err)),
            Ok(block) => Ok(block),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::hex_to_vec;

    fn check(key: &str, iv: &str, cleartext: &str, ciphertext: &str) {
        let key_vec = hex_to_vec(key);
        let mut iv_arr = [0; BLOCK_SIZE];
        iv_arr.copy_from_slice(&hex_to_vec(iv));

        let mut cipher = Cipher::new(iv_arr);
        cipher.init(&key_vec).expect("cipher init to not fail");

        let mut actual = cipher
            .write(cleartext.as_bytes())
            .expect("cipher write to not fail");
        actual.append(&mut cipher.flush().expect("cipher flush to not fail"));

        assert_eq!(actual, hex_to_vec(ciphertext));

        let mut decipher = Decipher::new(iv_arr);
        decipher.init(&key_vec).expect("decipher init to not fail");
        let mut back = decipher
            .write(&hex_to_vec(ciphertext))
            .expect("decipher write to not fail");
        back.append(&mut decipher.flush().expect("decipher flush to not fail"));

        assert_eq!(back, cleartext.as_bytes());
    }

    #[test]
    fn it_should_not_fail_on_vec_0() {
        check(
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "hello",
            "9834ed518cbc8fbe9af3c6ecb75eb8c0",
        );
    }

    #[test]
    fn it_should_not_fail_on_vec_1() {
        check(
            "69c2a9e62b613060c9797bdce4f6408e",
            "4cb452d678ca946192cdc691b7ab6176",
            "aes-cbc with iv",
            "98ba8e075bcfa7b93abe453ab184dc68",
        );
    }

    #[test]
    fn it_should_not_fail_on_vec_2() {
        check(
            "57e79712f7b7813490b63446e1bec39f",
            "a32fd274f2d5392f1a217aaa37a5a44d",
            "several AES blocks means more xoring",
            "d1aa1d92d6a93c84032ae322102aba62692b2548e92abc9f8d19bb42dd172e84c4102ff8d45889011b87de27f6d91ae4",
        );
    }
}
