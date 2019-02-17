//! # AES
//!
//! Implementation of AES encryption/decryption algorithm according to
//! [FIPS 197][fips].
//!
//! [fips]: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
//!

use std::error::Error;
use std::fmt;
use std::fmt::Display;

pub const BLOCK_SIZE: usize = 16;
const NB: usize = 4;

// Note: block[column][row]
type Block = [[u8; 4]; 4];

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Rcon[i], contains the values given by [ x^(i - 1), 0, 0, 0 ], with x^(i - 1)
// being powers of x (x denoted as {02}) in the field GF(2^8). (note that i
// starts at 1, not 0)
const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

// Double the number in the binary field.
fn double(b: u8) -> u8 {
    if (b & 0x80) == 0 {
        b << 1
    } else {
        (b << 1) ^ 0x1b
    }
}

// Multiply the number by another number in the binary field.
fn mul(b: u8, mut by: usize) -> u8 {
    let mut res: u8 = 0;
    let mut power = b;
    while by != 0 {
        if (by & 1) != 0 {
            res ^= power;
        }
        power = double(power);
        by >>= 1;
    }
    res
}

fn sub_word(b: u32) -> u32 {
    let b0 = (b >> 24) as usize;
    let b1 = ((b >> 16) & 0xff) as usize;
    let b2 = ((b >> 8) & 0xff) as usize;
    let b3 = (b & 0xff) as usize;

    (u32::from(SBOX[b0]) << 24)
        | (u32::from(SBOX[b1]) << 16)
        | (u32::from(SBOX[b2]) << 8)
        | u32::from(SBOX[b3])
}

fn rot_word(b: u32) -> u32 {
    (b << 8) | (b >> 24)
}

fn expand_key(key: &[u8], round_count: usize) -> Vec<u32> {
    // byte key[4*Nk]
    let nk = key.len() / 4;

    // word w[Nb*(Nr+1)]
    let mut w = Vec::with_capacity(NB * (round_count + 1));

    //  word  temp
    //  i = 0
    //  while (i < Nk)
    //      w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
    //      i = i+1
    //  end while

    let mut i: usize = 0;
    while i < nk {
        w.push(
            (u32::from(key[4 * i]) << 24)
                | (u32::from(key[4 * i + 1]) << 16)
                | (u32::from(key[4 * i + 2]) << 8)
                | u32::from(key[4 * i + 3]),
        );
        i += 1;
    }

    //  i = Nk
    //  while (i < Nb * (Nr+1)]
    //      temp = w[i-1]
    //      if (i mod Nk = 0)
    //          temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
    //      else if (Nk > 6 and i mod Nk = 4)
    //          temp = SubWord(temp)
    //      end if
    //      w[i] = w[i-Nk] xor temp
    //      i = i + 1
    //  end while
    while i < NB * (round_count + 1) {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w.push(w[i - nk] ^ temp);
        i += 1;
    }

    w
}

trait AESSide {
    fn lookup_sbox(b: u8) -> u8;
    fn mix_column(col: [u8; 4]) -> [u8; 4];
    fn shift_rows(s: &Block) -> Block;

    // Common methods

    fn add_round_key(s: &mut Block, round_key: &[u32]) {
        for (col, &key) in s.iter_mut().zip(round_key) {
            col[0] ^= (key >> 24) as u8;
            col[1] ^= ((key >> 16) & 0xff) as u8;
            col[2] ^= ((key >> 8) & 0xff) as u8;
            col[3] ^= (key & 0xff) as u8;
        }
    }

    fn sub_bytes(s: &mut Block) {
        for col in s.iter_mut() {
            for cell in col.iter_mut() {
                *cell = Self::lookup_sbox(*cell);
            }
        }
    }

    fn mix_columns(s: &mut Block) {
        for column in s.iter_mut() {
            *column = Self::mix_column(*column);
        }
    }
}

struct AESEncrypt {}
struct AESDecrypt {}

impl AESSide for AESEncrypt {
    fn lookup_sbox(b: u8) -> u8 {
        SBOX[usize::from(b)]
    }

    fn mix_column(col: [u8; 4]) -> [u8; 4] {
        [
            mul(col[0], 2) ^ mul(col[1], 3) ^ col[2] ^ col[3],
            mul(col[1], 2) ^ mul(col[2], 3) ^ col[3] ^ col[0],
            mul(col[2], 2) ^ mul(col[3], 3) ^ col[0] ^ col[1],
            mul(col[3], 2) ^ mul(col[0], 3) ^ col[1] ^ col[2],
        ]
    }

    fn shift_rows(s: &Block) -> Block {
        [
            [s[0][0], s[1][1], s[2][2], s[3][3]],
            [s[1][0], s[2][1], s[3][2], s[0][3]],
            [s[2][0], s[3][1], s[0][2], s[1][3]],
            [s[3][0], s[0][1], s[1][2], s[2][3]],
        ]
    }
}

impl AESSide for AESDecrypt {
    fn lookup_sbox(b: u8) -> u8 {
        INV_SBOX[usize::from(b)]
    }

    fn mix_column(col: [u8; 4]) -> [u8; 4] {
        [
            mul(col[0], 0x0e) ^ mul(col[1], 0x0b) ^ mul(col[2], 0x0d) ^ mul(col[3], 0x09),
            mul(col[1], 0x0e) ^ mul(col[2], 0x0b) ^ mul(col[3], 0x0d) ^ mul(col[0], 0x09),
            mul(col[2], 0x0e) ^ mul(col[3], 0x0b) ^ mul(col[0], 0x0d) ^ mul(col[1], 0x09),
            mul(col[3], 0x0e) ^ mul(col[0], 0x0b) ^ mul(col[1], 0x0d) ^ mul(col[2], 0x09),
        ]
    }

    fn shift_rows(s: &Block) -> Block {
        [
            [s[0][0], s[3][1], s[2][2], s[1][3]],
            [s[1][0], s[0][1], s[3][2], s[2][3]],
            [s[2][0], s[1][1], s[0][2], s[3][3]],
            [s[3][0], s[2][1], s[1][2], s[0][3]],
        ]
    }
}

fn to_block(b: &[u8; BLOCK_SIZE]) -> Block {
    [
        [b[0], b[1], b[2], b[3]],
        [b[4], b[5], b[6], b[7]],
        [b[8], b[9], b[10], b[11]],
        [b[12], b[13], b[14], b[15]],
    ]
}

fn from_block(s: &Block) -> [u8; BLOCK_SIZE] {
    [
        s[0][0], s[0][1], s[0][2], s[0][3], s[1][0], s[1][1], s[1][2], s[1][3], s[2][0], s[2][1],
        s[2][2], s[2][3], s[3][0], s[3][1], s[3][2], s[3][3],
    ]
}

/// Possible initialization errors
#[derive(Debug, PartialEq)]
pub enum AESError {
    /// Returned when key size is neither of: 128, 192, or 256 bits.
    InvalidKeySize,

    /// Returned when attempting encryption/decryption on non-initialized AES
    /// instance
    NotInitialized,
}

impl Display for AESError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AESError: {}", self.description())
    }
}

impl Error for AESError {
    fn description(&self) -> &str {
        match self {
            AESError::InvalidKeySize => "key size must be either of: 128, 192, or 256 bits",
            AESError::NotInitialized => "AES instance must be initialized prior to use",
        }
    }
}

///
/// Main AES structure.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use dumb_crypto::aes::{AES, BLOCK_SIZE};
///
/// let mut aes = AES::new();
/// let key: [u8; 16] = [
///     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
/// ];
/// aes.init(&key).unwrap();
///
/// let cleartext: [u8; BLOCK_SIZE] = [
///     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
///     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
/// ];
///
/// let ciphertext = aes.encrypt(&cleartext).unwrap();
///
/// assert_eq!(aes.decrypt(&ciphertext).unwrap(), cleartext);
/// ```
///
pub struct AES {
    round_count: usize,
    round_keys: Option<Vec<u32>>,
}

impl AES {
    /// Create new uninitialized instance of AES.
    pub fn new() -> Self {
        AES {
            round_count: 0,
            round_keys: None,
        }
    }

    /// Initialize an instance with a encryption/decryption key.
    pub fn init(&mut self, key: &[u8]) -> Result<(), AESError> {
        self.round_count = match key.len() {
            // 128 bits
            16 => 10,

            // 192 bits
            24 => 12,

            // 256 bits
            32 => 14,

            // Invalid key size
            _ => {
                return Err(AESError::InvalidKeySize);
            }
        };
        self.round_keys = Some(expand_key(key, self.round_count));

        Ok(())
    }

    /// Encrypt block of data.
    pub fn encrypt(&self, b: &[u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE], AESError> {
        let nr = self.round_count;

        let mut state = to_block(b);
        let round_keys = match &self.round_keys {
            Some(keys) => keys,
            None => {
                return Err(AESError::NotInitialized);
            }
        };

        AESEncrypt::add_round_key(&mut state, &round_keys[0..NB]);

        for round in 1..nr {
            AESEncrypt::sub_bytes(&mut state);
            state = AESEncrypt::shift_rows(&state);
            AESEncrypt::mix_columns(&mut state);
            AESEncrypt::add_round_key(&mut state, &round_keys[(round * NB)..((round + 1) * NB)]);
        }

        AESEncrypt::sub_bytes(&mut state);
        state = AESEncrypt::shift_rows(&state);
        AESEncrypt::add_round_key(&mut state, &round_keys[(nr * NB)..]);

        Ok(from_block(&state))
    }

    /// Decrypt block of data.
    pub fn decrypt(&self, b: &[u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE], AESError> {
        let nr = self.round_count;

        let mut state = to_block(b);
        let round_keys = match &self.round_keys {
            Some(keys) => keys,
            None => {
                return Err(AESError::NotInitialized);
            }
        };

        AESDecrypt::add_round_key(&mut state, &round_keys[(nr * NB)..]);

        for round in (1..nr).rev() {
            state = AESDecrypt::shift_rows(&state);
            AESDecrypt::sub_bytes(&mut state);
            AESDecrypt::add_round_key(&mut state, &round_keys[(round * NB)..((round + 1) * NB)]);
            AESDecrypt::mix_columns(&mut state);
        }

        state = AESDecrypt::shift_rows(&state);
        AESDecrypt::sub_bytes(&mut state);
        AESDecrypt::add_round_key(&mut state, &round_keys[0..NB]);

        Ok(from_block(&state))
    }
}

impl Default for AES {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::hex_to_vec;

    const TEST_BLOCK: Block = [
        [0x37, 0xd7, 0xa0, 0x2d],
        [0x8a, 0x65, 0xc1, 0x96],
        [0xda, 0xee, 0x01, 0x99],
        [0xb9, 0x9e, 0x55, 0x65],
    ];

    #[test]
    fn it_should_multiply_in_field() {
        assert_eq!(mul(1, 2), 2);
        assert_eq!(mul(1, 3), 3);

        assert_eq!(mul(0x57, 0x02), 0xae);
        assert_eq!(mul(0x57, 0x04), 0x47);
        assert_eq!(mul(0x57, 0x08), 0x8e);
        assert_eq!(mul(0x57, 0x10), 0x07);
        assert_eq!(mul(0x57, 0x13), 0xfe);
    }

    #[test]
    fn it_should_inverse_sub_bytes() {
        let mut s: Block = TEST_BLOCK;
        AESEncrypt::sub_bytes(&mut s);
        AESDecrypt::sub_bytes(&mut s);
        assert_eq!(s, TEST_BLOCK);
    }

    #[test]
    fn it_should_inverse_mix_columns() {
        let mut s: Block = TEST_BLOCK;
        AESEncrypt::mix_columns(&mut s);
        AESDecrypt::mix_columns(&mut s);
        assert_eq!(s, TEST_BLOCK);
    }

    #[test]
    fn it_should_inverse_shift_rows() {
        let t = AESEncrypt::shift_rows(&TEST_BLOCK);
        assert_eq!(AESDecrypt::shift_rows(&t), TEST_BLOCK);
    }

    #[test]
    fn it_should_expand_128bit_key() {
        assert_eq!(
            expand_key(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c
                ],
                10
            ),
            vec![
                0x2b7e_1516,
                0x28ae_d2a6,
                0xabf7_1588,
                0x09cf_4f3c,
                0xa0fa_fe17,
                0x8854_2cb1,
                0x23a3_3939,
                0x2a6c_7605,
                0xf2c2_95f2,
                0x7a96_b943,
                0x5935_807a,
                0x7359_f67f,
                0x3d80_477d,
                0x4716_fe3e,
                0x1e23_7e44,
                0x6d7a_883b,
                0xef44_a541,
                0xa852_5b7f,
                0xb671_253b,
                0xdb0b_ad00,
                0xd4d1_c6f8,
                0x7c83_9d87,
                0xcaf2_b8bc,
                0x11f9_15bc,
                0x6d88_a37a,
                0x110b_3efd,
                0xdbf9_8641,
                0xca00_93fd,
                0x4e54_f70e,
                0x5f5f_c9f3,
                0x84a6_4fb2,
                0x4ea6_dc4f,
                0xead2_7321,
                0xb58d_bad2,
                0x312b_f560,
                0x7f8d_292f,
                0xac77_66f3,
                0x19fa_dc21,
                0x28d1_2941,
                0x575c_006e,
                0xd014_f9a8,
                0xc9ee_2589,
                0xe13f_0cc8,
                0xb663_0ca6,
            ],
        );
    }

    #[test]
    fn it_should_expand_192bit_key() {
        assert_eq!(
            expand_key(
                &[
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80,
                    0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                ],
                12
            ),
            vec![
                0x8e73_b0f7,
                0xda0e_6452,
                0xc810_f32b,
                0x8090_79e5,
                0x62f8_ead2,
                0x522c_6b7b,
                0xfe0c_91f7,
                0x2402_f5a5,
                0xec12_068e,
                0x6c82_7f6b,
                0x0e7a_95b9,
                0x5c56_fec2,
                0x4db7_b4bd,
                0x69b5_4118,
                0x85a7_4796,
                0xe925_38fd,
                0xe75f_ad44,
                0xbb09_5386,
                0x485a_f057,
                0x21ef_b14f,
                0xa448_f6d9,
                0x4d6d_ce24,
                0xaa32_6360,
                0x113b_30e6,
                0xa25e_7ed5,
                0x83b1_cf9a,
                0x27f9_3943,
                0x6a94_f767,
                0xc0a6_9407,
                0xd19d_a4e1,
                0xec17_86eb,
                0x6fa6_4971,
                0x485f_7032,
                0x22cb_8755,
                0xe26d_1352,
                0x33f0_b7b3,
                0x40be_eb28,
                0x2f18_a259,
                0x6747_d26b,
                0x458c_553e,
                0xa7e1_466c,
                0x9411_f1df,
                0x821f_750a,
                0xad07_d753,
                0xca40_0538,
                0x8fcc_5006,
                0x282d_166a,
                0xbc3c_e7b5,
                0xe98b_a06f,
                0x448c_773c,
                0x8ecc_7204,
                0x0100_2202,
            ],
        );
    }

    #[test]
    fn it_should_expand_256bit_key() {
        assert_eq!(
            expand_key(
                &[
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
                    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                ],
                14
            ),
            vec![
                0x603d_eb10,
                0x15ca_71be,
                0x2b73_aef0,
                0x857d_7781,
                0x1f35_2c07,
                0x3b61_08d7,
                0x2d98_10a3,
                0x0914_dff4,
                0x9ba3_5411,
                0x8e69_25af,
                0xa51a_8b5f,
                0x2067_fcde,
                0xa8b0_9c1a,
                0x93d1_94cd,
                0xbe49_846e,
                0xb75d_5b9a,
                0xd59a_ecb8,
                0x5bf3_c917,
                0xfee9_4248,
                0xde8e_be96,
                0xb5a9_328a,
                0x2678_a647,
                0x9831_2229,
                0x2f6c_79b3,
                0x812c_81ad,
                0xdadf_48ba,
                0x2436_0af2,
                0xfab8_b464,
                0x98c5_bfc9,
                0xbebd_198e,
                0x268c_3ba7,
                0x09e0_4214,
                0x6800_7bac,
                0xb2df_3316,
                0x96e9_39e4,
                0x6c51_8d80,
                0xc814_e204,
                0x76a9_fb8a,
                0x5025_c02d,
                0x59c5_8239,
                0xde13_6967,
                0x6ccc_5a71,
                0xfa25_6395,
                0x9674_ee15,
                0x5886_ca5d,
                0x2e2f_31d7,
                0x7e0a_f1fa,
                0x27cf_73c3,
                0x749c_47ab,
                0x1850_1dda,
                0xe275_7e4f,
                0x7401_905a,
                0xcafa_aae3,
                0xe4d5_9b34,
                0x9adf_6ace,
                0xbd10_190d,
                0xfe48_90d1,
                0xe618_8d0b,
                0x046d_f344,
                0x706c_631e,
            ],
        );
    }

    #[test]
    fn it_should_encrypt_first_test_from_the_spec() {
        let mut aes = AES::new();
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        aes.init(&key).expect("init to not fail");

        let cleartext: [u8; BLOCK_SIZE] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        let ciphertext = aes.encrypt(&cleartext).expect("encrypt to not fail");

        assert_eq!(
            ciphertext,
            [
                0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
                0x0b, 0x32,
            ]
        );
    }

    fn hex_to_block(hex: &str) -> [u8; 16] {
        let vec = hex_to_vec(hex);
        let mut b = [0; 16];

        for (i, elem) in vec.into_iter().enumerate() {
            b[i] = elem;
        }

        b
    }

    fn check_cipher_vector(key: &str, input: &str, output: &str) {
        let mut aes = AES::new();
        aes.init(&hex_to_vec(key)).expect("init to not fail");

        assert_eq!(
            aes.encrypt(&hex_to_block(input))
                .expect("encrypt to not fail"),
            hex_to_block(output)
        );
        assert_eq!(
            aes.decrypt(&hex_to_block(output))
                .expect("decrypt to not fail"),
            hex_to_block(input)
        );
    }

    #[test]
    fn it_should_encrypt_test_vector_0() {
        check_cipher_vector(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn it_should_encrypt_test_vector_1() {
        check_cipher_vector(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn it_should_encrypt_test_vector_2() {
        check_cipher_vector(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }
}
