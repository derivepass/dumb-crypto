//! # Scrypt
//!
//! Implementation of scrypt key derivation algorithm according to
//! [RFC][rfc].
//!
//! [rfc]: https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03
//!

use crate::pbkdf2::pbkdf2_sha256;
use crate::salsa20::{salsa20, BLOCK_SIZE as SALSA_BLOCK_SIZE};

const SALSA_ROUNDS: usize = 4;
const PBKDF2_ROUNDS: usize = 1;
const BLOCK_SIZE: usize = 64;

use std::error::Error;
use std::fmt;
use std::fmt::Display;

type Block = Vec<u8>;

#[derive(Debug, PartialEq)]
pub enum ScryptError {
    RIsTooSmall,
    NIsTooSmall,
    NIsNotAPowerOfTwo,
    PIsTooSmall,
}

impl Display for ScryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ScryptError: {}", self.description())
    }
}

impl Error for ScryptError {
    fn description(&self) -> &str {
        match self {
            ScryptError::RIsTooSmall => "`r` must be larger than 1",
            ScryptError::NIsTooSmall => "`n` must be larger than 1",
            ScryptError::NIsNotAPowerOfTwo => "`n` must be a power of two",
            ScryptError::PIsTooSmall => "`p` must be larger than 1",
        }
    }
}

///
/// Main scrypt structure.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use dumb_crypto::scrypt::Scrypt;
///
/// let scrypt = Scrypt::new(1, 128, 1);
///
/// let mut out: [u8; 8] = [0; 8];
///
/// scrypt.derive(b"passphrase", b"salt", &mut out).unwrap();
///
/// assert_eq!(out.to_vec(), vec![
///     79, 35, 225, 99, 145, 145, 172, 245,
/// ]);
/// ```
///
pub struct Scrypt {
    r: usize,
    n: usize,
    p: usize,
}

fn block_xor(a: &[u8], b: &[u8]) -> Block {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

fn integerify(x: &[Block]) -> u64 {
    let last = &x[x.len() - 1];
    let tail = &last[(last.len() - SALSA_BLOCK_SIZE)..];

    u64::from(tail[0])
        | (u64::from(tail[1]) << 8)
        | (u64::from(tail[2]) << 16)
        | (u64::from(tail[3]) << 24)
        | (u64::from(tail[4]) << 32)
        | (u64::from(tail[5]) << 40)
        | (u64::from(tail[6]) << 48)
        | (u64::from(tail[7]) << 56)
}

impl Scrypt {
    ///
    /// Create new instance of Scrypt.
    ///
    /// Arguments:
    /// - `r` Block size parameter, must be larger than 1
    /// - `n` CPU/Memory cost parameter, must be larger than 1,
    ///       a power of 2 and less than 2 ^ (16 * r)
    /// - `p` Parallelization parameter, a positive integer
    ///       less than or equal to (2^32-1) / (4 * r)
    ///       where hLen is 32 and MFlen is 128 * r.
    ///
    pub fn new(r: usize, n: usize, p: usize) -> Self {
        Self { r, n, p }
    }

    fn block_mix(self: &Scrypt, b: &[Block]) -> Vec<Block> {
        //
        // Algorithm scryptBlockMix
        //
        // Parameters:
        //          r       Block size parameter.
        //
        // Input:
        //          B[0], ..., B[2 * r - 1]
        //                 Input vector of 2 * r 64-octet blocks.
        //
        // Output:
        //          B'[0], ..., B'[2 * r - 1]
        //                  Output vector of 2 * r 64-octet blocks.
        //
        // Steps:
        //
        //   1. X = B[2 * r - 1]
        //
        //   2. for i = 0 to 2 * r - 1 do
        //        T = X xor B[i]
        //        X = Salsa (T)
        //        Y[i] = X
        //      end for
        //
        //   3. B' = (Y[0], Y[2], ..., Y[2 * r - 2],
        //            Y[1], Y[3], ..., Y[2 * r - 1])
        //

        // Step 1
        let mut x = b[2 * self.r - 1].clone();

        // Step 2
        let mut y: Vec<Block> = Vec::with_capacity(2 * self.r);

        for b_elem in b.iter() {
            let t = block_xor(&x, b_elem);
            salsa20(&t, SALSA_ROUNDS, &mut x);
            y.push(x.clone());
        }

        // Step 3
        let mut bs_head: Vec<Block> = Vec::with_capacity(2 * self.r);
        let mut bs_tail: Vec<Block> = Vec::with_capacity(self.r);
        for (i, y_elem) in y.into_iter().enumerate() {
            if i % 2 == 0 {
                bs_head.push(y_elem);
            } else {
                bs_tail.push(y_elem);
            }
        }
        bs_head.append(&mut bs_tail);
        bs_head
    }

    fn ro_mix(self: &Scrypt, b: Vec<Block>) -> Vec<Block> {
        //
        // Algorithm scryptROMix
        //
        //   Input:
        //            r       Block size parameter.
        //            B       Input octet vector of length 128 * r octets.
        //            N       CPU/Memory cost parameter, must be larger than 1,
        //                    a power of 2 and less than 2^(128 * r / 8).
        //
        //   Output:
        //            B'      Output octet vector of length 128 * r octets.
        //
        //   Steps:
        //
        //     1. X = B
        //
        //     2. for i = 0 to N - 1 do
        //          V[i] = X
        //          X = scryptBlockMix (X)
        //        end for
        //
        //     3. for i = 0 to N - 1 do
        //          j = Integerify (X) mod N
        //                 where Integerify (B[0] ... B[2 * r - 1]) is defined
        //                 as the result of interpreting B[2 * r - 1] as a
        //                 little-endian integer.
        //          T = X xor V[j]
        //          X = scryptBlockMix (T)
        //        end for
        //
        //     4. B' = X
        //

        // Step 1
        let mut x = b;

        // Step 2
        let mut v: Vec<Vec<Block>> = Vec::with_capacity(self.n);
        for _i in 0..self.n {
            let t = self.block_mix(&x);
            v.push(x);
            x = t;
        }

        // Step 3
        for _i in 0..self.n {
            let j = (integerify(&x) as usize) % self.n;
            let t: Vec<Block> = x
                .iter()
                .zip(v[j].iter())
                .map(|(x_block, v_block)| block_xor(x_block, v_block))
                .collect();
            x = self.block_mix(&t);
        }

        x
    }

    ///
    /// Derive secret string using `passphrase` and `salt`.
    ///
    pub fn derive(
        self: &Scrypt,
        passphrase: &[u8],
        salt: &[u8],
        out: &mut [u8],
    ) -> Result<(), ScryptError> {
        if self.r < 1 {
            return Err(ScryptError::RIsTooSmall);
        }

        if self.n < 1 {
            return Err(ScryptError::NIsTooSmall);
        }

        if ((self.n - 1) & self.n) != 0 {
            return Err(ScryptError::NIsNotAPowerOfTwo);
        }

        if self.p < 1 {
            return Err(ScryptError::PIsTooSmall);
        }

        //
        //   Algorithm scrypt
        //
        //   Input:
        //            P       Passphrase, an octet string.
        //            S       Salt, an octet string.
        //            N       CPU/Memory cost parameter, must be larger than 1,
        //                    a power of 2 and less than 2^(128 * r / 8).
        //            r       Block size parameter.
        //            p       Parallelization parameter, a positive integer
        //                    less than or equal to ((2^32-1) * hLen) / MFLen
        //                    where hLen is 32 and MFlen is 128 * r.
        //            dkLen   Intended output length in octets of the derived
        //                    key; a positive integer less than or equal to
        //                    (2^32 - 1) * hLen where hLen is 32.
        //
        //   Output:
        //            DK      Derived key, of length dkLen octets.
        //
        //   Steps:
        //
        //     1. B[0] || B[1] || ... || B[p - 1] =
        //          PBKDF2-HMAC-SHA256 (P, S, 1, p * 128 * r)
        //
        //     2. for i = 0 to p - 1 do
        //          B[i] = scryptROMix (r, B[i], N)
        //        end for
        //
        //     3. DK = PBKDF2-HMAC-SHA256 (P, B[0] || B[1] || ... || B[p - 1],
        //                                 1, dkLen)
        //

        // Step 1
        let mut raw_b: Vec<u8> = vec![0; self.p * 2 * BLOCK_SIZE * self.r];
        pbkdf2_sha256(passphrase, salt, PBKDF2_ROUNDS, &mut raw_b);

        let mut b: Vec<Vec<Block>> = raw_b
            .chunks_exact(2 * BLOCK_SIZE * self.r)
            .map(|chunk| {
                chunk
                    .chunks_exact(BLOCK_SIZE)
                    .map(|sub_chunk| sub_chunk.to_vec())
                    .collect()
            })
            .collect();

        // Step 2
        b = b.into_iter().map(|elem| self.ro_mix(elem)).collect();

        // Step 3
        let b_salt: Vec<u8> = b.into_iter().flatten().flatten().collect();
        pbkdf2_sha256(passphrase, &b_salt, PBKDF2_ROUNDS, out);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-8

    fn check_mix(r: usize, input: &[Block], expected: &[Block]) {
        let s = Scrypt::new(r, 1, 1);
        assert_eq!(s.block_mix(input), expected);
    }

    #[test]
    fn it_should_compute_block_mix_for_vec0() {
        check_mix(
            1,
            &[
                vec![
                    0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4, 0x10, 0x8c, 0xf5, 0xab, 0xe9,
                    0x12, 0xff, 0xdd, 0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e, 0x82, 0x04,
                    0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad, 0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8,
                    0x7b, 0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29, 0x09, 0x4f, 0x01, 0x84,
                    0x63, 0x95, 0x74, 0xf3, 0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,
                ],
                vec![
                    0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22, 0x6c, 0x25, 0xb5, 0x4d, 0xa8,
                    0x63, 0x70, 0xfb, 0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb, 0x8f, 0xfc,
                    0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0, 0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5,
                    0xfe, 0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b, 0x7f, 0x4d, 0x1c, 0xad,
                    0x6a, 0x52, 0x3c, 0xda, 0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89,
                ],
            ],
            &[
                vec![
                    0xa4, 0x1f, 0x85, 0x9c, 0x66, 0x08, 0xcc, 0x99, 0x3b, 0x81, 0xca, 0xcb, 0x02,
                    0x0c, 0xef, 0x05, 0x04, 0x4b, 0x21, 0x81, 0xa2, 0xfd, 0x33, 0x7d, 0xfd, 0x7b,
                    0x1c, 0x63, 0x96, 0x68, 0x2f, 0x29, 0xb4, 0x39, 0x31, 0x68, 0xe3, 0xc9, 0xe6,
                    0xbc, 0xfe, 0x6b, 0xc5, 0xb7, 0xa0, 0x6d, 0x96, 0xba, 0xe4, 0x24, 0xcc, 0x10,
                    0x2c, 0x91, 0x74, 0x5c, 0x24, 0xad, 0x67, 0x3d, 0xc7, 0x61, 0x8f, 0x81,
                ],
                vec![
                    0x20, 0xed, 0xc9, 0x75, 0x32, 0x38, 0x81, 0xa8, 0x05, 0x40, 0xf6, 0x4c, 0x16,
                    0x2d, 0xcd, 0x3c, 0x21, 0x07, 0x7c, 0xfe, 0x5f, 0x8d, 0x5f, 0xe2, 0xb1, 0xa4,
                    0x16, 0x8f, 0x95, 0x36, 0x78, 0xb7, 0x7d, 0x3b, 0x3d, 0x80, 0x3b, 0x60, 0xe4,
                    0xab, 0x92, 0x09, 0x96, 0xe5, 0x9b, 0x4d, 0x53, 0xb6, 0x5d, 0x2a, 0x22, 0x58,
                    0x77, 0xd5, 0xed, 0xf5, 0x84, 0x2c, 0xb9, 0xf1, 0x4e, 0xef, 0xe4, 0x25,
                ],
            ],
        );
    }

    fn check_ro_mix(r: usize, n: usize, input: &[Block], expected: &[Block]) {
        let s = Scrypt::new(r, n, 1);
        assert_eq!(s.ro_mix(input.to_vec()), expected);
    }

    #[test]
    fn it_should_compute_ro_mix_for_vec0() {
        check_ro_mix(
            1,
            16,
            &[
                vec![
                    0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4, 0x10, 0x8c, 0xf5, 0xab, 0xe9,
                    0x12, 0xff, 0xdd, 0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e, 0x82, 0x04,
                    0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad, 0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8,
                    0x7b, 0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29, 0x09, 0x4f, 0x01, 0x84,
                    0x63, 0x95, 0x74, 0xf3, 0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,
                ],
                vec![
                    0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22, 0x6c, 0x25, 0xb5, 0x4d, 0xa8,
                    0x63, 0x70, 0xfb, 0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb, 0x8f, 0xfc,
                    0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0, 0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5,
                    0xfe, 0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b, 0x7f, 0x4d, 0x1c, 0xad,
                    0x6a, 0x52, 0x3c, 0xda, 0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89,
                ],
            ],
            &[
                vec![
                    0x79, 0xcc, 0xc1, 0x93, 0x62, 0x9d, 0xeb, 0xca, 0x04, 0x7f, 0x0b, 0x70, 0x60,
                    0x4b, 0xf6, 0xb6, 0x2c, 0xe3, 0xdd, 0x4a, 0x96, 0x26, 0xe3, 0x55, 0xfa, 0xfc,
                    0x61, 0x98, 0xe6, 0xea, 0x2b, 0x46, 0xd5, 0x84, 0x13, 0x67, 0x3b, 0x99, 0xb0,
                    0x29, 0xd6, 0x65, 0xc3, 0x57, 0x60, 0x1f, 0xb4, 0x26, 0xa0, 0xb2, 0xf4, 0xbb,
                    0xa2, 0x00, 0xee, 0x9f, 0x0a, 0x43, 0xd1, 0x9b, 0x57, 0x1a, 0x9c, 0x71,
                ],
                vec![
                    0xef, 0x11, 0x42, 0xe6, 0x5d, 0x5a, 0x26, 0x6f, 0xdd, 0xca, 0x83, 0x2c, 0xe5,
                    0x9f, 0xaa, 0x7c, 0xac, 0x0b, 0x9c, 0xf1, 0xbe, 0x2b, 0xff, 0xca, 0x30, 0x0d,
                    0x01, 0xee, 0x38, 0x76, 0x19, 0xc4, 0xae, 0x12, 0xfd, 0x44, 0x38, 0xf2, 0x03,
                    0xa0, 0xe4, 0xe1, 0xc4, 0x7e, 0xc3, 0x14, 0x86, 0x1f, 0x4e, 0x90, 0x87, 0xcb,
                    0x33, 0x39, 0x6a, 0x68, 0x73, 0xe8, 0xf9, 0xd2, 0x53, 0x9a, 0x4b, 0x8e,
                ],
            ],
        );
    }

    // https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-10

    #[test]
    fn it_should_compute_scrypt_for_vec0() {
        let s = Scrypt::new(1, 16, 1);

        let mut out: [u8; 64] = [0; 64];
        s.derive(b"", b"", &mut out)
            .expect("derivation to not fail");
        assert_eq!(
            out.to_vec(),
            vec![
                0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
                0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
                0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
                0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
                0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06
            ]
        );
    }

    #[test]
    fn it_should_compute_scrypt_for_vec1() {
        let s = Scrypt::new(8, 1024, 16);

        let mut out: [u8; 64] = [0; 64];
        s.derive(b"password", b"NaCl", &mut out)
            .expect("derivation to not fail");
        assert_eq!(
            out.to_vec(),
            vec![
                0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
                0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
                0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
                0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
                0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
            ]
        );
    }

    #[test]
    fn it_should_compute_scrypt_for_vec2() {
        let s = Scrypt::new(8, 16384, 1);

        let mut out: [u8; 64] = [0; 64];
        s.derive(b"pleaseletmein", b"SodiumChloride", &mut out)
            .expect("derivation to not fail");
        assert_eq!(
            out.to_vec(),
            vec![
                0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd,
                0x38, 0xeb, 0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6,
                0x54, 0x5d, 0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4,
                0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9, 0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
                0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87
            ]
        );
    }

    #[test]
    fn it_should_compute_scrypt_for_vec3() {
        let s = Scrypt::new(8, 1_048_576, 1);

        let mut out: [u8; 64] = [0; 64];
        s.derive(b"pleaseletmein", b"SodiumChloride", &mut out)
            .expect("derivation to not fail");
        assert_eq!(
            out.to_vec(),
            vec![
                0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70,
                0xf8, 0x81, 0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d, 0xab, 0xe5, 0xee, 0x98,
                0x20, 0xad, 0xaa, 0x47, 0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f, 0xfa, 0x1c,
                0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3, 0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb,
                0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41, 0xa4
            ]
        );
    }
}
