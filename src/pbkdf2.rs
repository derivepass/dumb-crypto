//! # PBKDF2
//!
//! Implementation of PBKDF2 key derivation algorithm according to
//! [RFC 2898][rfc].
//!
//! [rfc]: https://tools.ietf.org/html/rfc2898#section-5.2
//!

use crate::hmac::HMac;
use crate::sha256::DIGEST_SIZE;

// See: https://tools.ietf.org/html/rfc2898#section-5.2

///
/// Derive key using `password`, `salt`, and `c` rounds.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use dumb_crypto::pbkdf2::pbkdf2_sha256;
///
/// let mut out: [u8; 8] = [0; 8];
///
/// pbkdf2_sha256(b"password", b"salt", 100, &mut out);
///
/// assert_eq!(out.to_vec(), vec![
///      0x07, 0xe6, 0x99, 0x71, 0x80, 0xcf, 0x7f, 0x12,
/// ]);
/// ```
///
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], c: usize, out: &mut [u8]) {
    //
    // Terminology:
    //   P = password
    //   S = salt
    //   DK = out
    //   dkLen = out_len
    //

    // 1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and stop.
    // (skip)

    // 2. Let l be the number of hLen-octet blocks in the derived key,
    //    rounding up, and let r be the number of octets in the last
    //    block:
    //
    //               l = CEIL (dkLen / hLen) ,
    //               r = dkLen - (l - 1) * hLen .
    //
    //    Here, CEIL (x) is the "ceiling" function, i.e. the smallest
    //    integer greater than, or equal to, x.
    //

    let l: usize = (out.len() + DIGEST_SIZE - 1) / DIGEST_SIZE;

    // NOTE: unused
    // let r = out.len() - (l - 1) * DIGEST_SIZE;

    // 3. For each block of the derived key apply the function F defined
    //    below to the password P, the salt S, the iteration count c, and
    //    the block index to compute the block:
    //
    //               T_1 = F (P, S, c, 1) ,
    //               T_2 = F (P, S, c, 2) ,
    //               ...
    //               T_l = F (P, S, c, l) ,
    //
    //    where the function F is defined as the exclusive-or sum of the
    //    first c iterates of the underlying pseudorandom function PRF
    //    applied to the password P and the concatenation of the salt S
    //    and the block index i:
    //
    //               F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
    //
    //    where
    //
    //               U_1 = PRF (P, S || INT (i)) ,
    //               U_2 = PRF (P, U_1) ,
    //               ...
    //               U_c = PRF (P, U_{c-1}) .
    //
    //    Here, INT (i) is a four-octet encoding of the integer i, most
    //    significant octet first.
    //
    for i in 1..=l {
        let ctr: [u8; 4] = [(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8];

        // U_1 = PRF (P, S || INT (i))
        let mut hmac = HMac::new(password);
        hmac.update(salt);
        hmac.update(&ctr);
        let mut u = hmac.digest();
        let mut t = u;

        for _j in 2..=c {
            // U_c = PRF (P, U_{c-1})
            let mut hmac = HMac::new(password);
            hmac.update(&u);
            u = hmac.digest();

            // Xor Us
            for k in 0..u.len() {
                t[k] ^= u[k];
            }
        }

        // Copy out the results
        let start = (i - 1) * DIGEST_SIZE;
        let end = std::cmp::min(i * DIGEST_SIZE, out.len());
        out[start..end].copy_from_slice(&t[..(end - start)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    //
    // See: https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-10
    //

    #[test]
    fn it_should_compute_digest_for_vec0() {
        let mut out: [u8; 64] = [0; 64];

        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            out.to_vec(),
            vec![
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
                0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57,
                0xc2, 0x0d, 0xac, 0xbc, 0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16,
                0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31, 0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
                0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
            ]
        );
    }

    #[test]
    fn it_should_compute_digest_for_vec1() {
        let mut out: [u8; 64] = [0; 64];

        pbkdf2_sha256(b"Password", b"NaCl", 80000, &mut out);
        assert_eq!(
            out.to_vec(),
            vec![
                0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27,
                0x01, 0xf9, 0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87,
                0x6b, 0x34, 0xab, 0x56, 0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54, 0x9a, 0xdb,
                0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17, 0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
                0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d,
            ]
        );
    }
}
