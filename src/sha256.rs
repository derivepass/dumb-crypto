//! # SHA256
//!
//! Implementation of SHA256 digest according to [RFC 6234][rfc].
//!
//! [rfc]: https://tools.ietf.org/html/rfc6234#section-5.1
//!

/// Length of digest array
pub const DIGEST_SIZE: usize = 32;

/// Internal block size
pub const BLOCK_SIZE: usize = 64;

// See: https://tools.ietf.org/html/rfc6234#section-5.1
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

// CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

// MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn rotr(n: u32, s: u32) -> u32 {
    (n << (32 - s)) | (n >> s)
}

// BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
fn bsig0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

// BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
fn bsig1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

// SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
fn ssig0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

// SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
fn ssig1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

fn fill_block(input: &[u8; BLOCK_SIZE], output: &mut [u32; BLOCK_SIZE / 4]) {
    for i in 0..output.len() {
        let i0 = u32::from(input[i * 4]);
        let i1 = u32::from(input[i * 4 + 1]);
        let i2 = u32::from(input[i * 4 + 2]);
        let i3 = u32::from(input[i * 4 + 3]);

        output[i] = (i0 << 24) | (i1 << 16) | (i2 << 8) | i3;
    }
}

fn write_u64_be(data: &mut [u8], value: u64) {
    data[0] = (value >> 56) as u8;
    data[1] = (value >> 48) as u8;
    data[2] = (value >> 40) as u8;
    data[3] = (value >> 32) as u8;
    data[4] = (value >> 24) as u8;
    data[5] = (value >> 16) as u8;
    data[6] = (value >> 8) as u8;
    data[7] = (value) as u8;
}

///
/// Main digest structure.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use dumb_crypto::sha256::SHA256;
///
/// let mut sha256 = SHA256::new();
///
/// sha256.update(b"hello world");
/// assert_eq!(sha256.digest().to_vec(), vec![
///     0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
///     0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
///     0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
///     0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
/// ]);
/// ```
///
pub struct SHA256 {
    h: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    length: usize,
}

impl SHA256 {
    ///
    /// Create new instance of SHA256 digest.
    ///
    pub fn new() -> SHA256 {
        SHA256 {
            h: H,
            buffer: [0; BLOCK_SIZE],
            length: 0,
        }
    }

    fn process_block(self: &mut SHA256, block: &[u32; 16]) {
        //
        //    1. Prepare the message schedule W:
        //         For t = 0 to 15
        //             Wt = M(i)t
        //         For t = 16 to 63
        //             Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
        //
        let mut w: [u32; 64] = [0; 64];
        let mut a: u32;
        let mut b: u32;
        let mut c: u32;
        let mut d: u32;
        let mut e: u32;
        let mut f: u32;
        let mut g: u32;
        let mut h: u32;

        w[..16].clone_from_slice(&block[..16]);

        for t in 16..64 {
            w[t] = wrapping_sum!(ssig1(w[t - 2]), w[t - 7], ssig0(w[t - 15]), w[t - 16]);
        }

        //
        //    2. Initialize the working variables:
        //         a = H(i-1)0
        //         b = H(i-1)1
        //         c = H(i-1)2
        //         d = H(i-1)3
        //         e = H(i-1)4
        //         f = H(i-1)5
        //         g = H(i-1)6
        //         h = H(i-1)7
        //
        a = self.h[0];
        b = self.h[1];
        c = self.h[2];
        d = self.h[3];
        e = self.h[4];
        f = self.h[5];
        g = self.h[6];
        h = self.h[7];

        //
        //    3. Perform the main hash computation:
        //       For t = 0 to 63
        //          T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
        //          T2 = BSIG0(a) + MAJ(a,b,c)
        //          h = g
        //          g = f
        //          f = e
        //          e = d + T1
        //          d = c
        //          c = b
        //          b = a
        //          a = T1 + T2
        //
        for t in 0..64 {
            let t1 = wrapping_sum!(h, bsig1(e), ch(e, f, g), K[t], w[t]);
            let t2 = wrapping_sum!(bsig0(a), maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = wrapping_sum!(d, t1);
            d = c;
            c = b;
            b = a;
            a = wrapping_sum!(t1, t2);
        }

        //
        //    4. Compute the intermediate hash value H(i)
        //       H(i)0 = a + H(i-1)0
        //       H(i)1 = b + H(i-1)1
        //       H(i)2 = c + H(i-1)2
        //       H(i)3 = d + H(i-1)3
        //       H(i)4 = e + H(i-1)4
        //       H(i)5 = f + H(i-1)5
        //       H(i)6 = g + H(i-1)6
        //       H(i)7 = h + H(i-1)7
        //
        self.h[0] = wrapping_sum!(self.h[0], a);
        self.h[1] = wrapping_sum!(self.h[1], b);
        self.h[2] = wrapping_sum!(self.h[2], c);
        self.h[3] = wrapping_sum!(self.h[3], d);
        self.h[4] = wrapping_sum!(self.h[4], e);
        self.h[5] = wrapping_sum!(self.h[5], f);
        self.h[6] = wrapping_sum!(self.h[6], g);
        self.h[7] = wrapping_sum!(self.h[7], h);
    }

    ///
    /// Add input `data` to the digest.
    ///
    pub fn update(self: &mut SHA256, data: &[u8]) {
        let mut block: [u32; BLOCK_SIZE / 4] = [0; BLOCK_SIZE / 4];

        for &b in data {
            let off = self.length % BLOCK_SIZE;

            // Fill the buffer
            self.buffer[off] = b;
            self.length += 1;

            if self.length % BLOCK_SIZE != 0 {
                continue;
            }

            fill_block(&self.buffer, &mut block);
            self.process_block(&block);
        }
    }

    ///
    /// Generate digest array.
    ///
    pub fn digest(self: &mut SHA256) -> [u8; DIGEST_SIZE] {
        // https://tools.ietf.org/html/rfc6234#section-4.1

        //
        //   Suppose a message has length L < 2^64.  Before it is input to the
        //   hash function, the message is padded on the right as follows:
        //
        //   a. "1" is appended.  Example: if the original message is "01010000",
        //      this is padded to "010100001".
        //
        //   b. K "0"s are appended where K is the smallest, non-negative solution
        //      to the equation
        //
        //         ( L + 1 + K ) mod 512 = 448
        //
        //   c. Then append the 64-bit block that is L in binary representation.
        //      After appending this block, the length of the message will be a
        //      multiple of 512 bits.
        //

        let mut block: [u32; BLOCK_SIZE / 4] = [0; BLOCK_SIZE / 4];

        // NOTE: It is simple to calculate `k`, but having it is a bit useless,
        // since we know that this algorithm just wants to zero the rest of the
        // block and to put the 64bit length to the end
        let mut off = self.length % BLOCK_SIZE;

        // (b)
        for i in off..self.buffer.len() {
            self.buffer[i] = 0;
        }

        // If the padding does not fit in a single block - append 0x80 and zeroes
        // to the current block and flush it.
        // Then fill the block with zeroes and append size to it, and flush it
        // again.
        let has_overflow = off + 9 > BLOCK_SIZE;
        if has_overflow {
            // (a)
            self.buffer[off] |= 0x80;

            fill_block(&self.buffer, &mut block);
            self.process_block(&block);

            off = 0;
            self.buffer = [0; BLOCK_SIZE];
        }

        // (c)
        let len_off = self.buffer.len() - 8;
        write_u64_be(&mut self.buffer[len_off..], (self.length * 8) as u64);

        // (a)
        if !has_overflow {
            self.buffer[off] |= 0x80;
        }

        fill_block(&self.buffer, &mut block);
        self.process_block(&block);

        let mut out: [u8; DIGEST_SIZE] = [0; DIGEST_SIZE];
        for i in 0..self.h.len() {
            out[i * 4] = (self.h[i] >> 24) as u8;
            out[i * 4 + 1] = (self.h[i] >> 16) as u8;
            out[i * 4 + 2] = (self.h[i] >> 8) as u8;
            out[i * 4 + 3] = (self.h[i]) as u8;
        }
        out
    }
}

impl Default for SHA256 {
    fn default() -> SHA256 {
        SHA256::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(inputs: &[&str], expected: [u8; DIGEST_SIZE]) {
        let mut sha256 = SHA256::new();

        for chunk in inputs {
            sha256.update(chunk.as_bytes());
        }
        assert_eq!(sha256.digest(), expected);
    }

    #[test]
    fn it_should_compute_digest_for_abc() {
        check(
            &["abc"],
            [
                0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
                0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
                0xF2, 0x00, 0x15, 0xAD,
            ],
        );
    }

    #[test]
    fn it_should_compute_digest_for_a_b_c() {
        check(
            &["a", "b", "c"],
            [
                0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
                0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
                0xF2, 0x00, 0x15, 0xAD,
            ],
        );
    }

    #[test]
    fn it_should_compute_digest_for_long_str() {
        check(
            &["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"],
            [
                0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E,
                0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4,
                0x19, 0xDB, 0x06, 0xC1,
            ],
        );
    }

    #[test]
    fn it_should_compute_digest_for_long_chunked_str() {
        check(
            &[
                "abcdbcdec",
                "defdefgefg",
                "hfghighijhi",
                "jkijkljklmkl",
                "mnlmnomnopnopq",
            ],
            [
                0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E,
                0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4,
                0x19, 0xDB, 0x06, 0xC1,
            ],
        );
    }

    #[test]
    fn it_should_compute_digest_for_doubled_chunked_long_str() {
        check(
            &[
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ],
            [
                0x59, 0xf1, 0x09, 0xd9, 0x53, 0x3b, 0x2b, 0x70, 0xe7, 0xc3, 0xb8, 0x14, 0xa2, 0xbd,
                0x21, 0x8f, 0x78, 0xea, 0x5d, 0x37, 0x14, 0x45, 0x5b, 0xc6, 0x79, 0x87, 0xcf, 0x0d,
                0x66, 0x43, 0x99, 0xcf,
            ],
        );
    }

    #[test]
    fn it_should_compute_digest_for_doubled_long_str() {
        check(
            &[
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabc\
                 dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ],
            [
                0x59, 0xf1, 0x09, 0xd9, 0x53, 0x3b, 0x2b, 0x70, 0xe7, 0xc3, 0xb8, 0x14, 0xa2, 0xbd,
                0x21, 0x8f, 0x78, 0xea, 0x5d, 0x37, 0x14, 0x45, 0x5b, 0xc6, 0x79, 0x87, 0xcf, 0x0d,
                0x66, 0x43, 0x99, 0xcf,
            ],
        );
    }
}
