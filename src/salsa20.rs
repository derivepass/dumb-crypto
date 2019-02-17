//! # Salsa20
//!
//! Implementation of salsa20 algorithm according to [the specification][spec].
//!
//! [spec]: http://cr.yp.to/snuffle/spec.pdf
//!

/// Algorithm block size
pub const BLOCK_SIZE: usize = 64;

// http://cr.yp.to/snuffle/spec.pdf
fn rotl(n: u32, s: u8) -> u32 {
    (n << s) | (n >> (32 - s))
}

fn quarterround(y: &[u32], z: &mut [u32]) {
    //
    // If y = (y0, y1, y2, y3) then quarterround(y) = (z0, z1, z2, z3) where
    //
    //     z1 = y1 ⊕ ((y0 + y3) <<< 7),
    //     z2 = y2 ⊕ ((z1 + y0) <<< 9),
    //     z3 = y3 ⊕ ((z2 + z1) <<< 13),
    //     z0 = y0 ⊕ ((z3 + z2) <<< 18).
    //
    z[1] = y[1] ^ rotl(wrapping_sum!(y[0], y[3]), 7);
    z[2] = y[2] ^ rotl(wrapping_sum!(z[1], y[0]), 9);
    z[3] = y[3] ^ rotl(wrapping_sum!(z[2], z[1]), 13);
    z[0] = y[0] ^ rotl(wrapping_sum!(z[3], z[2]), 18);
}

fn rowround(y: &[u32], z: &mut [u32]) {
    //
    // If y = (y0, y1, y2, y3, . . . , y15) then
    // rowround(y) = (z0, z1, z2, z3, . . . , z15) where
    //
    //     (z0, z1, z2, z3) = quarterround(y0, y1, y2, y3),
    //     (z5, z6, z7, z4) = quarterround(y5, y6, y7, y4),
    //     (z10, z11, z8, z9) = quarterround(y10, y11, y8, y9),
    //     (z15, z12, z13, z14) = quarterround(y15, y12, y13, y14).
    //

    let s0: [u32; 4] = [y[0], y[1], y[2], y[3]];
    let s1: [u32; 4] = [y[5], y[6], y[7], y[4]];
    let s2: [u32; 4] = [y[10], y[11], y[8], y[9]];
    let s3: [u32; 4] = [y[15], y[12], y[13], y[14]];
    let mut t: [u32; 4] = [0; 4];

    quarterround(&s0, &mut t);
    z[0] = t[0];
    z[1] = t[1];
    z[2] = t[2];
    z[3] = t[3];

    quarterround(&s1, &mut t);
    z[5] = t[0];
    z[6] = t[1];
    z[7] = t[2];
    z[4] = t[3];

    quarterround(&s2, &mut t);
    z[10] = t[0];
    z[11] = t[1];
    z[8] = t[2];
    z[9] = t[3];

    quarterround(&s3, &mut t);
    z[15] = t[0];
    z[12] = t[1];
    z[13] = t[2];
    z[14] = t[3];
}

fn columnround(x: &[u32], y: &mut [u32]) {
    //
    // If x = (x0, x1, x2, x3, . . . , x15) then
    // columnround(x) = (y0, y1, y2, y3, . . . , y15) where
    //
    //     (y0, y4, y8, y12) = quarterround(x0, x4, x8, x12),
    //     (y5, y9, y13, y1) = quarterround(x5, x9, x13, x1),
    //     (y10, y14, y2, y6) = quarterround(x10, x14, x2, x6),
    //     (y15, y3, y7, y11) = quarterround(x15, x3, x7, x11).
    //

    let s0: [u32; 4] = [x[0], x[4], x[8], x[12]];
    let s1: [u32; 4] = [x[5], x[9], x[13], x[1]];
    let s2: [u32; 4] = [x[10], x[14], x[2], x[6]];
    let s3: [u32; 4] = [x[15], x[3], x[7], x[11]];
    let mut t: [u32; 4] = [0; 4];

    quarterround(&s0, &mut t);
    y[0] = t[0];
    y[4] = t[1];
    y[8] = t[2];
    y[12] = t[3];

    quarterround(&s1, &mut t);
    y[5] = t[0];
    y[9] = t[1];
    y[13] = t[2];
    y[1] = t[3];

    quarterround(&s2, &mut t);
    y[10] = t[0];
    y[14] = t[1];
    y[2] = t[2];
    y[6] = t[3];

    quarterround(&s3, &mut t);
    y[15] = t[0];
    y[3] = t[1];
    y[7] = t[2];
    y[11] = t[3];
}

fn doubleround(x: &[u32], y: &mut [u32]) {
    //
    // A double round is a column round followed by a row round:
    // doubleround(x) = rowround(columnround(x)).
    //
    let mut t: [u32; 16] = [0; 16];
    columnround(x, &mut t);
    rowround(&t, y);
}

fn littleendian(b: &[u8]) -> u32 {
    //
    // If b = (b0, b1, b2, b3) then littleendian(b) =
    // b0 + 2^8 * b1 + 2^16 * b2 + 2^24 * b3.
    //
    u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16) | (u32::from(b[3]) << 24)
}

fn littleendian_inv(x: u32, y: &mut [u8]) {
    y[0] = x as u8;
    y[1] = (x >> 8) as u8;
    y[2] = (x >> 16) as u8;
    y[3] = (x >> 24) as u8;
}

///
/// Mix `input` using `rounds` of internal transformations.
///
/// NOTE: `input` and `output` lengths must be multiples of `BLOCK_SIZE`
/// NOTE: `output` MUST have the same size as `input`.
///
/// Usage:
/// ```rust
/// extern crate dumb_crypto;
///
/// use dumb_crypto::salsa20::salsa20;
///
/// let mut out: [u8; 64] = [0; 64];
///
/// salsa20(&[7; 64], 100, &mut out);
///
/// assert_eq!(out.to_vec(), vec![
///     121, 110, 7, 195, 60, 132, 20, 193, 62, 42, 49, 114, 249, 93, 87, 33,
///     249, 93, 87, 33, 121, 110, 7, 195, 60, 132, 20, 193, 62, 42, 49, 114,
///     62, 42, 49, 114, 249, 93, 87, 33, 121, 110, 7, 195, 60, 132, 20, 193,
///     60, 132, 20, 193, 62, 42, 49, 114, 249, 93, 87, 33, 121, 110, 7, 195,
/// ]);
/// ```
///
pub fn salsa20(input: &[u8], rounds: usize, output: &mut [u8]) {
    //
    // In short: Salsa20(x) = x + doubleround^10(x), where each 4-byte sequence is
    // viewed as a word in little-endian form.
    //
    // In detail: Starting from x = (x[0], x[1], . . . , x[63]), define
    // x0 = littleendian(x[0], x[1], x[2], x[3]),
    // x1 = littleendian(x[4], x[5], x[6], x[7]),
    // x2 = littleendian(x[8], x[9], x[10], x[11]),
    // ...
    // x15 = littleendian(x[60], x[61], x[62], x[63]).
    //
    // Define (z0, z1, . . . , z15) = doubleround10(x0, x1, . . . , x15).
    //
    // Then Salsa20(x) is the concatenation of
    // littleendian^−1(z0 + x0),
    // littleendian^−1(z1 + x1),
    // littleendian^−1(z2 + x2),
    // ...
    // littleendian^−1(z15 + x15).
    //

    let mut x: [u32; 16] = [0; 16];

    for (i, elem) in x.iter_mut().enumerate() {
        let from = i * 4;
        let to = from + 4;
        *elem = littleendian(&input[from..to]);
    }

    let mut z = x;

    for _ in 0..rounds {
        let mut t: [u32; 16] = [0; 16];
        doubleround(&z, &mut t);
        z = t;
    }

    for ((i, &x_elem), &z_elem) in x.iter().enumerate().zip(z.iter()) {
        let from = i * 4;
        let to = from + 4;
        littleendian_inv(wrapping_sum!(x_elem, z_elem), &mut output[from..to]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    //
    // http://cr.yp.to/snuffle/spec.pdf
    //

    fn quarter_check(input: [u32; 4], expected: [u32; 4]) {
        let mut out: [u32; 4] = [0; 4];
        quarterround(&input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn it_should_compute_quarterround_for_vec0() {
        quarter_check(
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
        );
    }

    #[test]
    fn it_should_compute_quarterround_for_vec1() {
        quarter_check(
            [0x0000_0001, 0x0000_0000, 0x0000_0000, 0x0000_0000],
            [0x0800_8145, 0x0000_0080, 0x0001_0200, 0x2050_0000],
        );
    }

    #[test]
    fn it_should_compute_quarterround_for_vec2() {
        quarter_check(
            [0x0000_0000, 0x0000_0001, 0x0000_0000, 0x0000_0000],
            [0x8800_0100, 0x0000_0001, 0x0000_0200, 0x0040_2000],
        );
    }

    #[test]
    fn it_should_compute_quarterround_for_vec3() {
        quarter_check(
            [0x0000_0000, 0x0000_0000, 0x0000_0001, 0x0000_0000],
            [0x8004_0000, 0x0000_0000, 0x0000_0001, 0x0000_2000],
        );
    }

    #[test]
    fn it_should_compute_quarterround_for_vec4() {
        quarter_check(
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0001],
            [0x0004_8044, 0x0000_0080, 0x0001_0000, 0x2010_0001],
        );
    }

    #[test]
    fn it_should_compute_quarterround_for_vec5() {
        quarter_check(
            [0xe7e8_c006, 0xc4f9_417d, 0x6479_b4b2, 0x68c6_7137],
            [0xe876_d72b, 0x9361_dfd5, 0xf146_0244, 0x9485_41a3],
        );
    }

    #[test]
    fn it_should_compute_quarterround_for_vec6() {
        quarter_check(
            [0xd391_7c5b, 0x55f1_c407, 0x52a5_8a7a, 0x8f88_7a3b],
            [0x3e2f_308c, 0xd90a_8f36, 0x6ab2_a923, 0x2883_524c],
        );
    }

    fn column_check(input: [u32; 16], expected: [u32; 16]) {
        let mut out: [u32; 16] = [0; 16];
        columnround(&input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn it_should_compute_columnround_for_vec0() {
        column_check(
            [
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
            ],
            [
                0x1009_0288,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0101,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0002_0401,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x40a0_4001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
            ],
        );
    }

    #[test]
    fn it_should_compute_columnround_for_vec1() {
        column_check(
            [
                0x0852_1bd6,
                0x1fe8_8837,
                0xbb2a_a576,
                0x3aa2_6365,
                0xc54c_6a5b,
                0x2fc7_4c2f,
                0x6dd3_9cc3,
                0xda0a_64f6,
                0x90a2_f23d,
                0x067f_95a6,
                0x06b3_5f61,
                0x41e4_732e,
                0xe859_c100,
                0xea4d_84b7,
                0x0f61_9bff,
                0xbc6e_965a,
            ],
            [
                0x8c9d_190a,
                0xce8e_4c90,
                0x1ef8_e9d3,
                0x1326_a71a,
                0x90a2_0123,
                0xead3_c4f3,
                0x63a0_91a0,
                0xf070_8d69,
                0x789b_010c,
                0xd195_a681,
                0xeb7d_5504,
                0xa774_135c,
                0x481c_2027,
                0x53a8_e4b5,
                0x4c1f_89c5,
                0x3f78_c9c8,
            ],
        );
    }

    fn double_check(input: [u32; 16], expected: [u32; 16]) {
        let mut out: [u32; 16] = [0; 16];
        doubleround(&input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn it_should_compute_doubleround_for_vec0() {
        double_check(
            [
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
            ],
            [
                0x8186_a22d,
                0x0040_a284,
                0x8247_9210,
                0x0692_9051,
                0x0800_0090,
                0x0240_2200,
                0x0000_4000,
                0x0080_0000,
                0x0001_0200,
                0x2040_0000,
                0x0800_8104,
                0x0000_0000,
                0x2050_0000,
                0xa000_0040,
                0x0008_180a,
                0x612a_8020,
            ],
        );
    }

    #[test]
    fn it_should_compute_doubleround_for_vec1() {
        double_check(
            [
                0xde50_1066,
                0x6f9e_b8f7,
                0xe4fb_bd9b,
                0x454e_3f57,
                0xb755_40d3,
                0x43e9_3a4c,
                0x3a6f_2aa0,
                0x726d_6b36,
                0x9243_f484,
                0x9145_d1e8,
                0x4fa9_d247,
                0xdc8d_ee11,
                0x054b_f545,
                0x254d_d653,
                0xd942_1b6d,
                0x67b2_76c1,
            ],
            [
                0xccaa_f672,
                0x23d9_60f7,
                0x9153_e63a,
                0xcd9a_60d0,
                0x5044_0492,
                0xf07c_ad19,
                0xae34_4aa0,
                0xdf4c_fdfc,
                0xca53_1c29,
                0x8e79_43db,
                0xac16_80cd,
                0xd503_ca00,
                0xa74b_2ad6,
                0xbc33_1c5c,
                0x1dda_24c7,
                0xee92_8277,
            ],
        );
    }

    fn row_check(input: [u32; 16], expected: [u32; 16]) {
        let mut out: [u32; 16] = [0; 16];
        rowround(&input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn it_should_compute_rowround_for_vec0() {
        row_check(
            [
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
            ],
            [
                0x0800_8145,
                0x0000_0080,
                0x0001_0200,
                0x2050_0000,
                0x2010_0001,
                0x0004_8044,
                0x0000_0080,
                0x0001_0000,
                0x0000_0001,
                0x0000_2000,
                0x8004_0000,
                0x0000_0000,
                0x0000_0001,
                0x0000_0200,
                0x0040_2000,
                0x8800_0100,
            ],
        );
    }

    #[test]
    fn it_should_compute_rowround_for_vec1() {
        row_check(
            [
                0x0852_1bd6,
                0x1fe8_8837,
                0xbb2a_a576,
                0x3aa2_6365,
                0xc54c_6a5b,
                0x2fc7_4c2f,
                0x6dd3_9cc3,
                0xda0a_64f6,
                0x90a2_f23d,
                0x067f_95a6,
                0x06b3_5f61,
                0x41e4_732e,
                0xe859_c100,
                0xea4d_84b7,
                0x0f61_9bff,
                0xbc6e_965a,
            ],
            [
                0xa890_d39d,
                0x65d7_1596,
                0xe948_7daa,
                0xc8ca_6a86,
                0x949d_2192,
                0x764b_7754,
                0xe408_d9b9,
                0x7a41_b4d1,
                0x3402_e183,
                0x3c3a_f432,
                0x5066_9f96,
                0xd89e_f0a8,
                0x0040_ede5,
                0xb545_fbce,
                0xd257_ed4f,
                0x1818_882d,
            ],
        );
    }

    fn check(input: [u8; 64], rounds: usize, expected: [u8; 64]) {
        let mut out: [u8; 64] = [0; 64];
        salsa20(&input, rounds, &mut out);
        assert_eq!(out.to_vec(), expected.to_vec());
    }

    #[test]
    fn it_should_compute_salsa20_for_vec0() {
        check(
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            10,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
    }

    #[test]
    fn it_should_compute_salsa20_for_vec1() {
        check(
            [
                211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136, 49, 237,
                179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207, 31, 240, 32, 63,
                15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36, 79, 201, 235, 79, 3, 81, 156,
                47, 203, 26, 244, 243, 88, 118, 104, 54,
            ],
            10,
            [
                109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154, 29,
                29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57, 118, 40, 152,
                157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114, 219, 236, 232, 135, 111,
                155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202,
            ],
        );
    }

    #[test]
    fn it_should_compute_salsa20_for_vec2() {
        check(
            [
                88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 191, 187,
                234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 86, 16, 179, 207,
                49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 238, 55, 204, 36, 31, 240,
                32, 63, 15, 83, 93, 161, 116, 147, 48, 113,
            ],
            10,
            [
                179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 26, 110,
                170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 69, 144, 51,
                57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 27, 111, 114, 114, 118,
                40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35,
            ],
        );
    }

    // https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-8

    #[test]
    fn it_should_compute_salsa20_for_vec3() {
        check(
            [
                0x7e, 0x87, 0x9a, 0x21, 0x4f, 0x3e, 0xc9, 0x86, 0x7c, 0xa9, 0x40, 0xe6, 0x41, 0x71,
                0x8f, 0x26, 0xba, 0xee, 0x55, 0x5b, 0x8c, 0x61, 0xc1, 0xb5, 0x0d, 0xf8, 0x46, 0x11,
                0x6d, 0xcd, 0x3b, 0x1d, 0xee, 0x24, 0xf3, 0x19, 0xdf, 0x9b, 0x3d, 0x85, 0x14, 0x12,
                0x1e, 0x4b, 0x5a, 0xc5, 0xaa, 0x32, 0x76, 0x02, 0x1d, 0x29, 0x09, 0xc7, 0x48, 0x29,
                0xed, 0xeb, 0xc6, 0x8d, 0xb8, 0xb8, 0xc2, 0x5e,
            ],
            4,
            [
                0xa4, 0x1f, 0x85, 0x9c, 0x66, 0x08, 0xcc, 0x99, 0x3b, 0x81, 0xca, 0xcb, 0x02, 0x0c,
                0xef, 0x05, 0x04, 0x4b, 0x21, 0x81, 0xa2, 0xfd, 0x33, 0x7d, 0xfd, 0x7b, 0x1c, 0x63,
                0x96, 0x68, 0x2f, 0x29, 0xb4, 0x39, 0x31, 0x68, 0xe3, 0xc9, 0xe6, 0xbc, 0xfe, 0x6b,
                0xc5, 0xb7, 0xa0, 0x6d, 0x96, 0xba, 0xe4, 0x24, 0xcc, 0x10, 0x2c, 0x91, 0x74, 0x5c,
                0x24, 0xad, 0x67, 0x3d, 0xc7, 0x61, 0x8f, 0x81,
            ],
        );
    }
}
