# dumb-crypto
[![Build Status](https://secure.travis-ci.org/indutny/dumb-crypto.svg)](http://travis-ci.org/indutny/dumb-crypto)
[![Latest version](https://img.shields.io/crates/v/dumb-crypto.svg)](https://crates.io/crates/dumb-crypto)
[![Documentation](https://docs.rs/dumb-crypto/badge.svg)][docs]
![License](https://img.shields.io/crates/l/dumb-crypto.svg)

This library implements following cryptographic routines in the dumbest and
the most obvious way:

- sha256
- hmac-sha256
- pbkdf2-sha256
- salsa20
- scrypt

## Why?

Normally, one would find a highly optimized code implementing those.
However, verifying such code is a non-trivial task. All routines (except for
scrypt itself) are pre-requisites for scrypt, and a provided just for
convenience.

## Quick example

```rust
extern crate dumb_crypto;

use::dumb_crypto::scrypt::Scrypt;

let scrypt = Scrypt::new(1, 128, 1);

let mut out: [u8; 8] = [0; 8];

scrypt.derive(b"passphrase", b"salt", &mut out);

assert_eq!(out.to_vec(), vec![
79, 35, 225, 99, 145, 145, 172, 245,
]);
```

## Using dumb-crypto

See [documentation][docs] for details.

[docs]: https://docs.rs/dumb-crypto
