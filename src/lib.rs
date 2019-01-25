//! # dumb-crypto
//!
//! This library implements following cryptographic routines in the dumbest and
//! the most obvious way:
//!
//! - sha256
//! - hmac-sha256
//! - pbkdf2-sha256
//! - salsa20
//! - scrypt
//!
//! Normally, one would find a highly optimized code implementing those.
//! However, verifying such code is a non-trivial task.
//!
//! All routines (except for scrypt itself) are pre-requisites for scrypt. They
//! are provided here just for convenience.
//!
//! Documentation is available for each separate module.
//!

#[macro_use]
mod common;
mod pkcs7;

pub mod aes;
pub mod aes_cbc;
pub mod hmac;
pub mod pbkdf2;
pub mod salsa20;
pub mod scrypt;
pub mod sha256;
