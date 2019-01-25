//! # PKCS7
//!
//! Implementation of PKCS7 padding.
//!

use std::error::Error;
use std::fmt;
use std::fmt::Display;

pub struct Pad {
    block_size: usize,
    storage: Vec<u8>,
}

impl Pad {
    pub fn new(block_size: usize) -> Self {
        Pad {
            block_size,
            storage: Vec::with_capacity(2 * block_size),
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        for &elem in buf {
            self.storage.push(elem);
        }

        if self.storage.len() < self.block_size {
            return None;
        }

        let tail_len = self.storage.len() % self.block_size;
        let tail_pos = self.storage.len() - tail_len;

        let mut tail = self.storage.split_off(tail_pos);
        let head = self.storage.clone();
        self.storage.clear();
        self.storage.append(&mut tail);

        Some(head)
    }

    pub fn flush(&mut self) -> Vec<u8> {
        let len = self.block_size - self.storage.len();
        while self.storage.len() < self.block_size {
            self.storage.push(len as u8);
        }

        let result = self.storage.clone();
        self.storage.clear();
        result
    }
}

/// Possible unpad errors
#[derive(Debug, PartialEq)]
pub enum UnpadError {
    /// Returned when the data length is not divisible by the block size.
    UnfinishedBlock,

    /// Returned when the padding is invalid in the last block.
    InvalidPadding,
}

impl Display for UnpadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UnpadError: {}", self.description())
    }
}

impl Error for UnpadError {
    fn description(&self) -> &str {
        match self {
            UnpadError::UnfinishedBlock => "data length must be a multiple of block size",
            UnpadError::InvalidPadding => "final block contains invalid padding",
        }
    }
}

pub struct Unpad {
    block_size: usize,
    storage: Vec<u8>,
}

impl Unpad {
    pub fn new(block_size: usize) -> Self {
        Unpad {
            block_size,
            storage: Vec::with_capacity(2 * block_size),
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        for &elem in buf {
            self.storage.push(elem);
        }

        // Note the `<=` here. We don't know where the block is the last, so we
        // can't yet emit the block until we have at least one byte of the next
        // block.
        if self.storage.len() <= self.block_size {
            return None;
        }

        let mut tail_len = self.storage.len() % self.block_size;

        // NOTE: this is different from the Pad::write
        if tail_len == 0 {
            tail_len = self.block_size;
        }

        let tail_pos = self.storage.len() - tail_len;

        let mut tail = self.storage.split_off(tail_pos);
        let head = self.storage.clone();
        self.storage.clear();
        self.storage.append(&mut tail);

        Some(head)
    }

    pub fn flush(&mut self) -> Result<Vec<u8>, UnpadError> {
        if self.storage.len() != self.block_size {
            return Err(UnpadError::UnfinishedBlock);
        }

        let len = self.storage[self.storage.len() - 1];
        if len > (self.block_size as u8) {
            return Err(UnpadError::InvalidPadding);
        }
        let pad_off: usize = self.block_size - usize::from(len);

        // XXX(indutny): hopefully this won't be optimized away
        let mut is_same: u8 = 0;
        for b in self.storage[pad_off..].iter() {
            is_same |= len ^ b;
        }

        if is_same != 0 {
            return Err(UnpadError::InvalidPadding);
        }

        let result = self.storage[..pad_off].to_vec();
        self.storage.clear();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_apply_padding_to_incomplete_block() {
        let mut pad = Pad::new(4);

        assert_eq!(pad.write(b"123"), None);
        assert_eq!(pad.flush(), b"123\x01");
    }

    #[test]
    fn it_should_apply_padding_to_second_incomplete_block() {
        let mut pad = Pad::new(4);

        assert_eq!(pad.write(b"123456"), Some(b"1234".to_vec()));
        assert_eq!(pad.flush(), b"56\x02\x02");
    }

    #[test]
    fn it_should_return_padding_block() {
        let mut pad = Pad::new(4);

        assert_eq!(pad.write(b"1234"), Some(b"1234".to_vec()));
        assert_eq!(pad.flush(), b"\x04\x04\x04\x04");
    }

    #[test]
    fn it_should_unpad_single_block() {
        let mut unpad = Unpad::new(4);

        assert_eq!(unpad.write(b"123\x01"), None);
        assert_eq!(unpad.flush().expect("flush to succeed"), b"123".to_vec());
    }

    #[test]
    fn it_should_unpad_two_blocks() {
        let mut unpad = Unpad::new(4);

        assert_eq!(unpad.write(b"1234"), None);
        assert_eq!(unpad.write(b"5\x03\x03\x03"), Some(b"1234".to_vec()));
        assert_eq!(unpad.flush().expect("flush to succeed"), b"5".to_vec());
    }

    #[test]
    fn it_should_unpad_full_block() {
        let mut unpad = Unpad::new(4);

        assert_eq!(unpad.write(b"1234"), None);
        assert_eq!(unpad.write(b"\x04\x04\x04\x04"), Some(b"1234".to_vec()));
        assert_eq!(unpad.flush().expect("flush to succeed"), b"".to_vec());
    }

    #[test]
    fn it_should_error_on_unfinished_data() {
        let mut unpad = Unpad::new(4);

        assert_eq!(unpad.write(b"123"), None);
        assert_eq!(
            unpad.flush().expect_err("flush to fail"),
            UnpadError::UnfinishedBlock
        );
    }

    #[test]
    fn it_should_error_on_invalid_padding() {
        let mut unpad = Unpad::new(4);

        assert_eq!(unpad.write(b"12\x03\x02"), None);
        assert_eq!(
            unpad.flush().expect_err("flush to fail"),
            UnpadError::InvalidPadding
        );
    }
}
