//! A bit-aligned serializer and deserializer compatible with RakNet 2.52's `BitStream`.
//!
//! Provides reading/writing of values at the bit level, including the specific
//! integer compression algorithm used by RakNet.

/// A bit-level buffer for serializing and deserializing RakNet packets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BitStream {
    /// Internal byte buffer.
    data: Vec<u8>,
    /// Number of bits written to the stream.
    write_offset_bits: usize,
    /// Number of bits read from the stream.
    read_offset_bits: usize,
}

impl BitStream {
    /// Creates a new empty `BitStream`.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            write_offset_bits: 0,
            read_offset_bits: 0,
        }
    }

    /// Creates a `BitStream` wrapping a copy of the given byte slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            data: bytes.to_vec(),
            write_offset_bits: bytes.len() * 8,
            read_offset_bits: 0,
        }
    }

    /// Returns the internal byte representation of the stream.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the total number of bits written to the stream.
    pub fn len_bits(&self) -> usize {
        self.write_offset_bits
    }

    /// Returns the total number of bytes written to the stream (rounded up).
    pub fn len_bytes(&self) -> usize {
        (self.write_offset_bits + 7) / 8
    }

    /// Returns the number of bits that have not yet been read.
    pub fn unread_bits(&self) -> usize {
        if self.write_offset_bits > self.read_offset_bits {
            self.write_offset_bits - self.read_offset_bits
        } else {
            0
        }
    }

    /// Resets the read and write offsets, clearing the internal buffer.
    pub fn reset(&mut self) {
        self.data.clear();
        self.write_offset_bits = 0;
        self.read_offset_bits = 0;
    }

    /// Sets the read offset back to the beginning.
    pub fn reset_read_pointer(&mut self) {
        self.read_offset_bits = 0;
    }

    /// Writes a single bit (bool) to the stream.
    ///
    /// Bits are packed left-to-right (MSB to LSB) within each byte.
    pub fn write_bit(&mut self, bit: bool) {
        let byte_idx = self.write_offset_bits / 8;
        let bit_idx = 7 - (self.write_offset_bits % 8);
        if byte_idx >= self.data.len() {
            self.data.push(0);
        }
        if bit {
            self.data[byte_idx] |= 1 << bit_idx;
        }
        self.write_offset_bits += 1;
    }

    /// Reads a single bit (bool) from the stream.
    pub fn read_bit(&mut self) -> Option<bool> {
        if self.read_offset_bits >= self.write_offset_bits {
            return None;
        }
        let byte_idx = self.read_offset_bits / 8;
        let bit_idx = 7 - (self.read_offset_bits % 8);
        let bit = (self.data[byte_idx] & (1 << bit_idx)) != 0;
        self.read_offset_bits += 1;
        Some(bit)
    }

    /// Writes a block of bits to the stream.
    ///
    /// # Arguments
    /// * `input` - The byte slice containing source bits.
    /// * `num_bits` - Number of bits to write.
    /// * `right_aligned` - If `num_bits < 8` and `right_aligned` is true, the source bits
    ///   are read from the lowest bits (LSB-aligned) of each byte.
    pub fn write_bits(&mut self, input: &[u8], mut num_bits: usize, right_aligned: bool) {
        let mut offset = 0;
        while num_bits > 0 {
            let mut data_byte = input[offset];
            let bits_to_write = std::cmp::min(num_bits, 8);
            if bits_to_write < 8 && right_aligned {
                data_byte <<= 8 - bits_to_write;
            }
            for i in 0..bits_to_write {
                let bit = (data_byte & (1 << (7 - i))) != 0;
                self.write_bit(bit);
            }
            num_bits -= bits_to_write;
            offset += 1;
        }
    }

    /// Reads a block of bits from the stream.
    ///
    /// # Arguments
    /// * `num_bits` - Number of bits to read.
    /// * `align_right` - If true, pads partial bytes on the left so the bits are right-aligned.
    pub fn read_bits(&mut self, mut num_bits: usize, align_right: bool) -> Option<Vec<u8>> {
        if self.read_offset_bits + num_bits > self.write_offset_bits {
            return None;
        }
        let num_bytes = (num_bits + 7) / 8;
        let mut output = vec![0u8; num_bytes];
        let mut offset = 0;
        while num_bits > 0 {
            let bits_to_read = std::cmp::min(num_bits, 8);
            let mut data_byte = 0u8;
            for i in 0..bits_to_read {
                if self.read_bit()? {
                    data_byte |= 1 << (7 - i);
                }
            }
            if bits_to_read < 8 && align_right {
                data_byte >>= 8 - bits_to_read;
            }
            output[offset] = data_byte;
            num_bits -= bits_to_read;
            offset += 1;
        }
        Some(output)
    }

    /// Writes an uncompressed value of any type that implements `AsBytes` / simple byte casting.
    pub fn write<T: Sized>(&mut self, value: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.write_bits(bytes, bytes.len() * 8, false);
    }

    /// Reads an uncompressed value of any type.
    pub fn read<T: Sized + Default>(&mut self) -> Option<T> {
        let size = std::mem::size_of::<T>();
        let bytes = self.read_bits(size * 8, false)?;
        let mut val = T::default();
        unsafe {
            let dest = &mut val as *mut T as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, size);
        }
        Some(val)
    }

    /// Writes a slice of bytes directly to the stream (byte-aligned if currently aligned).
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_bits(bytes, bytes.len() * 8, false);
    }

    /// Reads a slice of bytes from the stream.
    pub fn read_bytes(&mut self, num_bytes: usize) -> Option<Vec<u8>> {
        self.read_bits(num_bytes * 8, false)
    }

    /// Writes a compressed value using RakNet's specific byte-skipping algorithm.
    pub fn write_compressed<T: Sized>(&mut self, value: &T, unsigned: bool) {
        let size_bytes = std::mem::size_of::<T>();
        let bytes = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, size_bytes)
        };
        let num_bits = size_bytes * 8;

        let mut current_byte = (num_bits >> 3) as isize - 1;
        let byte_match = if unsigned { 0x00 } else { 0xFF };

        // Write upper bytes with a single 1 bit if they match byte_match
        while current_byte > 0 {
            if bytes[current_byte as usize] == byte_match {
                self.write_bit(true);
            } else {
                self.write_bit(false);
                // Write the remainder of the data (from index 0 up to current_byte inclusive)
                self.write_bits(&bytes[0..=(current_byte as usize)], (current_byte + 1) as usize * 8, true);
                return;
            }
            current_byte -= 1;
        }

        // Handle the last byte (index 0)
        let last_byte = bytes[0];
        let has_match = if unsigned {
            (last_byte & 0xF0) == 0x00
        } else {
            (last_byte & 0xF0) == 0xF0
        };

        if has_match {
            self.write_bit(true);
            // Write remaining 4 bits
            self.write_bits(&[last_byte], 4, true);
        } else {
            self.write_bit(false);
            // Write all 8 bits
            self.write_bits(&[last_byte], 8, true);
        }
    }

    /// Reads a compressed value of any type using RakNet's specific byte-skipping algorithm.
    pub fn read_compressed<T: Sized + Default>(&mut self, unsigned: bool) -> Option<T> {
        let size_bytes = std::mem::size_of::<T>();
        let num_bits = size_bytes * 8;

        let mut current_byte = (num_bits >> 3) as isize - 1;
        let byte_match = if unsigned { 0x00 } else { 0xFF };
        let half_byte_match = if unsigned { 0x00 } else { 0xF0 };

        let mut output = vec![0u8; size_bytes];

        // Read upper bytes
        while current_byte > 0 {
            if self.read_bit()? {
                output[current_byte as usize] = byte_match;
                current_byte -= 1;
            } else {
                // Read the rest of the bytes
                let remaining = self.read_bits((current_byte + 1) as usize * 8, false)?;
                output[0..=(current_byte as usize)].copy_from_slice(&remaining);
                let mut val = T::default();
                unsafe {
                    std::ptr::copy_nonoverlapping(output.as_ptr(), &mut val as *mut T as *mut u8, size_bytes);
                }
                return Some(val);
            }
        }

        // Handle the last byte
        if self.read_bit()? {
            let last_4_bits = self.read_bits(4, true)?[0];
            output[0] = last_4_bits | half_byte_match;
        } else {
            let last_8_bits = self.read_bits(8, false)?[0];
            output[0] = last_8_bits;
        }

        let mut val = T::default();
        unsafe {
            std::ptr::copy_nonoverlapping(output.as_ptr(), &mut val as *mut T as *mut u8, size_bytes);
        }
        Some(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_read_write() {
        let mut bs = BitStream::new();
        bs.write_bit(true);
        bs.write_bit(false);
        bs.write_bit(true);
        bs.write_bit(true);
        
        assert_eq!(bs.len_bits(), 4);
        assert_eq!(bs.as_bytes()[0], 0xB0); // binary 1011 0000

        bs.reset_read_pointer();
        assert_eq!(bs.read_bit(), Some(true));
        assert_eq!(bs.read_bit(), Some(false));
        assert_eq!(bs.read_bit(), Some(true));
        assert_eq!(bs.read_bit(), Some(true));
        assert_eq!(bs.read_bit(), None);
    }

    #[test]
    fn test_uncompressed_types() {
        let mut bs = BitStream::new();
        let val1: u32 = 0x12345678;
        let val2: u16 = 0xABCD;

        bs.write(&val1);
        bs.write(&val2);

        bs.reset_read_pointer();
        assert_eq!(bs.read::<u32>(), Some(val1));
        assert_eq!(bs.read::<u16>(), Some(val2));
    }

    #[test]
    fn test_compressed_integers() {
        let mut bs = BitStream::new();
        // 15 fits in 4 bits, so it will be highly compressed
        let val1: u32 = 15;
        // 1000 fits in 2 bytes, so it will skip upper bytes
        let val2: u32 = 1000;

        bs.write_compressed(&val1, true);
        bs.write_compressed(&val2, true);

        bs.reset_read_pointer();
        assert_eq!(bs.read_compressed::<u32>(true), Some(val1));
        assert_eq!(bs.read_compressed::<u32>(true), Some(val2));
    }
}
