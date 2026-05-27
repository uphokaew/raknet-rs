//! SA-MP customization packet encryption and decryption.
//!
//! Provides the custom packet encoding/decoding protocol wrapper used
//! by SA-MP and open.mp clients and servers to authenticate and secure connections.

/// The 256-byte substitution table used for decrypting incoming SA-MP packets.
pub const DECRYPT_KEY_TABLE: [u8; 256] = [
    0xB4, 0x62, 0x07, 0xE5, 0x9D, 0xAF, 0x63, 0xDD, 0xE3, 0xD0, 0xCC, 0xFE, 0xDC, 0xDB, 0x6B, 0x2E,
    0x6A, 0x40, 0xAB, 0x47, 0xC9, 0xD1, 0x53, 0xD5, 0x20, 0x91, 0xA5, 0x0E, 0x4A, 0xDF, 0x18, 0x89,
    0xFD, 0x6F, 0x25, 0x12, 0xB7, 0x13, 0x77, 0x00, 0x65, 0x36, 0x6D, 0x49, 0xEC, 0x57, 0x2A, 0xA9,
    0x11, 0x5F, 0xFA, 0x78, 0x95, 0xA4, 0xBD, 0x1E, 0xD9, 0x79, 0x44, 0xCD, 0xDE, 0x81, 0xEB, 0x09,
    0x3E, 0xF6, 0xEE, 0xDA, 0x7F, 0xA3, 0x1A, 0xA7, 0x2D, 0xA6, 0xAD, 0xC1, 0x46, 0x93, 0xD2, 0x1B,
    0x9C, 0xAA, 0xD7, 0x4E, 0x4B, 0x4D, 0x4C, 0xF3, 0xB8, 0x34, 0xC0, 0xCA, 0x88, 0xF4, 0x94, 0xCB,
    0x04, 0x39, 0x30, 0x82, 0xD6, 0x73, 0xB0, 0xBF, 0x22, 0x01, 0x41, 0x6E, 0x48, 0x2C, 0xA8, 0x75,
    0xB1, 0x0A, 0xAE, 0x9F, 0x27, 0x80, 0x10, 0xCE, 0xF0, 0x29, 0x28, 0x85, 0x0D, 0x05, 0xF7, 0x35,
    0xBB, 0xBC, 0x15, 0x06, 0xF5, 0x60, 0x71, 0x03, 0x1F, 0xEA, 0x5A, 0x33, 0x92, 0x8D, 0xE7, 0x90,
    0x5B, 0xE9, 0xCF, 0x9E, 0xD3, 0x5D, 0xED, 0x31, 0x1C, 0x0B, 0x52, 0x16, 0x51, 0x0F, 0x86, 0xC5,
    0x68, 0x9B, 0x21, 0x0C, 0x8B, 0x42, 0x87, 0xFF, 0x4F, 0xBE, 0xC8, 0xE8, 0xC7, 0xD4, 0x7A, 0xE0,
    0x55, 0x2F, 0x8A, 0x8E, 0xBA, 0x98, 0x37, 0xE4, 0xB2, 0x38, 0xA1, 0xB6, 0x32, 0x83, 0x3A, 0x7B,
    0x84, 0x3C, 0x61, 0xFB, 0x8C, 0x14, 0x3D, 0x43, 0x3B, 0x1D, 0xC3, 0xA2, 0x96, 0xB3, 0xF8, 0xC4,
    0xF2, 0x26, 0x2B, 0xD8, 0x7C, 0xFC, 0x23, 0x24, 0x66, 0xEF, 0x69, 0x64, 0x50, 0x54, 0x59, 0xF1,
    0xA0, 0x74, 0xAC, 0xC6, 0x7D, 0xB5, 0xE6, 0xE2, 0xC2, 0x7E, 0x67, 0x17, 0x5E, 0xE1, 0xB9, 0x3F,
    0x6C, 0x70, 0x08, 0x99, 0x45, 0x56, 0x76, 0xF9, 0x9A, 0x97, 0x19, 0x72, 0x5C, 0x02, 0x8F, 0x58,
];

/// Decrypts a legacy SA-MP client packet using the specified server port.
///
/// Decryption validates the checksum embedded in the first byte of `src`.
///
/// Decrypts a legacy SA-MP client packet in-place.
///
/// Modifies the provided buffer in-place. The first byte of `data` is assumed to be the checksum.
/// If decryption succeeds, the decrypted payload is shifted left to start at index 0, and the new
/// length of the payload (excluding checksum) is returned.
///
/// # Examples
///
/// ```
/// use raknet_rs::decrypt_in_place;
///
/// let mut packet = vec![0x35, 0x01, 0x02]; // Mock packet [checksum, encrypted_bytes...]
/// // Note: This will fail checksum validation in real tests, unless checksum is correct.
/// ```
///
/// # Arguments
/// * `data` - The mutable packet byte slice.
/// * `port` - The server port number.
///
/// # Returns
/// * `Some(usize)` containing the size of the decrypted payload if successful.
/// * `None` if the input is empty or the checksum verification fails.
pub fn decrypt_in_place(data: &mut [u8], port: u16) -> Option<usize> {
    if data.is_empty() {
        return None;
    }

    let expected_checksum = data[0];
    let len = data.len();
    let port_mask = (port ^ 0xCC) as u8;
    let mut checksum = 0u8;

    for i in 1..len {
        let mut cur = data[i];
        // Alternate the port mask XOR operation every even index
        if (i & 1) == 0 {
            cur ^= port_mask;
        }
        cur = DECRYPT_KEY_TABLE[cur as usize];
        checksum ^= cur & 0xAA;
        data[i - 1] = cur;
    }

    if expected_checksum == checksum {
        Some(len - 1)
    } else {
        None
    }
}

/// Decrypts a legacy SA-MP client packet using the specified server port.
///
/// Decryption validates the checksum embedded in the first byte of `src`.
///
/// # Examples
///
/// ```
/// use raknet_rs::decrypt;
///
/// let packet = vec![0x00, 0x12, 0x34]; // Mock packet [checksum, encrypted_bytes...]
/// let result = decrypt(&packet, 7777);
/// assert!(result.is_none()); // Fails due to incorrect checksum
/// ```
///
/// # Arguments
/// * `src` - The raw packet byte slice received from the client.
/// * `port` - The server port number that the packet was sent to.
///
/// # Returns
/// * `Some(Vec<u8>)` containing the decrypted packet payload (excluding checksum byte) if successful.
/// * `None` if the input is empty or the checksum verification fails.
pub fn decrypt(src: &[u8], port: u16) -> Option<Vec<u8>> {
    if src.is_empty() {
        return None;
    }
    let mut buf = src.to_vec();
    let len = decrypt_in_place(&mut buf, port)?;
    buf.truncate(len);
    Some(buf)
}

/// Encrypts an outgoing packet payload into a pre-allocated destination buffer.
///
/// The destination buffer `dest` must have a length of exactly `src.len() + 1`.
///
/// # Examples
///
/// ```
/// use raknet_rs::encrypt_into;
///
/// let payload = b"Hello";
/// let mut dest = vec![0u8; payload.len() + 1];
/// encrypt_into(payload, &mut dest, 0x12345678).unwrap();
/// ```
///
/// # Arguments
/// * `src` - The raw payload byte slice.
/// * `dest` - The mutable destination slice to write the checksum and ciphertext.
/// * `key` - The player-specific 32-bit encryption key.
///
/// # Returns
/// * `Ok(())` if successful, or `Err` if the destination buffer size is incorrect.
pub fn encrypt_into(src: &[u8], dest: &mut [u8], key: u32) -> Result<(), &'static str> {
    if dest.len() != src.len() + 1 {
        return Err("destination buffer size must be exactly src.len() + 1");
    }

    let key_bytes = key.to_le_bytes();
    let len = src.len();
    let mut checksum = 0u8;

    for i in 0..len {
        let cur = src[i] ^ key_bytes[i % 4];
        checksum ^= src[i] & 0xAA;
        dest[i + 1] = cur;
    }

    dest[0] = checksum;
    Ok(())
}

/// Encrypts an outgoing packet payload using a player-specific 32-bit key.
///
/// Prepend a computed checksum byte at index 0 of the returned vector.
///
/// # Examples
///
/// ```
/// use raknet_rs::encrypt;
///
/// let payload = b"Hello";
/// let encrypted = encrypt(payload, 0x12345678);
/// assert_eq!(encrypted.len(), payload.len() + 1);
/// ```
///
/// # Arguments
/// * `src` - The raw payload byte slice to encrypt.
/// * `key` - The player-specific 32-bit encryption key.
///
/// # Returns
/// A new `Vec<u8>` containing:
/// * Byte 0: The computed checksum of the raw payload.
/// * Bytes 1..N: The encrypted ciphertext payload.
pub fn encrypt(src: &[u8], key: u32) -> Vec<u8> {
    let mut encrypted = vec![0u8; src.len() + 1];
    encrypt_into(src, &mut encrypted, key).unwrap();
    encrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original_data = b"Hello, SA-MP & open.mp developers! Testing cryptography.";
        let key = 0x12345678;
        let port = 7777;

        // 1. Encrypt with player key
        let encrypted = encrypt(original_data, key);
        assert_eq!(encrypted.len(), original_data.len() + 1);

        // Verify custom XOR encryption manually
        let key_bytes = key.to_le_bytes();
        let mut expected_checksum = 0u8;
        for i in 0..original_data.len() {
            expected_checksum ^= original_data[i] & 0xAA;
            assert_eq!(encrypted[i + 1], original_data[i] ^ key_bytes[i % 4]);
        }
        assert_eq!(encrypted[0], expected_checksum);

        // 2. Since SA-MP Decrypt and Encrypt are asymmetric, let's verify decrypt's correctness.
        // We will construct a dummy packet that decrypt will accept.
        // Let's create raw decrypted data:
        let decrypted_target = vec![0x10, 0x20, 0x30, 0x40, 0x55, 0xAA];
        let mut expected_decrypt_checksum = 0u8;
        for &b in &decrypted_target {
            expected_decrypt_checksum ^= b & 0xAA;
        }

        // Re-construct what the encrypted source for decrypt must look like
        let mut encrypted_src = vec![0u8; decrypted_target.len() + 1];
        encrypted_src[0] = expected_decrypt_checksum;

        // In C++, the substitution table mapping is: cur_decrypted = DECRYPT_KEY_TABLE[cur_encrypted]
        // So we need to find an index `idx` in DECRYPT_KEY_TABLE such that DECRYPT_KEY_TABLE[idx] == cur_decrypted.
        // Then cur_encrypted = idx (and possibly XORed with port_mask if even index).
        let port_mask = (port ^ 0xCC) as u8;
        for i in 1..=decrypted_target.len() {
            let target_byte = decrypted_target[i - 1];
            // Find target_byte in DECRYPT_KEY_TABLE
            let table_index = DECRYPT_KEY_TABLE.iter().position(|&x| x == target_byte).unwrap() as u8;
            let mut encrypted_byte = table_index;
            if (i & 1) == 0 {
                encrypted_byte ^= port_mask;
            }
            encrypted_src[i] = encrypted_byte;
        }

        // Perform decryption
        let decrypted_result = decrypt(&encrypted_src, port).expect("Decryption failed");
        assert_eq!(decrypted_result, decrypted_target);
    }

    #[test]
    fn test_decrypt_invalid_checksum() {
        let mut invalid_packet = vec![0x00, 0x12, 0x34, 0x56];
        // Decryption should fail due to invalid checksum
        assert!(decrypt(&invalid_packet, 7777).is_none());

        // Make checksum correct and ensure it succeeds
        let port = 7777;
        let port_mask = (port ^ 0xCC) as u8;
        
        let b1 = DECRYPT_KEY_TABLE[0x12]; // index 1 (odd, no XOR)
        let b2 = DECRYPT_KEY_TABLE[(0x34 ^ port_mask) as usize]; // index 2 (even, XORed)
        let b3 = DECRYPT_KEY_TABLE[0x56]; // index 3 (odd, no XOR)

        let correct_checksum = (b1 & 0xAA) ^ (b2 & 0xAA) ^ (b3 & 0xAA);
        invalid_packet[0] = correct_checksum;

        let res = decrypt(&invalid_packet, port).expect("Should succeed now");
        assert_eq!(res, vec![b1, b2, b3]);
    }

    #[test]
    fn test_inplace_crypto() {
        let original_data = b"Testing in-place crypto APIs";
        let key = 0xAA55BB66;
        let port = 7777;

        // Test encrypt_into
        let mut dest = vec![0u8; original_data.len() + 1];
        encrypt_into(original_data, &mut dest, key).unwrap();

        // Verify standard encryption output matches encrypt_into
        let expected = encrypt(original_data, key);
        assert_eq!(dest, expected);

        // Simulate client-side encryption and then server decrypt_in_place
        // We will construct encrypted client data using client substitution
        let port_mask = (port ^ 0xCC) as u8;
        let mut client_encrypted = vec![0u8; original_data.len() + 1];
        let mut checksum = 0u8;
        for (i, &b) in original_data.iter().enumerate() {
            checksum ^= b & 0xAA;
            let table_index = DECRYPT_KEY_TABLE.iter().position(|&x| x == b).unwrap() as u8;
            let mut encrypted_byte = table_index;
            let byte_pos = i + 1;
            if (byte_pos & 1) == 0 {
                encrypted_byte ^= port_mask;
            }
            client_encrypted[byte_pos] = encrypted_byte;
        }
        client_encrypted[0] = checksum;

        // Perform decrypt_in_place
        let mut decrypt_buf = client_encrypted.clone();
        let payload_len = decrypt_in_place(&mut decrypt_buf, port).unwrap();
        assert_eq!(payload_len, original_data.len());
        assert_eq!(&decrypt_buf[..payload_len], original_data);
    }
}
