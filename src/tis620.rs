//! TIS-620 / Windows-874 Thai character encoding converter.
//!
//! Provides zero-dependency encoding and decoding between UTF-8 and TIS-620
//! mapping tables for legacy SA-MP/open.mp clients.

/// Encodes a UTF-8 string into a TIS-620 byte vector.
///
/// ASCII characters (`U+0000` to `U+007F`) map 1-to-1.
/// Unicode Thai characters (`U+0E01` to `U+0E5B`) map to TIS-620 by:
/// `byte = unicode_char_value - 0x0E00 + 0xA0`.
/// Other characters default to `?` (0x3F).
pub fn encode_tis620(s: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp <= 0x7F {
            result.push(cp as u8);
        } else if cp >= 0x0E00 && cp <= 0x0E7F {
            result.push((cp - 0x0E00 + 0xA0) as u8);
        } else {
            result.push(b'?');
        }
    }
    result
}

/// Decodes a TIS-620 byte slice into a UTF-8 String.
pub fn decode_tis620(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if b <= 0x7F {
            s.push(b as char);
        } else if b >= 0xA0 && b <= 0xFE {
            let cp = b as u32 - 0xA0 + 0x0E00;
            if let Some(c) = char::from_u32(cp) {
                s.push(c);
            } else {
                s.push('?');
            }
        } else {
            s.push('?');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tis620_roundtrip() {
        let original = "ยินดีต้อนรับสู่เซิร์ฟเวอร์ Rust! Hello 123";
        let encoded = encode_tis620(original);
        
        // "ย" is U+0E22 -> should map to 0x22 + 0xA0 = 0xC2
        assert_eq!(encoded[0], 0xC2);
        
        let decoded = decode_tis620(&encoded);
        assert_eq!(decoded, original);
    }
}
