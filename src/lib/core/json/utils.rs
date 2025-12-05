//! Utility functions for JSON value conversion.

use super::data::JsonError;

/// Convert a boolean to a single byte (0x00 for false, 0x01 for true)
pub fn bool_to_byte(b: bool) -> u8 {
    if b {
        0x01
    } else {
        0x00
    }
}

/// Convert a byte to a boolean. Returns an error if the byte is neither 0x00 nor 0x01
pub fn byte_to_bool(byte: u8) -> Result<bool, JsonError> {
    match byte {
        0x00 => Ok(false),
        0x01 => Ok(true),
        b => Err(format!(
            "Invalid boolean byte value: 0x{:02x}. Expected 0x00 or 0x01",
            b
        )),
    }
}

/// Convert a JSON number to bytes (9 bytes: 1 byte type tag + 8 bytes data).
///
/// Type tags:
/// - 0x00: unsigned integer (u64)
/// - 0x01: signed integer (i64)
/// - 0x02: float (f64)
///
/// This method never fails for numbers created by serde_json since they are always
/// one of u64, i64, or f64.
pub fn number_to_bytes(n: &serde_json::Number) -> [u8; 9] {
    if let Some(u) = n.as_u64() {
        let mut bytes = [0u8; 9];
        bytes[0] = 0x00; // u64 tag
        bytes[1..].copy_from_slice(&u.to_be_bytes());
        bytes
    } else if let Some(i) = n.as_i64() {
        let mut bytes = [0u8; 9];
        bytes[0] = 0x01; // i64 tag
        bytes[1..].copy_from_slice(&i.to_be_bytes());
        bytes
    } else if let Some(f) = n.as_f64() {
        let mut bytes = [0u8; 9];
        bytes[0] = 0x02; // f64 tag
        bytes[1..].copy_from_slice(&f.to_bits().to_be_bytes());
        bytes
    } else {
        // This should never happen with standard serde_json::Number
        unreachable!("serde_json::Number is always u64, i64, or f64")
    }
}

/// Convert bytes to a JSON number (9 bytes: 1 byte type tag + 8 bytes data).
pub fn bytes_to_number(bytes: &[u8; 9]) -> serde_json::Number {
    let type_tag = bytes[0];
    let data_bytes: [u8; 8] = match bytes[1..].try_into() {
        Ok(bytes) => bytes,
        Err(_) => unreachable!("slice is always 8 bytes"),
    };

    match type_tag {
        0x00 => {
            // u64
            let u = u64::from_be_bytes(data_bytes);
            serde_json::Number::from(u)
        }
        0x01 => {
            // i64
            let i = i64::from_be_bytes(data_bytes);
            serde_json::Number::from(i)
        }
        0x02 => {
            // f64
            let bits = u64::from_be_bytes(data_bytes);
            let f = f64::from_bits(bits);
            match serde_json::Number::from_f64(f) {
                Some(n) => n,
                None => panic!("Number should be finite but got: {}", f),
            }
        }
        _ => panic!("Invalid number type tag: 0x{:02x}", type_tag),
    }
}
