//! Utility functions for JSON value conversion.

use super::core::JsonError;

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

/// Convert a JSON number to bytes (8 bytes for u64/i64/f64).
///
/// This method never fails for numbers created by serde_json since they are always
/// one of u64, i64, or f64.
pub fn number_to_bytes(n: &serde_json::Number) -> [u8; 8] {
    if let Some(u) = n.as_u64() {
        u.to_be_bytes()
    } else if let Some(i) = n.as_i64() {
        i.to_be_bytes()
    } else if let Some(f) = n.as_f64() {
        f.to_bits().to_be_bytes()
    } else {
        // This should never happen with standard serde_json::Number
        unreachable!("serde_json::Number is always u64, i64, or f64")
    }
}

/// Convert bytes to a JSON number
pub fn bytes_to_number(bytes: &[u8; 8]) -> serde_json::Number {
    let value = u64::from_be_bytes(*bytes);

    // Try to interpret as signed integer first (most common case)
    let signed = value as i64;
    if signed >= 0 {
        serde_json::Number::from(value)
    } else {
        serde_json::Number::from(signed)
    }
}
