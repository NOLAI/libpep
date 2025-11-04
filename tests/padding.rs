use libpep::high_level::contexts::{
    EncryptionContext, PseudonymizationDomain, PseudonymizationInfo,
};
use libpep::high_level::data_types::{Attribute, Encryptable, EncryptedPseudonym, Pseudonym};
use libpep::high_level::keys::{make_pseudonym_global_keys, make_pseudonym_session_keys};
use libpep::high_level::ops::{decrypt, encrypt, pseudonymize};
use libpep::high_level::padding::{LongAttribute, LongPseudonym, Padded};
use libpep::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use std::io::{Error, ErrorKind};

#[test]
fn test_from_bytes_padded_empty() {
    let data: &[u8] = &[];
    let result = LongAttribute::from_bytes_padded(data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_from_bytes_padded_single_block() {
    // Test with less than 16 bytes
    let data = b"Hello, world!";
    let result = LongAttribute::from_bytes_padded(data).unwrap();

    assert_eq!(1, result.len());

    // The padding should be 3 bytes of value 3
    let bytes = result[0].as_bytes().unwrap();
    assert_eq!(b"Hello, world!\x03\x03\x03", &bytes);
}

#[test]
fn test_from_bytes_padded_exact_block() {
    // Test with exactly 16 bytes
    let data = b"0123456789ABCDEF";
    let result = LongAttribute::from_bytes_padded(data).unwrap();

    // Should have 2 blocks: the 16 bytes of data and one full block of padding
    assert_eq!(2, result.len());

    // First block should be exactly our input
    assert_eq!(b"0123456789ABCDEF", &result[0].as_bytes().unwrap());

    // Second block should be all padding bytes with value 16
    let expected_padding = [16u8; 16];
    assert_eq!(expected_padding, result[1].as_bytes().unwrap());
}

#[test]
fn test_from_bytes_padded_multiple_blocks() {
    // Test with more than 16 bytes
    let data = b"This is a longer string that spans multiple blocks";
    let result = LongAttribute::from_bytes_padded(data).unwrap();

    // Calculate expected number of blocks (51 bytes -> 4 blocks)
    let expected_blocks = (data.len() / 16) + 1;
    assert_eq!(expected_blocks, result.len());

    // Check the content of each full block
    for (i, block) in result.iter().enumerate().take(data.len() / 16) {
        let start = i * 16;
        let expected = data[start..start + 16].to_vec();
        assert_eq!(expected, block.as_bytes().unwrap()[..16]);
    }

    // Check the last block's padding
    let last_block = result.last().unwrap().as_bytes().unwrap();
    let remaining = data.len() % 16;
    let padding_byte = (16 - remaining) as u8;

    // Verify data portion
    assert_eq!(&data[data.len() - remaining..], &last_block[..remaining]);

    // Verify padding portion
    for byte in last_block.iter().skip(remaining) {
        assert_eq!(&padding_byte, byte);
    }
}

#[test]
fn test_to_bytes_padded() -> Result<(), Error> {
    // Create some test data
    let original = b"This is some test data for padding";

    // Encode it
    let attributes = LongAttribute::from_bytes_padded(original)?;

    // Decode it
    let decoded = attributes.to_bytes_padded()?;

    // Verify it matches the original
    assert_eq!(original, decoded.as_slice());

    Ok(())
}

#[test]
fn test_to_bytes_padded_empty() {
    // Test with empty vec
    let attributes = LongAttribute::from(vec![]);
    let result = attributes.to_bytes_padded();

    // Should be an error
    assert!(result.is_err());
    match result {
        Err(e) => {
            assert_eq!(ErrorKind::InvalidInput, e.kind());
        }
        _ => panic!("Expected an error"),
    }
}

#[test]
fn test_to_bytes_padded_invalid_padding() {
    use libpep::high_level::data_types::Attribute;

    // Create an Attribute with invalid padding (padding byte = 0)
    let invalid_block = [0u8; 16];
    let attribute = Attribute::from_bytes(&invalid_block);
    let long_attr = LongAttribute::from(vec![attribute]);

    // Attempt to decode
    let result = long_attr.to_bytes_padded();

    // Should be an error
    assert!(result.is_err());
    match result {
        Err(e) => {
            assert_eq!(ErrorKind::InvalidData, e.kind());
        }
        _ => panic!("Expected an error"),
    }

    // Try with inconsistent padding (some bytes have different values)
    let mut inconsistent_block = [5u8; 16]; // padding of 5
    inconsistent_block[15] = 6; // but one byte is wrong
    let attribute = Attribute::from_bytes(&inconsistent_block);
    let long_attr = LongAttribute::from(vec![attribute]);

    // Attempt to decode
    let result = long_attr.to_bytes_padded();

    // Should be an error
    assert!(result.is_err());
}

#[test]
fn test_to_string_padded() -> Result<(), Error> {
    // Test string
    let original = "This is a UTF-8 string with special chars: ñáéíóú 你好";

    // Encode it
    let attributes = LongAttribute::from_string_padded(original)?;

    // Decode it
    let decoded = attributes.to_string_padded()?;

    // Verify it matches the original
    assert_eq!(original, decoded);

    Ok(())
}

#[test]
fn test_to_string_padded_invalid_utf8() {
    use libpep::high_level::data_types::Attribute;

    // Create data points with non-UTF8 data
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
    let mut block = [0u8; 16];
    block[..3].copy_from_slice(&invalid_utf8);
    block[3..].fill(13); // Padding

    let attribute = Attribute::from_bytes(&block);
    let long_attr = LongAttribute::from(vec![attribute]);

    // Attempt to decode to string
    let result = long_attr.to_string_padded();

    // Should be an error
    assert!(result.is_err());
}

#[test]
fn test_roundtrip_all_padding_sizes() -> Result<(), Error> {
    // Test all possible padding sizes (1-16)
    for padding_size in 1..=16 {
        let size = 32 - padding_size; // 32 is arbitrary, just want multiple blocks
        let data = vec![b'X'; size];

        // Encode
        let attributes = LongAttribute::from_bytes_padded(&data)?;

        // Decode
        let decoded = attributes.to_bytes_padded()?;

        // Verify
        assert_eq!(data, decoded);
    }

    Ok(())
}

#[test]
fn test_pseudonym_from_bytes_padded() {
    // Test with less than 16 bytes
    let data = b"Hello, world!";
    let result = LongPseudonym::from_bytes_padded(data).unwrap();

    assert_eq!(1, result.len());

    // The padding should be 3 bytes of value 3
    let bytes = result[0].as_bytes().unwrap();
    assert_eq!(b"Hello, world!\x03\x03\x03", &bytes);
}

#[test]
fn test_pseudonym_to_bytes_padded() -> Result<(), Error> {
    // Create some test data
    let original = b"This is some test data for padding";

    // Encode it
    let pseudonyms = LongPseudonym::from_bytes_padded(original)?;

    // Decode it
    let decoded = pseudonyms.to_bytes_padded()?;

    // Verify it matches the original
    assert_eq!(original, decoded.as_slice());

    Ok(())
}

#[test]
fn test_pseudonym_string_roundtrip() -> Result<(), Error> {
    // Test string
    let original = "Testing pseudonym string conversion";

    // Encode it
    let pseudonyms = LongPseudonym::from_string_padded(original)?;

    // Decode it
    let decoded = pseudonyms.to_string_padded()?;

    // Verify it matches the original
    assert_eq!(original, decoded);

    Ok(())
}

#[test]
fn test_pseudonymize_string_roundtrip() -> Result<(), Error> {
    // Initialize test environment
    let mut rng = rand::thread_rng();
    let (_global_public, global_secret) = make_pseudonym_global_keys(&mut rng);
    let pseudo_secret = PseudonymizationSecret::from("test-secret".as_bytes().to_vec());
    let enc_secret = EncryptionSecret::from("enc-secret".as_bytes().to_vec());

    // Setup domains and contexts
    let domain_a = PseudonymizationDomain::from("domain-a");
    let domain_b = PseudonymizationDomain::from("domain-b");
    let session = EncryptionContext::from("session-1");

    // Create session keys
    let (session_public, session_secret) =
        make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

    // Original string to encrypt and pseudonymize
    let original_string = "This is a very long id that will be pseudonymized";

    // Step 1: Convert string to padded pseudonyms
    let pseudonym = LongPseudonym::from_string_padded(original_string)?;

    // Step 2: Encrypt the pseudonyms
    let encrypted_pseudonyms: Vec<EncryptedPseudonym> = pseudonym
        .iter()
        .map(|p| encrypt(p, &session_public, &mut rng))
        .collect();

    // Step 3: Create pseudonymization info for transform
    let pseudo_info = PseudonymizationInfo::new(
        &domain_a,
        &domain_b,
        Some(&session),
        Some(&session),
        &pseudo_secret,
        &enc_secret,
    );

    // Step 4: Pseudonymize (transform) the encrypted pseudonyms
    let transformed_pseudonyms: Vec<EncryptedPseudonym> = encrypted_pseudonyms
        .iter()
        .map(|ep| pseudonymize(ep, &pseudo_info))
        .collect();

    // Step 5: Decrypt the transformed pseudonyms
    let decrypted_pseudonyms: Vec<Pseudonym> = transformed_pseudonyms
        .iter()
        .map(|ep| decrypt(ep, &session_secret))
        .collect();

    // Step 6: Encrypt the decrypted pseudonyms
    let re_encrypted_pseudonyms: Vec<EncryptedPseudonym> = decrypted_pseudonyms
        .iter()
        .map(|p| encrypt(p, &session_public, &mut rng))
        .collect();

    // Step 7: Reverse the pseudonymization
    let reverse_pseudo_info = PseudonymizationInfo::new(
        &domain_b,
        &domain_a,
        Some(&session),
        Some(&session),
        &pseudo_secret,
        &enc_secret,
    );

    let reverse_transformed: Vec<EncryptedPseudonym> = re_encrypted_pseudonyms
        .iter()
        .map(|ep| pseudonymize(ep, &reverse_pseudo_info))
        .collect();

    let reverse_decrypted: Vec<Pseudonym> = reverse_transformed
        .iter()
        .map(|ep| decrypt(ep, &session_secret))
        .collect();

    let reverse_long = LongPseudonym::from(reverse_decrypted);
    let reverse_string = reverse_long.to_string_padded()?;

    // After reversing the pseudonymization, we should get back the original string
    assert_eq!(original_string, reverse_string);

    Ok(())
}

// ===== Tests for single-block Pseudonym and Attribute padding =====

#[test]
fn test_pseudonym_single_block_from_bytes_padded() -> Result<(), Error> {
    // Test with various byte lengths up to 15
    let test_cases = [
        b"" as &[u8],
        b"a",
        b"hello",
        b"Hello, world!",
        b"123456789012345", // 15 bytes (max)
    ];

    for data in test_cases {
        let pseudo = Pseudonym::from_bytes_padded(data)?;
        let decoded = pseudo.to_bytes_padded()?;
        assert_eq!(data, decoded.as_slice(), "Failed for input: {:?}", data);
    }

    Ok(())
}

#[test]
fn test_pseudonym_single_block_from_string_padded() -> Result<(), Error> {
    // Test with various strings up to 15 bytes
    let test_cases = ["", "a", "hello", "Hello, world!", "123456789012345"];

    for text in test_cases {
        let pseudo = Pseudonym::from_string_padded(text)?;
        let decoded = pseudo.to_string_padded()?;
        assert_eq!(text, decoded.as_str(), "Failed for input: {:?}", text);
    }

    Ok(())
}

#[test]
fn test_pseudonym_single_block_too_long() {
    // Test that data > 15 bytes returns an error
    let data = b"This is 16 bytes"; // Exactly 16 bytes
    let result = Pseudonym::from_bytes_padded(data);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);

    let data = b"This is way more than 15 bytes!";
    let result = Pseudonym::from_bytes_padded(data);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);

    // Test with string
    let text = "This is way more than 15 bytes!";
    let result = Pseudonym::from_string_padded(text);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn test_pseudonym_single_block_padding_correctness() -> Result<(), Error> {
    // Test empty data (should pad with 16 bytes of value 16)
    let pseudo = Pseudonym::from_bytes_padded(b"")?;
    let bytes = pseudo.as_bytes().unwrap();
    assert_eq!([16u8; 16], bytes);

    // Test 1 byte (should pad with 15 bytes of value 15)
    let pseudo = Pseudonym::from_bytes_padded(b"X")?;
    let bytes = pseudo.as_bytes().unwrap();
    assert_eq!(b'X', bytes[0]);
    for byte in bytes.iter().skip(1) {
        assert_eq!(15, *byte);
    }

    // Test 15 bytes (should pad with 1 byte of value 1)
    let data = b"123456789012345";
    let pseudo = Pseudonym::from_bytes_padded(data)?;
    let bytes = pseudo.as_bytes().unwrap();
    assert_eq!(data, &bytes[..15]);
    assert_eq!(1, bytes[15]);

    Ok(())
}

#[test]
fn test_attribute_single_block_from_bytes_padded() -> Result<(), Error> {
    // Test with various byte lengths up to 15
    let test_cases = [
        b"" as &[u8],
        b"a",
        b"hello",
        b"Hello, world!",
        b"123456789012345", // 15 bytes (max)
    ];

    for data in test_cases {
        let attr = Attribute::from_bytes_padded(data)?;
        let decoded = attr.to_bytes_padded()?;
        assert_eq!(data, decoded.as_slice(), "Failed for input: {:?}", data);
    }

    Ok(())
}

#[test]
fn test_attribute_single_block_from_string_padded() -> Result<(), Error> {
    // Test with various strings up to 15 bytes
    let test_cases = ["", "a", "hello", "Hello, world!", "123456789012345"];

    for text in test_cases {
        let attr = Attribute::from_string_padded(text)?;
        let decoded = attr.to_string_padded()?;
        assert_eq!(text, decoded.as_str(), "Failed for input: {:?}", text);
    }

    Ok(())
}

#[test]
fn test_attribute_single_block_too_long() {
    // Test that data > 15 bytes returns an error
    let data = b"This is 16 bytes"; // Exactly 16 bytes
    let result = Attribute::from_bytes_padded(data);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);

    let data = b"This is way more than 15 bytes!";
    let result = Attribute::from_bytes_padded(data);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);

    // Test with string
    let text = "This is way more than 15 bytes!";
    let result = Attribute::from_string_padded(text);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn test_attribute_single_block_unicode() -> Result<(), Error> {
    // Test with Unicode characters (counting bytes, not chars)
    let test_cases = [
        "café", // 5 bytes (é is 2 bytes)
        "你好", // 6 bytes (each Chinese char is 3 bytes)
        "🎉",   // 4 bytes (emoji)
    ];

    for text in test_cases {
        let attr = Attribute::from_string_padded(text)?;
        let decoded = attr.to_string_padded()?;
        assert_eq!(text, decoded.as_str(), "Failed for input: {:?}", text);
    }

    Ok(())
}

#[test]
fn test_attribute_single_block_unicode_too_long() {
    // A string that looks short but is > 16 bytes in UTF-8
    let text = "你好世界！"; // 15 bytes (5 chars × 3 bytes each)
    let result = Attribute::from_string_padded(text);
    assert!(result.is_ok()); // Should fit

    let text = "你好世界！！"; // 18 bytes (6 chars × 3 bytes each)
    let result = Attribute::from_string_padded(text);
    assert!(result.is_err()); // Should not fit
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn test_single_block_invalid_padding_decode() {
    // Create an attribute with invalid padding (padding byte = 0)
    let invalid_block = [0u8; 16];
    let attr = Attribute::from_bytes(&invalid_block);
    let result = attr.to_bytes_padded();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);

    // Create an attribute with inconsistent padding
    let mut inconsistent_block = [5u8; 16];
    inconsistent_block[15] = 6; // Wrong padding byte
    let attr = Attribute::from_bytes(&inconsistent_block);
    let result = attr.to_bytes_padded();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);

    // Create an attribute with padding byte > 16
    let mut invalid_block = [17u8; 16];
    invalid_block[0] = b'X'; // Some data
    let attr = Attribute::from_bytes(&invalid_block);
    let result = attr.to_bytes_padded();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
}

#[test]
fn test_single_block_roundtrip_all_sizes() -> Result<(), Error> {
    // Test roundtrip for all possible data sizes (0-15 bytes)
    for size in 0..=15 {
        let data = vec![b'X'; size];

        // Test with Pseudonym
        let pseudo = Pseudonym::from_bytes_padded(&data)?;
        let decoded = pseudo.to_bytes_padded()?;
        assert_eq!(data, decoded, "Pseudonym failed for size {}", size);

        // Test with Attribute
        let attr = Attribute::from_bytes_padded(&data)?;
        let decoded = attr.to_bytes_padded()?;
        assert_eq!(data, decoded, "Attribute failed for size {}", size);
    }

    Ok(())
}
