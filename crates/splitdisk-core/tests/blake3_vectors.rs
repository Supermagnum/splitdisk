//! Official BLAKE3 test vectors (from the BLAKE3 specification).

#[test]
fn blake3_empty() {
    let h = blake3::hash(b"");
    assert_eq!(
        h.to_hex().as_str(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

#[test]
fn blake3_one_byte() {
    // From BLAKE3 test_vectors.json: input_len 1 (byte 0x00); first 32 bytes of hash.
    let h = blake3::hash(&[0u8]);
    assert_eq!(
        h.to_hex().as_str(),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
    );
}

#[test]
fn blake3_derive_key_domain_separation() {
    let ikm = [0u8; 32];
    let a = blake3::derive_key("cess-kem-v1", &ikm);
    let b = blake3::derive_key("cess-pin-v1", &ikm);
    assert_ne!(a, b);
}
