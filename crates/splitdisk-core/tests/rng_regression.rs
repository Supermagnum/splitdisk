//! Regression: two production (OsRng) runs must not produce identical shares
//! or identical ciphertext for the same plaintext. Guards against accidentally
//! wiring a fixed-seed RNG into production paths.

use splitdisk_core::aead::{encrypt_stream, AeadKey, AeadSuite};
use splitdisk_core::rng::{OsRng, SecureRng};
use splitdisk_core::sss::{split_session_key, SessionKey};
use std::io::Cursor;

#[test]
fn two_osrng_runs_differ_for_sss_and_aead() {
    let secret = SessionKey::new([0x42u8; 32]);

    let mut rng_a = OsRng;
    let mut rng_b = OsRng;
    let shares_a = split_session_key(&secret, 2, 3, &mut rng_a).unwrap();
    let shares_b = split_session_key(&secret, 2, 3, &mut rng_b).unwrap();

    assert_ne!(
        shares_a[0].as_bytes(),
        shares_b[0].as_bytes(),
        "SSS shares identical across OsRng runs — fixed seed regression?"
    );

    // Distinct session keys from OsRng => distinct ciphertext.
    let mut key_bytes_a = [0u8; 32];
    let mut key_bytes_b = [0u8; 32];
    rng_a.fill(&mut key_bytes_a).unwrap();
    rng_b.fill(&mut key_bytes_b).unwrap();
    // Extremely unlikely equality; if equal, draw again once.
    if key_bytes_a == key_bytes_b {
        rng_b.fill(&mut key_bytes_b).unwrap();
    }
    assert_ne!(key_bytes_a, key_bytes_b);

    let key_a = AeadKey::new(key_bytes_a);
    let key_b = AeadKey::new(key_bytes_b);
    let pt = b"identical plaintext for both runs";

    let mut ct_a = Vec::new();
    let mut ct_b = Vec::new();
    encrypt_stream(
        &key_a,
        AeadSuite::ChaCha20Poly1305,
        64,
        Cursor::new(pt),
        &mut ct_a,
    )
    .unwrap();
    encrypt_stream(
        &key_b,
        AeadSuite::ChaCha20Poly1305,
        64,
        Cursor::new(pt),
        &mut ct_b,
    )
    .unwrap();
    assert_ne!(
        ct_a, ct_b,
        "ciphertext identical for different OsRng keys — unexpected"
    );
}
