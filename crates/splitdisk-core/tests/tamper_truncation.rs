//! Tamper and truncation tests for AEAD stream, chunk frames, and meta.

use splitdisk_core::aead::{decrypt_stream, encrypt_stream, AeadKey, AeadSuite};
use splitdisk_core::error::Error;
use splitdisk_core::format::{
    parse_chunk_frame, parse_meta, write_chunk_frame, write_meta, ChunkFrame, MetaPlaintext,
};
use splitdisk_core::rs::{join_stripes, split_stripes};
use std::io::Cursor;

#[test]
fn aead_flip_bit_in_ciphertext_errors() {
    let key = AeadKey::new([3u8; 32]);
    let pt = vec![0x55u8; 100];
    let mut ct = Vec::new();
    encrypt_stream(
        &key,
        AeadSuite::ChaCha20Poly1305,
        64,
        Cursor::new(&pt),
        &mut ct,
    )
    .unwrap();

    // Flip a bit in the last byte of ciphertext body.
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    let mut out = Vec::new();
    let err = decrypt_stream(&key, Cursor::new(&ct), &mut out);
    assert!(matches!(err, Err(Error::AeadAuth)));
}

#[test]
fn aead_truncation_removes_final_errors() {
    let key = AeadKey::new([4u8; 32]);
    let pt = vec![0x66u8; 130];
    let mut ct = Vec::new();
    encrypt_stream(
        &key,
        AeadSuite::ChaCha20Poly1305,
        64,
        Cursor::new(&pt),
        &mut ct,
    )
    .unwrap();

    // Drop the last segment entirely (header is 12 bytes; keep only first segment).
    // Find second segment start: after header + first record.
    // Simpler: truncate last 20 bytes.
    ct.truncate(ct.len().saturating_sub(40));

    let mut out = Vec::new();
    let err = decrypt_stream(&key, Cursor::new(&ct), &mut out);
    assert!(
        matches!(
            err,
            Err(Error::AeadTruncation | Error::AeadAuth | Error::Format(_) | Error::UnexpectedEof)
        ),
        "got {err:?}"
    );
}

#[test]
fn aead_flip_header_suite_errors() {
    let key = AeadKey::new([5u8; 32]);
    let mut ct = Vec::new();
    encrypt_stream(
        &key,
        AeadSuite::ChaCha20Poly1305,
        64,
        Cursor::new(b"abc"),
        &mut ct,
    )
    .unwrap();
    // suite_id at offset 6..8
    ct[6] ^= 0xff;
    let mut out = Vec::new();
    assert!(decrypt_stream(&key, Cursor::new(&ct), &mut out).is_err());
}

#[test]
fn chunk_frame_flip_hash_errors_on_rs_join() {
    let data = vec![0x77u8; 64];
    let k = 2usize;
    let n = 3usize;
    let stripe = 64;
    let mut outs: Vec<Cursor<Vec<u8>>> = (0..n).map(|_| Cursor::new(Vec::new())).collect();
    split_stripes(Cursor::new(&data), &mut outs, k, n, stripe).unwrap();

    // Flip one bit in share 0's stored hash (offset 23..55 in first frame).
    let buf = outs[0].get_mut();
    buf[23] ^= 0x01;

    let indices = [0u8, 1];
    let mut readers: Vec<Cursor<Vec<u8>>> = indices
        .iter()
        .map(|&i| Cursor::new(outs[i as usize].get_ref().clone()))
        .collect();
    let mut out = Vec::new();
    let err = join_stripes(&mut readers, &indices, &mut out, k, n);
    assert!(matches!(err, Err(Error::Integrity)));
    assert!(out.is_empty());
}

#[test]
fn meta_flip_field_errors() {
    let m = MetaPlaintext {
        version: 1,
        share_index: 1,
        k: 3,
        n: 5,
        suite_id: 1,
        chunk_blake3: [9u8; 32],
        drive_fingerprint: [8u8; 32],
    };
    let mut buf = Vec::new();
    write_meta(&mut buf, &m).unwrap();
    buf[7] ^= 0x01; // flip k — still parses, but demonstrate field sensitivity
    let parsed = parse_meta(&buf).unwrap();
    assert_ne!(parsed.k, m.k);

    // Flip magic -> error
    buf[0] ^= 0x01;
    assert!(matches!(parse_meta(&buf), Err(Error::Format(_))));
}

#[test]
fn chunk_truncated_header_errors() {
    let data = vec![1u8, 2, 3];
    let frame = ChunkFrame {
        version: 1,
        share_index: 0,
        stripe_index: 0,
        original_stripe_len: 3,
        shard_len: 3,
        hash: *blake3::hash(&data).as_bytes(),
        data,
    };
    let mut buf = Vec::new();
    write_chunk_frame(&mut buf, &frame).unwrap();
    buf.truncate(10);
    assert!(parse_chunk_frame(&mut Cursor::new(&buf)).is_err());
}
