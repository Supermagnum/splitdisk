#![forbid(unsafe_code)]
//! Enrollment: encrypt, RS-split, SSS-split, write file-backed carriers, verify.

use splitdisk_auth::{derive_k_pin, hash_pin, validate_pin, verify_pin, Argon2Params};
use splitdisk_core::aead::{encrypt_stream, AeadKey, AeadSuite, SUITE_CHACHA20};
use splitdisk_core::error::{Error, Result};
use splitdisk_core::format::{
    parse_key_wrap, parse_meta, parse_pin_hash, read_drive_sections, seal_meta, unwrap_key_share,
    wrap_key_share, write_drive, write_key_wrap, write_meta, write_pin_hash, DriveSections,
    MetaPlaintext,
};
use splitdisk_core::path::validate_carrier_path;
use splitdisk_core::rng::{OsRng, SecureRng};
use splitdisk_core::rs::{join_stripes, split_stripes};
use splitdisk_core::sss::{combine_session_key, split_session_key, KeyShare, SessionKey};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Parameters for a Phase 2 file-backed enrollment.
#[derive(Debug, Clone)]
pub struct EnrollParams {
    pub input: PathBuf,
    pub drive_paths: Vec<PathBuf>,
    pub pins: Vec<String>,
    pub threshold_k: usize,
    pub stripe_size: usize,
    pub segment_size: usize,
    pub argon2: Argon2Params,
}

/// Result of enrollment including source hash for later assembly checks.
#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub source_blake3: [u8; 32],
    pub n: usize,
    pub k: usize,
}

/// Unlocked carrier contents after PIN success.
pub struct UnlockedCarrier {
    pub source_blake3: [u8; 32],
    pub meta: MetaPlaintext,
    pub share: KeyShare,
    pub chunk: Vec<u8>,
}

/// Run full enrollment against regular-file carriers (SPEC §8.4–8.5).
///
/// ECDH / Mode A outer envelope is **not** used in Phase 2 (Brainpool arithmetic
/// unavailable — OPEN-QUESTIONS (a)). Key shares are PIN-wrapped only.
pub fn enroll(params: &EnrollParams, rng: &mut dyn SecureRng) -> Result<EnrollResult> {
    let n = params.drive_paths.len();
    let k = params.threshold_k;
    splitdisk_core::sss::validate_threshold(k, n)?;
    if params.pins.len() != n {
        return Err(Error::InvalidParameter("pins.len() must equal drive count"));
    }
    if params.stripe_size == 0 || params.stripe_size % k != 0 {
        return Err(Error::InvalidParameter(
            "stripe_size must be non-zero and divisible by k",
        ));
    }
    for p in &params.drive_paths {
        validate_carrier_path(p)?;
    }
    validate_carrier_path(&params.input)?;

    for pin in &params.pins {
        validate_pin(pin).map_err(|_| Error::InvalidParameter("PIN validation failed"))?;
    }

    let source_blake3 = hash_file(&params.input)?;

    let session = SessionKey::generate(rng)?;
    let aead_key = AeadKey::new(*session.as_bytes());

    let ct_path = params.input.with_extension("splitdisk.ct.tmp");
    {
        let input = File::open(&params.input)?;
        let mut ct_out = BufWriter::new(File::create(&ct_path)?);
        encrypt_stream(
            &aead_key,
            AeadSuite::ChaCha20Poly1305,
            params.segment_size,
            BufReader::new(input),
            &mut ct_out,
        )?;
        ct_out.flush()?;
    }

    let mut chunk_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
    {
        let ct_in = File::open(&ct_path)?;
        let mut out_cursors: Vec<Cursor<Vec<u8>>> =
            (0..n).map(|_| Cursor::new(Vec::new())).collect();
        split_stripes(
            BufReader::new(ct_in),
            &mut out_cursors,
            k,
            n,
            params.stripe_size,
        )?;
        for c in out_cursors {
            chunk_bufs.push(c.into_inner());
        }
    }
    let _ = fs::remove_file(&ct_path);

    let shares = split_session_key(&session, k, n, rng)?;

    for i in 0..n {
        write_one_drive(
            &params.drive_paths[i],
            i as u8,
            k as u8,
            n as u8,
            &params.pins[i],
            &shares[i],
            &chunk_bufs[i],
            &source_blake3,
            params.stripe_size as u32,
            params.argon2,
            rng,
        )?;
    }

    drop(aead_key);
    drop(session);

    verify_reconstruction_dry_run(params, &source_blake3)?;

    Ok(EnrollResult {
        source_blake3,
        n,
        k,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_one_drive(
    path: &Path,
    share_index: u8,
    k: u8,
    n: u8,
    pin: &str,
    share: &KeyShare,
    chunk: &[u8],
    source_blake3: &[u8; 32],
    stripe_size: u32,
    argon2: Argon2Params,
    rng: &mut dyn SecureRng,
) -> Result<()> {
    let pin_rec = hash_pin(pin, argon2, rng).map_err(|_| Error::AuthFailed)?;
    let argon_out = verify_pin(pin, &pin_rec).map_err(|_| Error::AuthFailed)?;
    let k_pin = derive_k_pin(&argon_out);

    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)?;
    let mut drive_uuid = [0u8; splitdisk_core::DRIVE_UUID_LEN];
    rng.fill(&mut drive_uuid)?;
    // Must not encode share_index into the UUID (holder anonymity).
    if drive_uuid.iter().all(|&b| b == share_index) {
        rng.fill(&mut drive_uuid)?;
    }

    let wrap = wrap_key_share(&k_pin, &nonce, &drive_uuid, share.as_bytes())?;
    let mut share_bytes = Vec::new();
    write_key_wrap(&mut share_bytes, &wrap)?;

    let mut fingerprint = [0u8; 32];
    rng.fill(&mut fingerprint)?;

    let chunk_blake3 = *blake3::hash(chunk).as_bytes();
    let meta = MetaPlaintext {
        version: 1,
        share_index,
        k,
        n,
        suite_id: SUITE_CHACHA20,
        chunk_blake3,
        drive_fingerprint: fingerprint,
        stripe_size,
    };
    let mut meta_pt = Vec::new();
    write_meta(&mut meta_pt, &meta)?;
    let meta_sealed = seal_meta(&k_pin, &drive_uuid, &meta_pt)?;
    meta_pt.zeroize();

    let mut pin_bytes = Vec::new();
    write_pin_hash(&mut pin_bytes, &pin_rec)?;

    let sections = DriveSections {
        source_blake3: *source_blake3,
        drive_uuid,
        suite_id: SUITE_CHACHA20,
        chunk: chunk.to_vec(),
        pin_hash: pin_bytes,
        share_wrap: share_bytes,
        meta_sealed,
    };

    let mut file = File::create(path)?;
    write_drive(&mut file, &sections)?;
    file.sync_all()?;

    let mut check = File::open(path)?;
    let (_hdr, got) = read_drive_sections(&mut check)?;
    let got_hash = *blake3::hash(&got.chunk).as_bytes();
    if got_hash != chunk_blake3 {
        return Err(Error::Integrity);
    }
    Ok(())
}

fn verify_reconstruction_dry_run(params: &EnrollParams, source_blake3: &[u8; 32]) -> Result<()> {
    let k = params.threshold_k;
    let paths: Vec<&Path> = params
        .drive_paths
        .iter()
        .take(k)
        .map(|p| p.as_path())
        .collect();
    let pins: Vec<&str> = params.pins.iter().take(k).map(|s| s.as_str()).collect();

    let mut plaintext = reconstruct_to_vec(&paths, &pins)?;
    let out_hash = *blake3::hash(&plaintext).as_bytes();
    plaintext.zeroize();
    if !bool::from(out_hash.ct_eq(source_blake3)) {
        return Err(Error::Integrity);
    }
    Ok(())
}

/// Unlock carriers and reconstruct plaintext (small fixtures / dry-run).
pub fn reconstruct_to_vec(paths: &[&Path], pins: &[&str]) -> Result<Vec<u8>> {
    if paths.len() != pins.len() {
        return Err(Error::InvalidParameter("paths/pins length mismatch"));
    }
    if paths.is_empty() {
        return Err(Error::NotEnoughShares { need: 2, have: 0 });
    }

    let mut key_shares: Vec<KeyShare> = Vec::new();
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut indices: Vec<u8> = Vec::new();
    let mut seen_fp: Vec<[u8; 32]> = Vec::new();
    let mut scheme_k: Option<u8> = None;
    let mut scheme_n: Option<u8> = None;
    let mut source_blake3 = [0u8; 32];

    for (path, pin) in paths.iter().zip(pins.iter()) {
        let unlocked = unlock_carrier(path, pin)?;
        if let Some(sk) = scheme_k {
            if unlocked.meta.k != sk || unlocked.meta.n != scheme_n.unwrap_or(0) {
                return Err(Error::Format("inconsistent k/n across carriers"));
            }
        } else {
            scheme_k = Some(unlocked.meta.k);
            scheme_n = Some(unlocked.meta.n);
            source_blake3 = unlocked.source_blake3;
        }
        for fp in &seen_fp {
            if bool::from(fp.ct_eq(&unlocked.meta.drive_fingerprint)) {
                return Err(Error::DuplicateCarrier);
            }
        }
        seen_fp.push(unlocked.meta.drive_fingerprint);
        indices.push(unlocked.meta.share_index);
        key_shares.push(unlocked.share);
        chunks.push(unlocked.chunk);
    }

    let k = usize::from(scheme_k.ok_or(Error::NotEnoughShares { need: 2, have: 0 })?);
    let n = usize::from(scheme_n.ok_or(Error::NotEnoughShares { need: 2, have: 0 })?);
    if paths.len() < k {
        return Err(Error::NotEnoughShares {
            need: k,
            have: paths.len(),
        });
    }

    let session = combine_session_key(&key_shares)?;
    let aead_key = AeadKey::new(*session.as_bytes());

    let mut readers: Vec<Cursor<Vec<u8>>> = chunks.into_iter().map(Cursor::new).collect();
    let mut ciphertext = Vec::new();
    join_stripes(&mut readers, &indices, &mut ciphertext, k, n)?;

    let mut plaintext = Vec::new();
    splitdisk_core::decrypt_stream(&aead_key, Cursor::new(&ciphertext), &mut plaintext)?;
    ciphertext.zeroize();

    let out_hash = *blake3::hash(&plaintext).as_bytes();
    if !bool::from(out_hash.ct_eq(&source_blake3)) {
        plaintext.zeroize();
        return Err(Error::Integrity);
    }
    Ok(plaintext)
}

/// Unlock a single file carrier with a PIN.
pub fn unlock_carrier(path: &Path, pin: &str) -> Result<UnlockedCarrier> {
    validate_carrier_path(path)?;
    let mut f = File::open(path)?;
    let (hdr, sections) = read_drive_sections(&mut f)?;
    let pin_rec = parse_pin_hash(&sections.pin_hash)?;
    let argon_out = verify_pin(pin, &pin_rec).map_err(|_| Error::AuthFailed)?;
    let k_pin = derive_k_pin(&argon_out);

    let wrap = parse_key_wrap(&sections.share_wrap)?;
    let share_pt = unwrap_key_share(&k_pin, &wrap, &hdr.drive_uuid)?;
    let meta_pt = splitdisk_core::open_meta(&k_pin, &hdr.drive_uuid, &sections.meta_sealed)?;
    let meta = parse_meta(&meta_pt)?;
    let chunk_hash = *blake3::hash(&sections.chunk).as_bytes();
    if chunk_hash != meta.chunk_blake3 {
        return Err(Error::Integrity);
    }

    Ok(UnlockedCarrier {
        source_blake3: hdr.source_blake3,
        meta,
        share: KeyShare(share_pt),
        chunk: sections.chunk,
    })
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Convenience enroll with OS RNG.
pub fn enroll_os_rng(params: &EnrollParams) -> Result<EnrollResult> {
    let mut rng = OsRng;
    enroll(params, &mut rng)
}
