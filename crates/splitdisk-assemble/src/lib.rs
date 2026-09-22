#![forbid(unsafe_code)]
//! Assembly: unlock carriers, reconstruct, decrypt with checkpoint journal.

mod journal;
pub mod pcscd;

use journal::{JournalState, JOURNAL_NAME};
use splitdisk_auth::{
    derive_k_pin, verify_pin, AttemptLimiter, AttemptPolicy, Clock, InstantClock, MockClock,
};
use splitdisk_core::aead::{decrypt_stream_with_progress, AeadKey};
use splitdisk_core::error::{Error, Result};
use splitdisk_core::format::{
    parse_key_wrap, parse_meta, parse_pin_hash, read_drive_sections, unwrap_key_share,
};
use splitdisk_core::path::validate_carrier_path;
use splitdisk_core::rs::join_stripes;
use splitdisk_core::sss::{combine_session_key, KeyShare};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Inputs for a non-interactive assembly run.
#[derive(Debug, Clone)]
pub struct AssembleParams {
    pub carriers: Vec<PathBuf>,
    pub pins: Vec<String>,
    pub output: PathBuf,
    pub checkpoint_dir: PathBuf,
    /// Use mock clock (no real sleep) for attempt cool-down in tests.
    pub mock_cooldown: bool,
    /// Pause after N plaintext bytes — only with `test-hooks` (SIGKILL tests).
    #[cfg(feature = "test-hooks")]
    pub test_pause_after_bytes: Option<u64>,
}

/// Assemble plaintext to `params.output`, resuming from journal when present.
pub fn assemble(params: &AssembleParams) -> Result<[u8; 32]> {
    if params.carriers.len() != params.pins.len() {
        return Err(Error::InvalidParameter("carriers/pins length mismatch"));
    }
    if params.carriers.is_empty() {
        return Err(Error::NotEnoughShares { need: 2, have: 0 });
    }
    for p in &params.carriers {
        validate_carrier_path(p)?;
    }
    validate_carrier_path(&params.output)?;
    fs::create_dir_all(&params.checkpoint_dir)?;

    let journal_path = params.checkpoint_dir.join(JOURNAL_NAME);

    let mut unlocked = Vec::new();
    let mut seen_fp: Vec<[u8; 32]> = Vec::new();
    for (path, pin) in params.carriers.iter().zip(params.pins.iter()) {
        let u = unlock_with_attempts(path, pin, params.mock_cooldown)?;
        for fp in &seen_fp {
            if bool::from(fp.ct_eq(&u.fingerprint)) {
                return Err(Error::DuplicateCarrier);
            }
        }
        seen_fp.push(u.fingerprint);
        unlocked.push(u);
    }

    let k = unlocked[0].k as usize;
    let n = unlocked[0].n as usize;
    if unlocked.len() < k {
        return Err(Error::NotEnoughShares {
            need: k,
            have: unlocked.len(),
        });
    }
    for u in &unlocked {
        if u.k as usize != k || u.n as usize != n {
            return Err(Error::Format("inconsistent k/n"));
        }
    }

    let source_blake3 = unlocked[0].source_blake3;
    let indices: Vec<u8> = unlocked.iter().map(|u| u.share_index).collect();
    let shares: Vec<KeyShare> = unlocked
        .iter()
        .map(|u| KeyShare(u.share_bytes.clone()))
        .collect();
    let session = combine_session_key(&shares)?;
    let aead_key = AeadKey::new(*session.as_bytes());

    let ct_tmp = params.output.with_extension("splitdisk.ct.assemble");
    {
        let mut readers: Vec<Cursor<Vec<u8>>> = unlocked
            .iter()
            .map(|u| Cursor::new(u.chunk.clone()))
            .collect();
        let mut ct_out = BufWriter::new(File::create(&ct_tmp)?);
        join_stripes(&mut readers, &indices, &mut ct_out, k, n)?;
        ct_out.flush()?;
    }
    for u in &mut unlocked {
        u.share_bytes.zeroize();
        u.chunk.zeroize();
    }

    let (skip_segments, prior_bytes) =
        prepare_output_and_journal(&journal_path, &params.output, source_blake3)?;

    assemble_decrypt_journaled(
        &aead_key,
        &ct_tmp,
        &params.output,
        &journal_path,
        source_blake3,
        skip_segments,
        prior_bytes,
        #[cfg(feature = "test-hooks")]
        params.test_pause_after_bytes,
        #[cfg(not(feature = "test-hooks"))]
        None,
    )?;

    let _ = fs::remove_file(&ct_tmp);

    let out_hash = hash_file(&params.output)?;
    if !bool::from(out_hash.ct_eq(&source_blake3)) {
        let _ = fs::remove_file(&params.output);
        let _ = fs::remove_file(&journal_path);
        return Err(Error::Integrity);
    }

    let mut done = JournalState::new(source_blake3);
    done.complete = true;
    done.bytes_committed = fs::metadata(&params.output)?.len();
    done.segments_committed = skip_segments; // overwritten below after decrypt knows count
    done.running_blake3 = out_hash;
    // Reload last journal for segment count if present.
    if let Ok(st) = JournalState::load(&journal_path) {
        done.segments_committed = st.segments_committed;
        done.last_segment_blake3 = st.last_segment_blake3;
    }
    done.complete = true;
    done.store(&journal_path)?;

    Ok(out_hash)
}

fn prepare_output_and_journal(
    journal_path: &Path,
    output: &Path,
    source_blake3: [u8; 32],
) -> Result<(u64, u64)> {
    if journal_path.exists() {
        let st = JournalState::load(journal_path)?;
        if st.source_blake3 != source_blake3 {
            return Err(Error::Journal("journal source hash mismatch"));
        }
        if st.complete {
            return Ok((u64::MAX, st.bytes_committed)); // signal complete via special skip
        }
        if output.exists() {
            let meta = fs::metadata(output)?;
            if meta.len() != st.bytes_committed {
                return Err(Error::Journal("output length does not match journal"));
            }
            let prefix_hash = hash_file_prefix(output, st.bytes_committed)?;
            if prefix_hash != st.running_blake3 {
                return Err(Error::Journal("committed plaintext hash mismatch"));
            }
        } else if st.bytes_committed != 0 {
            return Err(Error::Journal("missing output for non-empty journal"));
        }
        return Ok((st.segments_committed, st.bytes_committed));
    }

    File::create(output)?;
    JournalState::new(source_blake3).store(journal_path)?;
    Ok((0, 0))
}

#[allow(clippy::too_many_arguments)]
fn assemble_decrypt_journaled(
    key: &AeadKey,
    ct_path: &Path,
    output: &Path,
    journal_path: &Path,
    source_blake3: [u8; 32],
    skip_segments: u64,
    prior_bytes: u64,
    pause_after: Option<u64>,
) -> Result<()> {
    if skip_segments == u64::MAX {
        // Already complete.
        return Ok(());
    }

    let ct_in = File::open(ct_path)?;
    let mut out = OpenOptions::new().write(true).read(true).open(output)?;
    out.set_len(prior_bytes)?;
    out.seek(SeekFrom::Start(prior_bytes))?;

    let output_path = output.to_path_buf();
    let journal_path_buf = journal_path.to_path_buf();

    decrypt_stream_with_progress(
        key,
        BufReader::new(ct_in),
        &mut out,
        skip_segments,
        |prog| {
            if prog.segments_done <= skip_segments {
                return Ok(());
            }
            // Sync via path to avoid borrowing `out` inside this callback.
            {
                let f = OpenOptions::new().write(true).open(&output_path)?;
                f.sync_all().map_err(Error::Io)?;
            }
            let absolute_bytes = fs::metadata(&output_path)?.len();
            let running_blake3 = hash_file_prefix(&output_path, absolute_bytes)?;

            let mut st = JournalState::new(source_blake3);
            st.segments_committed = prog.segments_done;
            st.bytes_committed = absolute_bytes;
            st.running_blake3 = running_blake3;
            st.last_segment_blake3 = prog.segment_plaintext_blake3;
            st.store(&journal_path_buf)?;

            if let Some(pause_at) = pause_after {
                #[cfg(feature = "test-hooks")]
                {
                    if absolute_bytes >= pause_at && !prog.is_final {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                #[cfg(not(feature = "test-hooks"))]
                {
                    let _ = (pause_at, prog.is_final);
                }
            }
            Ok(())
        },
    )?;
    out.sync_all()?;
    Ok(())
}

struct Unlocked {
    source_blake3: [u8; 32],
    share_index: u8,
    k: u8,
    n: u8,
    fingerprint: [u8; 32],
    share_bytes: Vec<u8>,
    chunk: Vec<u8>,
}

fn unlock_with_attempts(path: &Path, pin: &str, mock_cooldown: bool) -> Result<Unlocked> {
    if mock_cooldown {
        let clock = MockClock::new();
        let policy = AttemptPolicy::new(5, Duration::from_millis(1))
            .map_err(|_| Error::InvalidParameter("attempt policy"))?;
        let mut lim = AttemptLimiter::new(policy, clock);
        unlock_limited(path, pin, &mut lim)
    } else {
        let clock = InstantClock;
        let policy = AttemptPolicy::default();
        let mut lim = AttemptLimiter::new(policy, clock);
        unlock_limited(path, pin, &mut lim)
    }
}

fn unlock_limited<C: Clock>(
    path: &Path,
    pin: &str,
    lim: &mut AttemptLimiter<C>,
) -> Result<Unlocked> {
    lim.before_attempt()?;
    match unlock_one(path, pin) {
        Ok(u) => Ok(u),
        Err(Error::AuthFailed) => {
            lim.record_failure();
            Err(Error::AuthFailed)
        }
        Err(e) => Err(e),
    }
}

fn unlock_one(path: &Path, pin: &str) -> Result<Unlocked> {
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

    Ok(Unlocked {
        source_blake3: hdr.source_blake3,
        share_index: meta.share_index,
        k: meta.k,
        n: meta.n,
        fingerprint: meta.drive_fingerprint,
        share_bytes: share_pt,
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

fn hash_file_prefix(path: &Path, len: u64) -> Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    if len == 0 {
        return Ok(*h.finalize().as_bytes());
    }
    let mut f = File::open(path)?;
    let mut left = len;
    let mut buf = [0u8; 64 * 1024];
    while left > 0 {
        let n = std::cmp::min(left as usize, buf.len());
        f.read_exact(&mut buf[..n])?;
        h.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(*h.finalize().as_bytes())
}
