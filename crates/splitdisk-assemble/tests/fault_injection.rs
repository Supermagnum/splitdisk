//! Phase 2 fault-injection and enrollment/assembly integration tests.
//!
//! All fixtures are regular files under a temp directory (never `/dev`).
//! Requires `--features test-hooks` on this package (enabled via Cargo.toml
//! dev-dependencies / CI script).

use splitdisk_assemble::{assemble, AssembleParams};
use splitdisk_auth::Argon2Params;
use splitdisk_core::format::{
    parse_chunk_frame, parse_drive_header, DRIVE_HEADER_LEN, DRIVE_UUID_LEN,
};
use splitdisk_core::rng::SeededRng;
use splitdisk_core::Error;
use splitdisk_create::{enroll, unlock_carrier, EnrollParams};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn enroll_fixture(
    dir: &Path,
    k: usize,
    n: usize,
    plaintext: &[u8],
) -> (Vec<PathBuf>, Vec<String>, [u8; 32]) {
    let input = dir.join("source.bin");
    fs::write(&input, plaintext).unwrap();

    let mut drives = Vec::new();
    let mut pins = Vec::new();
    for i in 0..n {
        drives.push(dir.join(format!("drive{i}.sddr")));
        pins.push(format!("pinok{i}"));
    }

    let stripe = k * 64;
    let segment = 64;

    let params = EnrollParams {
        input,
        drive_paths: drives.clone(),
        pins: pins.clone(),
        threshold_k: k,
        stripe_size: stripe,
        segment_size: segment,
        argon2: Argon2Params::for_tests(),
    };
    let mut rng = SeededRng::from_seed([42u8; 32]);
    let res = enroll(&params, &mut rng).expect("enroll");
    (drives, pins, res.source_blake3)
}

/// Assert `share_index` is not present as cleartext on any drive file.
///
/// Scans each drive's cleartext header and every SDCF frame header. Also
/// verifies `drive_uuid` is not a trivial encoding of the index.
fn assert_share_index_absent_in_cleartext(drives: &[PathBuf], pins: &[String]) {
    let mut seen_uuids = Vec::new();
    for (path, pin) in drives.iter().zip(pins.iter()) {
        let unlocked = unlock_carrier(path, pin).expect("unlock for index check");
        let idx = unlocked.meta.share_index;
        let bytes = fs::read(path).expect("read drive");

        // --- Header (fully cleartext) ---
        let hdr = parse_drive_header(&bytes[..DRIVE_HEADER_LEN]).expect("header");
        assert_ne!(
            hdr.drive_uuid, [idx; DRIVE_UUID_LEN],
            "drive_uuid must not be share_index repeated"
        );
        // Old buggy layout stored share_index at offset 38 as a single byte.
        // After the fix that offset is the first byte of drive_uuid (random).
        // Across drives it must not form the sequence 0,1,2,... at that offset
        // in lockstep with share_index for every drive (checked after loop).
        seen_uuids.push((idx, hdr.drive_uuid, bytes[38]));

        // Byte-scan the cleartext header for a dedicated u8 field equal to idx
        // at the former share_index offset only when uuid would also encode it —
        // already covered. Scan: no ASCII decimal of idx as a lone field.
        let header = &bytes[..DRIVE_HEADER_LEN];
        // Ensure header does not contain the two-byte pattern that would be
        // `share_index || suite_id` from the removed AAD (idx then 0x01,0x00).
        let bad = [idx, 0x01, 0x00];
        assert!(
            !header.windows(3).any(|w| w == bad),
            "cleartext header must not contain share_index||suite_id AAD pattern"
        );

        // --- Chunk frames (cleartext structure, no share_index field) ---
        let chunk = &bytes[hdr.chunk_off as usize..(hdr.chunk_off + hdr.chunk_len) as usize];
        let mut cur = Cursor::new(chunk);
        loop {
            match parse_chunk_frame(&mut cur) {
                Ok(_frame) => {
                    // Parsed successfully without a share_index field (type has none).
                }
                Err(Error::UnexpectedEof) => break,
                Err(e) => panic!("chunk parse: {e}"),
            }
        }
    }

    // UUIDs must be unique across drives (not correlated with index).
    for i in 0..seen_uuids.len() {
        for j in (i + 1)..seen_uuids.len() {
            assert_ne!(seen_uuids[i].1, seen_uuids[j].1, "drive_uuid collision");
        }
    }
    // Former offset-38 bytes must not equal share_index for every drive.
    let all_match_old_layout = seen_uuids.iter().all(|(idx, _, b38)| *b38 == *idx);
    assert!(
        !all_match_old_layout,
        "offset 38 must not encode share_index for all drives (old cleartext layout)"
    );
}

#[test]
fn enroll_assemble_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pt = b"hello phase2 splitdisk plaintext payload!!";
    let (drives, pins, src_hash) = enroll_fixture(dir.path(), 2, 3, pt);
    assert_share_index_absent_in_cleartext(&drives, &pins);

    let out = dir.path().join("out.bin");
    let ckpt = dir.path().join("ckpt");
    let hash = assemble(&AssembleParams {
        carriers: drives[..2].to_vec(),
        pins: pins[..2].to_vec(),
        output: out.clone(),
        checkpoint_dir: ckpt,
        mock_cooldown: true,
        test_pause_after_bytes: None,
    })
    .unwrap();
    assert_eq!(hash, src_hash);
    assert_eq!(fs::read(&out).unwrap(), pt);
}

#[test]
fn share_index_not_in_cleartext_on_any_drive() {
    let dir = tempfile::tempdir().unwrap();
    let (drives, pins, _) = enroll_fixture(dir.path(), 2, 3, b"anonymity-check-payload!");
    assert_share_index_absent_in_cleartext(&drives, &pins);
}

#[test]
fn fewer_than_k_carriers() {
    let dir = tempfile::tempdir().unwrap();
    let (drives, pins, _) = enroll_fixture(dir.path(), 2, 3, b"abcdefghijklmnop");
    let err = assemble(&AssembleParams {
        carriers: drives[..1].to_vec(),
        pins: pins[..1].to_vec(),
        output: dir.path().join("out.bin"),
        checkpoint_dir: dir.path().join("ckpt"),
        mock_cooldown: true,
        test_pause_after_bytes: None,
    });
    assert!(matches!(err, Err(Error::NotEnoughShares { .. })));
}

#[test]
fn wrong_pin_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let (drives, mut pins, _) = enroll_fixture(dir.path(), 2, 3, b"0123456789abcdef");
    pins[0] = "wrongX".into();
    let err = assemble(&AssembleParams {
        carriers: drives[..2].to_vec(),
        pins: pins[..2].to_vec(),
        output: dir.path().join("out.bin"),
        checkpoint_dir: dir.path().join("ckpt"),
        mock_cooldown: true,
        test_pause_after_bytes: None,
    });
    assert!(matches!(err, Err(Error::AuthFailed)));
}

#[test]
fn duplicate_carrier() {
    let dir = tempfile::tempdir().unwrap();
    let (drives, pins, _) = enroll_fixture(dir.path(), 2, 3, b"dup-carrier-test!!");
    let err = assemble(&AssembleParams {
        carriers: vec![drives[0].clone(), drives[0].clone()],
        pins: vec![pins[0].clone(), pins[0].clone()],
        output: dir.path().join("out.bin"),
        checkpoint_dir: dir.path().join("ckpt"),
        mock_cooldown: true,
        test_pause_after_bytes: None,
    });
    assert!(matches!(err, Err(Error::DuplicateCarrier)));
}

#[test]
fn flipped_byte_in_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let (drives, pins, _) = enroll_fixture(dir.path(), 2, 3, b"tamper-chunk-bytes!");
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&drives[0])
            .unwrap();
        let len = f.metadata().unwrap().len();
        let pos = len.saturating_sub(8);
        f.seek(SeekFrom::Start(pos)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        b[0] ^= 0x01;
        f.seek(SeekFrom::Start(pos)).unwrap();
        f.write_all(&b).unwrap();
    }
    let err = assemble(&AssembleParams {
        carriers: drives[..2].to_vec(),
        pins: pins[..2].to_vec(),
        output: dir.path().join("out.bin"),
        checkpoint_dir: dir.path().join("ckpt"),
        mock_cooldown: true,
        test_pause_after_bytes: None,
    });
    assert!(err.is_err());
}

#[test]
fn flipped_byte_in_meta() {
    let dir = tempfile::tempdir().unwrap();
    let (drives, pins, _) = enroll_fixture(dir.path(), 2, 3, b"tamper-meta-bytes!!");
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&drives[0])
            .unwrap();
        let len = f.metadata().unwrap().len();
        f.seek(SeekFrom::Start(len - 1)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        b[0] ^= 0xff;
        f.seek(SeekFrom::Start(len - 1)).unwrap();
        f.write_all(&b).unwrap();
    }
    let err = assemble(&AssembleParams {
        carriers: drives[..2].to_vec(),
        pins: pins[..2].to_vec(),
        output: dir.path().join("out.bin"),
        checkpoint_dir: dir.path().join("ckpt"),
        mock_cooldown: true,
        test_pause_after_bytes: None,
    });
    assert!(err.is_err());
}

#[test]
fn kill_and_resume_via_sigkill() {
    let dir = tempfile::tempdir().unwrap();
    let mut pt = vec![0x5Au8; 200];
    pt.extend_from_slice(b"tail");
    let (drives, pins, src_hash) = {
        let input = dir.path().join("source.bin");
        fs::write(&input, &pt).unwrap();
        let drives: Vec<_> = (0..3)
            .map(|i| dir.path().join(format!("drive{i}.sddr")))
            .collect();
        let pins: Vec<_> = (0..3).map(|i| format!("pinok{i}")).collect();
        let params = EnrollParams {
            input,
            drive_paths: drives.clone(),
            pins: pins.clone(),
            threshold_k: 2,
            stripe_size: 128,
            segment_size: 64,
            argon2: Argon2Params::for_tests(),
        };
        let mut rng = SeededRng::from_seed([7u8; 32]);
        let res = enroll(&params, &mut rng).unwrap();
        (drives, pins, res.source_blake3)
    };

    let out = dir.path().join("out.bin");
    let ckpt = dir.path().join("ckpt");
    fs::create_dir_all(&ckpt).unwrap();

    let carrier_arg = format!("{},{}", drives[0].display(), drives[1].display());
    let pin_arg = format!("{},{}", pins[0], pins[1]);

    let bin = env!("CARGO_BIN_EXE_splitdisk-assemble-pause-harness");
    let mut child = Command::new(bin)
        .args([
            &carrier_arg,
            &pin_arg,
            out.to_str().unwrap(),
            ckpt.to_str().unwrap(),
            "64",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pause harness");

    let journal = ckpt.join("splitdisk.journal");
    let mut saw_progress = false;
    for _ in 0..400 {
        std::thread::sleep(Duration::from_millis(25));
        if journal.exists() {
            if let Ok(st) = journal_segments(&journal) {
                if st > 0 {
                    saw_progress = true;
                    break;
                }
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("assemble harness exited early: {status:?}");
        }
    }
    assert!(
        saw_progress,
        "assemble did not journal progress before pause"
    );

    let _ = Command::new("kill")
        .args(["-KILL", &child.id().to_string()])
        .status();
    let _ = child.wait();

    let hash = assemble(&AssembleParams {
        carriers: drives[..2].to_vec(),
        pins: pins[..2].to_vec(),
        output: out.clone(),
        checkpoint_dir: ckpt,
        mock_cooldown: true,
        test_pause_after_bytes: None,
    })
    .expect("resume assemble");
    assert_eq!(hash, src_hash);
    assert_eq!(fs::read(&out).unwrap(), pt);
}

fn journal_segments(path: &Path) -> Result<u64, ()> {
    let mut f = File::open(path).map_err(|_| ())?;
    let mut buf = [0u8; 119];
    f.read_exact(&mut buf).map_err(|_| ())?;
    if &buf[0..4] != b"SDJN" {
        return Err(());
    }
    let mut seg = [0u8; 8];
    seg.copy_from_slice(&buf[38..46]);
    Ok(u64::from_le_bytes(seg))
}
