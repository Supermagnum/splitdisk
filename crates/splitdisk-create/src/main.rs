#![forbid(unsafe_code)]
//! `splitdisk-create` CLI — Phase 2 file-backed enrollment.
//!
//! Test-only Argon2 weakening is **not** exposed as a CLI flag. Use the
//! `test-hooks` Cargo feature and `Argon2Params::for_tests()` from Rust tests.

use clap::Parser;
use splitdisk_auth::Argon2Params;
use splitdisk_core::aead::DEFAULT_SEGMENT_SIZE;
use splitdisk_core::rs::DEFAULT_STRIPE_SIZE;
use splitdisk_create::{enroll_os_rng, EnrollParams};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "splitdisk-create",
    about = "SplitDisk enrollment (Phase 2 file carriers)"
)]
struct Args {
    /// Source image / file to enroll.
    #[arg(long)]
    input: PathBuf,

    /// Comma-separated regular-file carrier paths (n drives).
    #[arg(long)]
    drives: String,

    /// Threshold k (2 <= k <= n).
    #[arg(long)]
    threshold: usize,

    /// Comma-separated PINs, one per drive (non-interactive Phase 2 harness).
    #[arg(long)]
    pins: String,

    /// RS stripe size in bytes (must be divisible by k).
    #[arg(long, default_value_t = DEFAULT_STRIPE_SIZE)]
    stripe_size: usize,

    /// AEAD segment size in bytes.
    #[arg(long, default_value_t = DEFAULT_SEGMENT_SIZE)]
    segment_size: usize,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let drives: Vec<PathBuf> = args
        .drives
        .split(',')
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    let pins: Vec<String> = args
        .pins
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let params = EnrollParams {
        input: args.input,
        drive_paths: drives,
        pins,
        threshold_k: args.threshold,
        stripe_size: args.stripe_size,
        segment_size: args.segment_size,
        argon2: Argon2Params::default(),
    };

    match enroll_os_rng(&params) {
        Ok(r) => {
            eprintln!(
                "Enrollment OK: k={} n={} source_blake3={}",
                r.k,
                r.n,
                hex32(&r.source_blake3)
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Enrollment failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod cli_tests {
    use super::Args;
    use clap::CommandFactory;

    #[test]
    fn help_omits_test_hook_flags() {
        let mut cmd = Args::command();
        let mut help = Vec::new();
        cmd.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(
            !help.contains("test-argon2") && !help.contains("test_argon2"),
            "release CLI must not expose --test-argon2: {help}"
        );
        assert!(
            !help.contains("test-pause") && !help.contains("test_pause"),
            "create CLI must not expose pause hooks: {help}"
        );
    }
}
