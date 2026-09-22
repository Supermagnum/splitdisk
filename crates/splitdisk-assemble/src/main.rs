#![forbid(unsafe_code)]
//! `splitdisk-assemble` CLI — Phase 2 file-backed assembly.
//!
//! Pause / cool-down test hooks are **not** CLI flags. Use the `test-hooks`
//! feature and library APIs from tests only.

use clap::Parser;
use splitdisk_assemble::{assemble, AssembleParams};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "splitdisk-assemble",
    about = "SplitDisk assembly (Phase 2 file carriers)"
)]
struct Args {
    /// Comma-separated carrier file paths (at least k).
    #[arg(long)]
    carriers: String,

    /// Comma-separated PINs matching carriers.
    #[arg(long)]
    pins: String,

    /// Output plaintext path.
    #[arg(long)]
    output: PathBuf,

    /// Checkpoint / journal directory.
    #[arg(long)]
    checkpoint_dir: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let carriers: Vec<PathBuf> = args
        .carriers
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

    let params = AssembleParams {
        carriers,
        pins,
        output: args.output,
        checkpoint_dir: args.checkpoint_dir,
        mock_cooldown: false,
        #[cfg(feature = "test-hooks")]
        test_pause_after_bytes: None,
    };

    match assemble(&params) {
        Ok(hash) => {
            eprintln!("Assembly OK: blake3={}", hex32(&hash));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Assembly failed: {e}");
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
            !help.contains("test-pause")
                && !help.contains("test_pause")
                && !help.contains("test-argon2")
                && !help.contains("test_argon2")
                && !help.contains("mock-cooldown")
                && !help.contains("mock_cooldown"),
            "release CLI must not expose test hooks: {help}"
        );
    }
}
