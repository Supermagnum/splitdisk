#![forbid(unsafe_code)]
//! `splitdisk-assemble` CLI — file-backed assembly or initramfs `--agent` mode.

use clap::Parser;
use splitdisk_assemble::{assemble, pcscd, AssembleParams};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "splitdisk-assemble",
    about = "SplitDisk assembly agent (file carriers or initramfs --agent)"
)]
struct Args {
    /// Initramfs agent mode: start pcscd, emit serial markers, idle.
    /// Used by `/init` after mounts (SPEC §10.3). No Galdralag / TUI yet.
    #[arg(long)]
    agent: bool,

    /// Comma-separated carrier file paths (at least k).
    #[arg(long, required_unless_present = "agent")]
    carriers: Option<String>,

    /// Comma-separated PINs matching carriers.
    #[arg(long, required_unless_present = "agent")]
    pins: Option<String>,

    /// Output plaintext path.
    #[arg(long, required_unless_present = "agent")]
    output: Option<PathBuf>,

    /// Checkpoint / journal directory.
    #[arg(long, required_unless_present = "agent")]
    checkpoint_dir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.agent {
        return run_agent();
    }

    let carriers: Vec<PathBuf> = args
        .carriers
        .as_ref()
        .unwrap()
        .split(',')
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    let pins: Vec<String> = args
        .pins
        .as_ref()
        .unwrap()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let params = AssembleParams {
        carriers,
        pins,
        output: args.output.unwrap(),
        checkpoint_dir: args.checkpoint_dir.unwrap(),
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

fn run_agent() -> ExitCode {
    // Greppable proof that /init actually exec'd this binary (not the Phase 5 stub).
    eprintln!("SPLITDISK_ASSEMBLE_STARTED");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    match pcscd::start_pcscd() {
        Ok(_child) => {
            // Keep agent (and pcscd child) alive for QEMU observation.
            // Multi-drive PIN/TUI reconstruction is deferred (Phase 7+).
            eprintln!("SPLITDISK_AGENT_IDLE");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        Err(_) => {
            // Stay up so serial logs remain readable; do not kernel-panic.
            eprintln!("SPLITDISK_AGENT_IDLE_WITHOUT_PCSCD");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
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
