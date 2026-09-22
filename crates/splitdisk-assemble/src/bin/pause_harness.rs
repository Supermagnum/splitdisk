#![forbid(unsafe_code)]
//! Test-only assemble harness (requires `--features test-hooks`).

use splitdisk_assemble::{assemble, AssembleParams};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let carriers_csv = args.next().expect("carriers csv");
    let pins_csv = args.next().expect("pins csv");
    let output = PathBuf::from(args.next().expect("output"));
    let checkpoint_dir = PathBuf::from(args.next().expect("checkpoint_dir"));
    let pause_after: u64 = args
        .next()
        .expect("pause_after_bytes")
        .parse()
        .expect("u64");

    let carriers: Vec<PathBuf> = carriers_csv
        .split(',')
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    let pins: Vec<String> = pins_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let params = AssembleParams {
        carriers,
        pins,
        output,
        checkpoint_dir,
        mock_cooldown: true,
        test_pause_after_bytes: Some(pause_after),
    };

    match assemble(&params) {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
