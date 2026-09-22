#![forbid(unsafe_code)]
//! `splitdisk-image` CLI — produce a base USB image (SPEC §10.7).
//!
//! Phase 3 uses synthetic GRUB/kernel/CCID placeholders. Output is suitable
//! for layout inspection and reproducibility tests, not for actual boot.

use clap::Parser;
use splitdisk_core::DRIVE_UUID_LEN;
use splitdisk_image::{build_base_image, size::parse_size, ImageRequest};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "splitdisk-image",
    about = "Build a SplitDisk base USB image (GPT + FAT32 ESP + ext4). Phase 3: synthetic boot blobs only."
)]
struct Args {
    /// Output image path.
    #[arg(long)]
    output: PathBuf,

    /// Image size (e.g. 512MiB, 1GiB, or byte count).
    #[arg(long)]
    size: String,

    /// Path to `splitdisk-assemble` binary to embed.
    #[arg(long)]
    assemble_bin: Option<PathBuf>,

    /// Fixed drive UUID as 32 hex chars (tests / reproducibility). If omitted,
    /// a random UUID is generated via getrandom.
    #[arg(long)]
    drive_uuid: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("splitdisk-image: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let size = parse_size(&args.size)?;
    let assemble_bin = resolve_assemble_bin(args.assemble_bin)?;
    let drive_uuid = match args.drive_uuid {
        Some(hex) => parse_drive_uuid(&hex)?,
        None => {
            let mut u = [0u8; DRIVE_UUID_LEN];
            getrandom_fill(&mut u)?;
            u
        }
    };

    let req = ImageRequest {
        output: args.output,
        size,
        drive_uuid,
        assemble_bin,
    };
    build_base_image(&req)?;
    Ok(())
}

fn resolve_assemble_bin(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("SPLITDISK_ASSEMBLE_BIN") {
        return Ok(PathBuf::from(p));
    }
    Err("assemble binary required: pass --assemble-bin or set SPLITDISK_ASSEMBLE_BIN".into())
}

fn parse_drive_uuid(hex: &str) -> Result<[u8; DRIVE_UUID_LEN], Box<dyn std::error::Error>> {
    let hex = hex.trim();
    if hex.len() != DRIVE_UUID_LEN * 2 {
        return Err(format!("drive_uuid must be {} hex characters", DRIVE_UUID_LEN * 2).into());
    }
    let mut out = [0u8; DRIVE_UUID_LEN];
    for i in 0..DRIVE_UUID_LEN {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("drive_uuid hex: {e}"))?;
    }
    Ok(out)
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    // OS CSPRNG only (AGENTS Rule 5). Never use /dev paths from this binary
    // for Phase 1–3 safety rules; getrandom uses the platform CSPRNG API.
    getrandom::getrandom(buf).map_err(|e| format!("getrandom: {e}"))?;
    Ok(())
}
