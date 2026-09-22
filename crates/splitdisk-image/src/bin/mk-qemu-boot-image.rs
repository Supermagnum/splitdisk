//! Build a Phase 5 QEMU boot-chain test disk (test-serial GRUB + init marker).
//!
//! Not used for production images. Invoked by `scripts/qemu-boot-chain.sh`.

use splitdisk_core::DRIVE_UUID_LEN;
use splitdisk_image::vendor::COMMIT_GRUB;
use splitdisk_image::{build_base_image, ImageRequest};
use std::env;
use std::path::PathBuf;
use std::process;

fn usage() -> ! {
    eprintln!(
        "usage: mk-qemu-boot-image --output PATH --assemble-bin PATH [--size BYTES]\n\
         Optional env: SPLITDISK_BLOB_CACHE, SPLITDISK_INIT_STUB"
    );
    process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let mut output = None;
    let mut assemble = None;
    let mut size: u64 = 64 * 1024 * 1024;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--output" => output = args.next().map(PathBuf::from),
            "--assemble-bin" => assemble = args.next().map(PathBuf::from),
            "--size" => {
                let v = args.next().unwrap_or_else(|| usage());
                size = v.parse().unwrap_or_else(|_| usage());
            }
            _ => usage(),
        }
    }
    let output = output.unwrap_or_else(|| usage());
    let assemble_bin = assemble.unwrap_or_else(|| usage());

    let cache = env::var("SPLITDISK_BLOB_CACHE").unwrap_or_else(|_| {
        env::var("CARGO_TARGET_DIR")
            .map(|t| format!("{t}/vendor-blobs"))
            .unwrap_or_else(|_| "target/vendor-blobs".into())
    });
    let grub_serial = PathBuf::from(&cache)
        .join("grub")
        .join(COMMIT_GRUB)
        .join("BOOTX64-TEST-SERIAL.EFI");
    let grub_efi_override = std::fs::read(&grub_serial).unwrap_or_else(|e| {
        eprintln!(
            "missing test-serial GRUB EFI at {}: {e}\n\
             rebuild with scripts/build-vendor-blobs.sh (produces BOOTX64-TEST-SERIAL.EFI)",
            grub_serial.display()
        );
        process::exit(1);
    });

    let init_stub = std::fs::read(
        std::env::var("SPLITDISK_INIT_STUB")
            .unwrap_or_else(|_| "/usr/local/share/splitdisk/init-stub".into()),
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "missing Phase 5 init stub (set SPLITDISK_INIT_STUB or bake into Docker image): {e}"
        );
        process::exit(1);
    });
    if init_stub.starts_with(b"SPLITDISK-SYNTHETIC") {
        eprintln!("refusing synthetic exiting /init stub for QEMU boot image");
        process::exit(1);
    }

    // Fixed UUID for deterministic QEMU fixtures.
    let drive_uuid: [u8; DRIVE_UUID_LEN] = *b"PHASE5-QEMU-BT01";

    let req = ImageRequest {
        output,
        size,
        drive_uuid,
        assemble_bin,
        test_serial_console: true,
        grub_efi_override: Some(grub_efi_override),
        init_stub_override: Some(init_stub),
    };
    if let Err(e) = build_base_image(&req) {
        eprintln!("mk-qemu-boot-image failed: {e}");
        process::exit(1);
    }
}
