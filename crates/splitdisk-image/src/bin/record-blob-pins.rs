//! Print BLAKE3 digests of cached Phase 4 vendor blobs (no pin assert).
//! Used once after `scripts/build-vendor-blobs.sh` to refresh PIN_* constants.

use splitdisk_image::vendor::{
    digest_cached_blob, BLOB_CCID_IFD, BLOB_GRUB_EFI, BLOB_KERNEL, PIN_CCID_IFD, PIN_GRUB_EFI,
    PIN_KERNEL,
};

fn main() {
    let grub = digest_cached_blob(BLOB_GRUB_EFI).expect("grub digest");
    let kernel = digest_cached_blob(BLOB_KERNEL).expect("kernel digest");
    let ccid = digest_cached_blob(BLOB_CCID_IFD).expect("ccid digest");
    println!("PIN_GRUB_EFI={grub}");
    println!("PIN_KERNEL={kernel}");
    println!("PIN_CCID_IFD={ccid}");
    println!("# checked-in now: grub={PIN_GRUB_EFI} kernel={PIN_KERNEL} ccid={PIN_CCID_IFD}");
}
