//! Vendored boot blobs for Phase 4/5 (real GRUB / kernel / CCID builds).
//!
//! Artifacts are produced offline by `scripts/build-vendor-blobs.sh` from the
//! human-verified trees under `vendor/{grub,linux,ccid,gnulib}/` (see
//! `docs/VENDORING.md`). BLAKE3 pins below catch accidental swaps. The `/init`
//! path uses a static stub that prints `SPLITDISK_INIT_REACHED` (Phase 5);
//! mount/exec init per SPEC §10.3 remains later work.

use crate::error::{Error, Result};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Role id for the GRUB EFI standalone image (`/EFI/BOOT/BOOTX64.EFI`).
pub const BLOB_GRUB_EFI: &str = "grub_efi";

/// Role id for the kernel bzImage (`/boot/vmlinuz`).
pub const BLOB_KERNEL: &str = "kernel_bzimage";

/// Role id for the CCID IFD driver (initramfs `usr/lib/pcsc/drivers/ifd-ccid.so`).
pub const BLOB_CCID_IFD: &str = "ccid_ifd_ccid_so";

/// Pinned commits (must match `docs/VENDORING.md` / `git rev-parse HEAD`).
pub const COMMIT_GRUB: &str = "d38d6a1a9b79427848976f53d474392cd29c2a71";
pub const COMMIT_LINUX: &str = "e2acc2211022246c77740d5df08265cc27eedcc5";
pub const COMMIT_CCID: &str = "c37cf6cb42279ce9648ff7314180c866d68f9e0d";

/// Pinned BLAKE3 hex digests (lowercase) of the built artifacts.
///
/// Regenerated when build metadata or Dockerfile toolchain pins change.
/// Asserted whenever a blob is loaded (SPEC intent for accidental swap detection).
///
/// Reproducibility (same `splitdisk-test:phase4` image / pinned apt toolchains
/// only — not a general cross-host guarantee; see OPEN-QUESTIONS (j)):
/// - **Kernel:** byte-identical across two cold `O=` builds when
///   `KBUILD_BUILD_USER/HOST/TIMESTAMP` and per-tree `SOURCE_DATE_EPOCH` are set
///   (author date of the vendored commit). Enforced via
///   `scripts/verify-kernel-repro.sh`.
/// - **CCID:** byte-identical when built from canonical `/tmp/splitdisk-ccid-src`
///   with Meson `-Dc_args=-ffile-prefix-map…` and `-Dc_link_args=-Wl,--build-id=none`
///   (avoids embedding bind-mount names like `/src` vs `/work` via `__FILE__`).
/// - **GRUB:** still may vary between cold rebuilds; pin catches accidental swaps
///   when the cache matches the recorded digest.
pub const PIN_GRUB_EFI: &str = "ff42b845dc8d04ef7d4dab0662051d285645e0e18939e47aae0ff81830d7029e";
/// Confirmed byte-reproducible in the Phase 4 Docker image (see pin block above).
pub const PIN_KERNEL: &str = "84fd57508902cf83c8f80ca4293a004106ed60ef579310de11a78bbd35f1812d";
/// Confirmed byte-reproducible with canonical CCID build paths (see pin block above).
pub const PIN_CCID_IFD: &str = "787e4af3ae101f71c4d7acbc375c05c76e374e4afc05979c0b98ab7522587d8b";

/// Expected `Linux version …` UTS string fragment when built with fixed Kbuild metadata.
pub const KERNEL_UTS_VERSION_SNIPPET: &str =
    "6.12.111 (splitdisk@splitdisk) #1 SMP PREEMPT_DYNAMIC Mon Sep 21 13:02:51 UTC 2026";

/// Trait for vendored blobs used by the image builder.
pub trait VendoredBlob {
    /// Stable role name (e.g. `grub_efi`).
    fn role(&self) -> &str;
    /// Raw bytes.
    fn bytes(&self) -> &[u8];
    /// BLAKE3 hex digest of [`Self::bytes`].
    fn blake3_hex(&self) -> String;
}

/// Real build output loaded from the offline blob cache.
#[derive(Debug, Clone)]
pub struct BuiltBlob {
    role: String,
    data: Vec<u8>,
    blake3_hex: String,
}

impl BuiltBlob {
    /// Load a known role from `$SPLITDISK_BLOB_CACHE` (or
    /// `$CARGO_TARGET_DIR/vendor-blobs`), assert the BLAKE3 pin.
    pub fn load(role: &str) -> Result<Self> {
        let (rel, pin, commit) = match role {
            BLOB_GRUB_EFI => (
                format!("grub/{COMMIT_GRUB}/BOOTX64.EFI"),
                PIN_GRUB_EFI,
                COMMIT_GRUB,
            ),
            BLOB_KERNEL => (
                format!("linux/{COMMIT_LINUX}/bzImage"),
                PIN_KERNEL,
                COMMIT_LINUX,
            ),
            BLOB_CCID_IFD => (
                format!("ccid/{COMMIT_CCID}/ifd-ccid.so"),
                PIN_CCID_IFD,
                COMMIT_CCID,
            ),
            other => {
                return Err(Error::InvalidParameter(format!(
                    "unknown vendored blob role: {other}"
                )));
            }
        };
        let path = blob_cache_dir()?.join(&rel);
        let data = std::fs::read(&path).map_err(|e| {
            Error::Io(format!(
                "read vendored blob {role} (commit {commit}) at {}: {e}; \
                 run scripts/build-vendor-blobs.sh offline first",
                path.display()
            ))
        })?;
        if data.is_empty() {
            return Err(Error::InvalidParameter(format!(
                "vendored blob {role} is empty at {}",
                path.display()
            )));
        }
        // Reject leftover synthetic placeholders if a cache was mis-seeded.
        if data.starts_with(b"SPLITDISK-SYNTHETIC-PLACEHOLDER") {
            return Err(Error::InvalidParameter(format!(
                "vendored blob {role} still looks synthetic at {}",
                path.display()
            )));
        }
        let blake3_hex = hex_blake3(&data);
        if pin == "PENDING_PHASE4_BUILD" {
            return Err(Error::BlobPinMismatch {
                role: role.to_string(),
                expected: format!(
                    "PENDING_PHASE4_BUILD (rebuild recorded digest {blake3_hex}; \
                     update PIN_* in vendor.rs)"
                ),
                got: blake3_hex,
            });
        }
        if blake3_hex != pin {
            return Err(Error::BlobPinMismatch {
                role: role.to_string(),
                expected: pin.to_string(),
                got: blake3_hex,
            });
        }
        Ok(Self {
            role: role.to_string(),
            data,
            blake3_hex,
        })
    }
}

impl VendoredBlob for BuiltBlob {
    fn role(&self) -> &str {
        &self.role
    }

    fn bytes(&self) -> &[u8] {
        &self.data
    }

    fn blake3_hex(&self) -> String {
        self.blake3_hex.clone()
    }
}

fn blob_cache_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("SPLITDISK_BLOB_CACHE") {
        return Ok(PathBuf::from(p));
    }
    if let Ok(t) = std::env::var("CARGO_TARGET_DIR") {
        return Ok(PathBuf::from(t).join("vendor-blobs"));
    }
    Ok(PathBuf::from("target/vendor-blobs"))
}

pub fn hex_blake3(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    let mut s = String::with_capacity(64);
    for byte in hash.as_bytes() {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Marker printed by Phase 5 nostdlib stub (legacy). Phase 6 `/init` prints
/// `SPLITDISK_INIT_STARTING` / `SPLITDISK_INIT_MOUNTS_OK` then execs assemble.
pub const INIT_REACHED_MARKER: &str = "SPLITDISK_INIT_REACHED";

/// Load CCID `Info.plist` generated beside the IFD `.so` (Phase 6 / item (k)).
pub fn load_ccid_info_plist() -> Result<Vec<u8>> {
    let path = blob_cache_dir()?.join(format!("ccid/{COMMIT_CCID}/Info.plist"));
    std::fs::read(&path).map_err(|e| {
        Error::Io(format!(
            "read CCID Info.plist at {}: {e}; rebuild with scripts/build-vendor-blobs.sh",
            path.display()
        ))
    })
}

/// Marker used only by the synthetic `/init` stub (not GRUB/kernel/CCID).
pub const PLACEHOLDER_BANNER: &[u8] =
    b"SPLITDISK-SYNTHETIC-PLACEHOLDER-v1\nNOT A REAL BOOTABLE COMPONENT\n";

/// Default `/init` for image builds: prefer the Docker-baked static stub
/// (`/usr/local/share/splitdisk/init-stub` or `$SPLITDISK_INIT_STUB`), else the
/// Phase 3 synthetic ELF (unit tests without the container binary).
pub fn default_init_stub() -> Vec<u8> {
    if let Ok(p) = std::env::var("SPLITDISK_INIT_STUB") {
        if let Ok(b) = std::fs::read(&p) {
            if !b.is_empty() {
                return b;
            }
        }
    }
    let baked = Path::new("/usr/local/share/splitdisk/init-stub");
    if baked.is_file() {
        if let Ok(b) = std::fs::read(baked) {
            if !b.is_empty() {
                return b;
            }
        }
    }
    synthetic_init_stub()
}

/// Minimal x86_64 ELF64 that issues `exit_group(0)` — unit-test placeholder.
///
/// Prefixed with [`PLACEHOLDER_BANNER`] so it is obviously not a production
/// bootable `/init`. [`default_init_stub`] prefers the Docker-baked nostdlib
/// stub; do not use this exiting stub in QEMU images (exit makes the kernel
/// attempt a real root mount and panic).
pub fn synthetic_init_stub() -> Vec<u8> {
    let mut elf = vec![
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    elf.extend_from_slice(&[
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    elf.extend_from_slice(&[0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05]);
    let mut out = PLACEHOLDER_BANNER.to_vec();
    out.extend_from_slice(b"role=init_stub\n");
    while out.len() < 128 {
        out.push(0x00);
    }
    out.extend_from_slice(&elf);
    out
}

/// Resolve the on-disk path for a role (test / tooling helper).
pub fn blob_path_for_role(role: &str) -> Result<PathBuf> {
    let rel = match role {
        BLOB_GRUB_EFI => format!("grub/{COMMIT_GRUB}/BOOTX64.EFI"),
        BLOB_KERNEL => format!("linux/{COMMIT_LINUX}/bzImage"),
        BLOB_CCID_IFD => format!("ccid/{COMMIT_CCID}/ifd-ccid.so"),
        other => {
            return Err(Error::InvalidParameter(format!(
                "unknown vendored blob role: {other}"
            )));
        }
    };
    Ok(blob_cache_dir()?.join(rel))
}

/// Compute BLAKE3 of an existing cache file without pin-checking (pin update helper).
pub fn digest_cached_blob(role: &str) -> Result<String> {
    let path = blob_path_for_role(role)?;
    let data = std::fs::read(&path).map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
    Ok(hex_blake3(&data))
}

pub fn cache_dir_display() -> Result<String> {
    Ok(blob_cache_dir()?.display().to_string())
}

#[allow(dead_code)]
fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_stub_has_banner_and_elf() {
        let stub = synthetic_init_stub();
        assert!(stub.starts_with(PLACEHOLDER_BANNER));
        assert!(stub.windows(4).any(|w| w == b"\x7fELF"));
    }
}
