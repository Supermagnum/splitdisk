#![forbid(unsafe_code)]
//! SplitDisk boot image builder (Phase 4).
//!
//! Assembles a GPT + FAT32 ESP + ext4 system partition image using **real**
//! GRUB EFI / Linux bzImage / CCID `.so` blobs built offline from
//! `vendor/{grub,linux,ccid,gnulib}/` (see `docs/VENDORING.md`).

pub mod error;
pub mod ext4_mke2fs;
pub mod fat_esp;
pub mod gpt_layout;
pub mod initramfs;
pub mod size;
pub mod vendor;

use crate::error::{Error, Result};
use crate::vendor::{BuiltBlob, VendoredBlob, BLOB_CCID_IFD, BLOB_GRUB_EFI, BLOB_KERNEL};
use splitdisk_core::DRIVE_UUID_LEN;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Default ESP size when the image is large enough (SPEC §6: ~256 MiB).
pub const ESP_SIZE_DEFAULT: u64 = 256 * 1024 * 1024;

/// Minimum image size accepted by the CLI (covers GPT + small ESP + system).
pub const MIN_IMAGE_SIZE: u64 = 64 * 1024 * 1024;

/// First usable LBA alignment (1 MiB).
pub const ALIGN_LBA: u64 = 2048;

/// Sector size used for GPT and partition math.
pub const SECTOR_SIZE: u64 = 512;

/// Inputs for a base USB image (no share data; SPEC §10.7).
#[derive(Debug, Clone)]
pub struct ImageRequest {
    pub output: PathBuf,
    pub size: u64,
    /// Fixed or random 16-byte drive UUID (Phase 2 SDDR / GPT GUID seed).
    pub drive_uuid: [u8; DRIVE_UUID_LEN],
    /// Path to a built `splitdisk-assemble` binary (embedded in initramfs + ext4).
    pub assemble_bin: PathBuf,
}

/// Partition byte ranges within the image file (absolute offsets).
#[derive(Debug, Clone, Copy)]
pub struct PartitionLayout {
    pub esp_offset: u64,
    pub esp_size: u64,
    pub system_offset: u64,
    pub system_size: u64,
}

/// Compute ESP / system sizes for a given image length.
pub fn plan_partitions(image_size: u64) -> Result<PartitionLayout> {
    if image_size < MIN_IMAGE_SIZE {
        return Err(Error::InvalidParameter(format!(
            "image size {image_size} is below minimum {MIN_IMAGE_SIZE}"
        )));
    }
    let esp_size = if image_size >= 2 * ESP_SIZE_DEFAULT {
        ESP_SIZE_DEFAULT
    } else {
        // Small fixtures: keep ESP at most ~half the image minus GPT overhead.
        let half = image_size / 2;
        half.clamp(8 * 1024 * 1024, ESP_SIZE_DEFAULT)
            .min(image_size.saturating_sub(16 * 1024 * 1024))
    };
    // Align ESP size down to 1 MiB.
    let esp_size = (esp_size / (ALIGN_LBA * SECTOR_SIZE)) * (ALIGN_LBA * SECTOR_SIZE);
    if esp_size < 8 * 1024 * 1024 {
        return Err(Error::InvalidParameter(
            "computed ESP too small for FAT32 content".into(),
        ));
    }

    let esp_offset = ALIGN_LBA * SECTOR_SIZE;
    let system_offset = esp_offset + esp_size;
    // Reserve last 33 LBAs for GPT backup (header + entries), plus alignment slack.
    let backup_reserve = 34 * SECTOR_SIZE;
    if system_offset + backup_reserve >= image_size {
        return Err(Error::InvalidParameter(
            "image too small for ESP + system + GPT backup".into(),
        ));
    }
    let system_end = image_size - backup_reserve;
    let system_size = system_end.saturating_sub(system_offset);
    if system_size < 8 * 1024 * 1024 {
        return Err(Error::InvalidParameter(
            "computed system partition too small".into(),
        ));
    }

    Ok(PartitionLayout {
        esp_offset,
        esp_size,
        system_offset,
        system_size,
    })
}

/// Build a standalone base image (GPT + ESP + system). No share data.
pub fn build_base_image(req: &ImageRequest) -> Result<()> {
    let layout = plan_partitions(req.size)?;
    let assemble_bytes = std::fs::read(&req.assemble_bin).map_err(|e| {
        Error::Io(format!(
            "read assemble binary {}: {e}",
            req.assemble_bin.display()
        ))
    })?;
    if assemble_bytes.is_empty() {
        return Err(Error::InvalidParameter("assemble binary is empty".into()));
    }

    // Real Phase 4 blobs (BLAKE3-pinned; built by scripts/build-vendor-blobs.sh).
    let grub = BuiltBlob::load(BLOB_GRUB_EFI)?;
    let kernel = BuiltBlob::load(BLOB_KERNEL)?;
    let ccid = BuiltBlob::load(BLOB_CCID_IFD)?;

    let init_stub = vendor::synthetic_init_stub();
    let initramfs_bytes = initramfs::build_initramfs(
        &init_stub,
        &assemble_bytes,
        &[("usr/lib/pcsc/drivers/ifd-ccid.so", ccid.bytes())],
    )?;

    // Create sparse-capable zero-filled file of exact size.
    {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&req.output)
            .map_err(|e| Error::Io(e.to_string()))?;
        f.set_len(req.size).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }

    gpt_layout::write_gpt(&req.output, req.size, &req.drive_uuid, layout)?;

    // ESP (FAT32)
    {
        let mut part = partition_file(&req.output, layout.esp_offset, layout.esp_size)?;
        fat_esp::format_and_populate(
            &mut part,
            layout.esp_size,
            &req.drive_uuid,
            grub.bytes(),
            kernel.bytes(),
            &initramfs_bytes,
        )?;
        part.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }

    // System (ext4 via mke2fs + debugfs -w; OPEN-QUESTIONS (h) option C)
    {
        let staging = tempfile::tempdir().map_err(|e| Error::Io(e.to_string()))?;
        let part_path = staging.path().join("system.ext4");
        let assemble_path = staging.path().join("splitdisk-assemble");
        let initramfs_path = staging.path().join("initramfs.img");
        std::fs::write(&assemble_path, &assemble_bytes).map_err(|e| Error::Io(e.to_string()))?;
        std::fs::write(&initramfs_path, &initramfs_bytes).map_err(|e| Error::Io(e.to_string()))?;

        ext4_mke2fs::format_and_populate(
            &part_path,
            layout.system_size,
            &req.drive_uuid,
            &assemble_path,
            &initramfs_path,
        )?;
        ext4_mke2fs::splice_into_image(&req.output, layout.system_offset, &part_path)?;
    }

    // Final image fsync.
    let f = OpenOptions::new()
        .write(true)
        .open(&req.output)
        .map_err(|e| Error::Io(e.to_string()))?;
    f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

fn partition_file(path: &Path, offset: u64, size: u64) -> Result<PartitionView> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| Error::Io(e.to_string()))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(PartitionView { file, offset, size })
}

/// File view restricted to one partition's byte range.
pub struct PartitionView {
    file: File,
    offset: u64,
    size: u64,
}

impl PartitionView {
    pub fn size_bytes(&self) -> u64 {
        self.size
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    fn relative_pos(&mut self) -> std::io::Result<u64> {
        let abs = self.file.stream_position()?;
        if abs < self.offset {
            self.file.seek(SeekFrom::Start(self.offset))?;
            Ok(0)
        } else {
            Ok(abs - self.offset)
        }
    }
}

impl std::io::Read for PartitionView {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cur = self.relative_pos()?;
        if cur >= self.size {
            return Ok(0);
        }
        let max = (self.size - cur) as usize;
        let n = buf.len().min(max);
        self.file.read(&mut buf[..n])
    }
}

impl std::io::Write for PartitionView {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let cur = self.relative_pos()?;
        if cur >= self.size {
            return Ok(0);
        }
        let max = (self.size - cur) as usize;
        let n = buf.len().min(max);
        self.file.write(&buf[..n])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for PartitionView {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let cur = self.relative_pos()?;
        let target = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                let t = self.size as i64 + n;
                if t < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seek before partition start",
                    ));
                }
                t as u64
            }
            SeekFrom::Current(n) => {
                let t = cur as i64 + n;
                if t < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seek before partition start",
                    ));
                }
                t as u64
            }
        };
        if target > self.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek past partition end",
            ));
        }
        self.file.seek(SeekFrom::Start(self.offset + target))?;
        Ok(target)
    }
}

/// Derive a UUID (16 bytes) from `drive_uuid` and a domain label.
pub fn derive_guid(drive_uuid: &[u8; DRIVE_UUID_LEN], label: &str) -> uuid::Uuid {
    let mut hasher = blake3::Hasher::new_derive_key(label);
    hasher.update(drive_uuid);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    // RFC 4122 version 4 / variant 1 bits so GPT tooling accepts the GUID.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn plan_512mib_uses_256mib_esp() {
        let layout = plan_partitions(512 * 1024 * 1024).unwrap();
        assert_eq!(layout.esp_size, ESP_SIZE_DEFAULT);
        assert!(layout.system_size > 100 * 1024 * 1024);
    }
}
