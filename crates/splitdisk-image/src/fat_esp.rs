//! FAT32 ESP construction (`fatfs`), SPEC §6 / §10.4.

use crate::derive_guid;
use crate::error::{Error, Result};
use fatfs::{FileSystem, FormatVolumeOptions, FsOptions};
use splitdisk_core::DRIVE_UUID_LEN;
use std::io::{Read, Seek, Write};

/// GRUB config text matching SPEC §10.4.
pub const GRUB_CFG: &str = r#"set timeout=0
set default=0

menuentry "SplitDisk" {
    linux /boot/vmlinuz quiet loglevel=0 rd.udev.log_level=0
    initrd /boot/initramfs.img
}
"#;

/// Format `device` as FAT32 and write ESP boot files.
pub fn format_and_populate<D>(
    device: &mut D,
    size: u64,
    drive_uuid: &[u8; DRIVE_UUID_LEN],
    grub_efi: &[u8],
    kernel: &[u8],
    initramfs: &[u8],
) -> Result<()>
where
    D: Read + Write + Seek,
{
    // Volume ID: first 4 bytes of a derived GUID (stable for reproducibility).
    let vol_guid = derive_guid(drive_uuid, "splitdisk-fat-volume-id-v1");
    let vol_bytes = vol_guid.as_bytes();
    let volume_id = u32::from_le_bytes([vol_bytes[0], vol_bytes[1], vol_bytes[2], vol_bytes[3]]);

    let total_sectors = size / 512;
    if total_sectors > u32::MAX as u64 {
        return Err(Error::InvalidParameter("FAT volume too large".into()));
    }

    let opts = FormatVolumeOptions::new()
        .fat_type(fatfs::FatType::Fat32)
        .volume_label(*b"SPLITDISK  ")
        .volume_id(volume_id)
        .total_sectors(total_sectors as u32)
        .bytes_per_sector(512);

    fatfs::format_volume(&mut *device, opts)
        .map_err(|e| Error::Format(format!("FAT format: {e}")))?;

    device
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| Error::Io(e.to_string()))?;

    {
        let fs = FileSystem::new(&mut *device, FsOptions::new())
            .map_err(|e| Error::Format(format!("FAT mount: {e}")))?;
        let root = fs.root_dir();

        root.create_dir("EFI")
            .map_err(|e| Error::Format(format!("mkdir EFI: {e}")))?;
        let efi = root
            .open_dir("EFI")
            .map_err(|e| Error::Format(format!("open EFI: {e}")))?;
        efi.create_dir("BOOT")
            .map_err(|e| Error::Format(format!("mkdir BOOT: {e}")))?;
        let boot_efi = efi
            .open_dir("BOOT")
            .map_err(|e| Error::Format(format!("open BOOT: {e}")))?;
        {
            let mut f = boot_efi
                .create_file("BOOTX64.EFI")
                .map_err(|e| Error::Format(format!("create BOOTX64.EFI: {e}")))?;
            f.write_all(grub_efi)
                .map_err(|e| Error::Io(format!("write BOOTX64.EFI: {e}")))?;
            f.flush().map_err(|e| Error::Io(e.to_string()))?;
        }

        root.create_dir("boot")
            .map_err(|e| Error::Format(format!("mkdir boot: {e}")))?;
        let boot = root
            .open_dir("boot")
            .map_err(|e| Error::Format(format!("open boot: {e}")))?;
        {
            let mut f = boot
                .create_file("vmlinuz")
                .map_err(|e| Error::Format(format!("create vmlinuz: {e}")))?;
            f.write_all(kernel)
                .map_err(|e| Error::Io(format!("write vmlinuz: {e}")))?;
            f.flush().map_err(|e| Error::Io(e.to_string()))?;
        }
        {
            let mut f = boot
                .create_file("initramfs.img")
                .map_err(|e| Error::Format(format!("create initramfs.img: {e}")))?;
            f.write_all(initramfs)
                .map_err(|e| Error::Io(format!("write initramfs.img: {e}")))?;
            f.flush().map_err(|e| Error::Io(e.to_string()))?;
        }
        boot.create_dir("grub")
            .map_err(|e| Error::Format(format!("mkdir grub: {e}")))?;
        let grub_dir = boot
            .open_dir("grub")
            .map_err(|e| Error::Format(format!("open grub: {e}")))?;
        {
            let mut f = grub_dir
                .create_file("grub.cfg")
                .map_err(|e| Error::Format(format!("create grub.cfg: {e}")))?;
            f.write_all(GRUB_CFG.as_bytes())
                .map_err(|e| Error::Io(format!("write grub.cfg: {e}")))?;
            f.flush().map_err(|e| Error::Io(e.to_string()))?;
        }
    }

    Ok(())
}

/// Read a file from a FAT32 partition image in memory / device.
pub fn read_esp_file<D>(device: &mut D, path: &str) -> Result<Vec<u8>>
where
    D: Read + Write + Seek,
{
    device
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| Error::Io(e.to_string()))?;
    let fs = FileSystem::new(&mut *device, FsOptions::new())
        .map_err(|e| Error::Format(format!("FAT remount: {e}")))?;
    let mut file = fs
        .root_dir()
        .open_file(path)
        .map_err(|e| Error::Format(format!("open {path}: {e}")))?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)
        .map_err(|e| Error::Io(format!("read {path}: {e}")))?;
    Ok(out)
}
