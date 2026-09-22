//! GPT partition table construction (`gpt` crate), SPEC §6 / §10.2.

use crate::derive_guid;
use crate::error::{Error, Result};
use crate::{PartitionLayout, SECTOR_SIZE};
use gpt::disk::LogicalBlockSize;
use gpt::partition::Partition;
use gpt::partition_types;
use gpt::GptConfig;
use splitdisk_core::DRIVE_UUID_LEN;
use std::collections::BTreeMap;
use std::path::Path;

/// Write a protective MBR + GPT with ESP (EFI) and Linux filesystem partitions.
///
/// Partition and disk GUIDs are derived from `drive_uuid` so output is
/// reproducible when the UUID is fixed (SPEC §10.1).
pub fn write_gpt(
    image_path: &Path,
    image_size: u64,
    drive_uuid: &[u8; DRIVE_UUID_LEN],
    layout: PartitionLayout,
) -> Result<()> {
    let disk_guid = derive_guid(drive_uuid, "splitdisk-gpt-disk-guid-v1");
    let esp_guid = derive_guid(drive_uuid, "splitdisk-gpt-esp-part-guid-v1");
    let sys_guid = derive_guid(drive_uuid, "splitdisk-gpt-system-part-guid-v1");

    let cfg = GptConfig::new()
        .writable(true)
        .initialized(false)
        .logical_block_size(LogicalBlockSize::Lb512);

    let mut disk = cfg
        .create_from_device(
            Box::new(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(image_path)
                    .map_err(|e| Error::Gpt(format!("open image: {e}")))?,
            ),
            Some(disk_guid),
        )
        .map_err(|e| Error::Gpt(format!("create GPT: {e}")))?;

    disk.update_guid(Some(disk_guid))
        .map_err(|e| Error::Gpt(format!("set disk GUID: {e}")))?;

    let esp_first = layout.esp_offset / SECTOR_SIZE;
    let esp_last = (layout.esp_offset + layout.esp_size) / SECTOR_SIZE - 1;
    let sys_first = layout.system_offset / SECTOR_SIZE;
    let sys_last = (layout.system_offset + layout.system_size) / SECTOR_SIZE - 1;

    let mut parts = BTreeMap::new();
    parts.insert(
        1,
        Partition {
            part_type_guid: partition_types::EFI,
            part_guid: esp_guid,
            first_lba: esp_first,
            last_lba: esp_last,
            flags: 0,
            name: "EFI System".to_string(),
        },
    );
    parts.insert(
        2,
        Partition {
            part_type_guid: partition_types::LINUX_FS,
            part_guid: sys_guid,
            first_lba: sys_first,
            last_lba: sys_last,
            flags: 0,
            name: "SplitDisk System".to_string(),
        },
    );

    disk.update_partitions(parts)
        .map_err(|e| Error::Gpt(format!("set partitions: {e}")))?;
    disk.write()
        .map_err(|e| Error::Gpt(format!("write GPT: {e}")))?;

    let meta = std::fs::metadata(image_path).map_err(|e| Error::Io(e.to_string()))?;
    if meta.len() != image_size {
        return Err(Error::Gpt(format!(
            "image size changed after GPT write: {} != {image_size}",
            meta.len()
        )));
    }
    Ok(())
}

/// Read partition count and first two partition sizes (sectors) for tests.
pub fn inspect_partitions(image_path: &Path) -> Result<(usize, u64, u64)> {
    let cfg = GptConfig::new()
        .writable(false)
        .initialized(true)
        .logical_block_size(LogicalBlockSize::Lb512);
    let disk = cfg
        .open(image_path)
        .map_err(|e| Error::Gpt(format!("inspect open: {e}")))?;
    let mut parts: Vec<_> = disk.partitions().values().cloned().collect();
    parts.sort_by_key(|p| p.first_lba);
    if parts.len() < 2 {
        return Err(Error::Gpt(format!(
            "expected 2 partitions, found {}",
            parts.len()
        )));
    }
    let esp_sectors = parts[0].last_lba - parts[0].first_lba + 1;
    let sys_sectors = parts[1].last_lba - parts[1].first_lba + 1;
    Ok((parts.len(), esp_sectors, sys_sectors))
}
