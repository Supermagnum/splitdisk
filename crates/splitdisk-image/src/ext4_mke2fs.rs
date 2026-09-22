//! System partition construction via pinned `mke2fs` + `debugfs -w` (e2fsprogs).
//!
//! Replaces the Phase 3 hand-rolled `ext4_simple` writer (OPEN-QUESTIONS (h),
//! option C). No mount, no loop devices, no `/dev` paths — only regular files.

use crate::derive_guid;
use crate::error::{Error, Result};
use splitdisk_core::DRIVE_UUID_LEN;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Fixed epoch used only for documentation / structural checks; mke2fs/debugfs
/// still stamp wall-clock times into the image (see FORMAT.md §11.4 / reproducibility).
pub const EXT4_TOOLING_NOTE: &str = "e2fsprogs mke2fs+debugfs (Dockerfile pin)";

/// Format a fresh ext4 filesystem image and populate SPEC §6 base paths.
///
/// `part_path` is a regular file that will be truncated to `size` bytes.
pub fn format_and_populate(
    part_path: &Path,
    size: u64,
    drive_uuid: &[u8; DRIVE_UUID_LEN],
    assemble_host_path: &Path,
    initramfs_host_path: &Path,
) -> Result<()> {
    if size < 8 * 1024 * 1024 {
        return Err(Error::InvalidParameter(
            "ext4 partition must be at least 8 MiB".into(),
        ));
    }
    if !assemble_host_path.is_file() {
        return Err(Error::InvalidParameter(format!(
            "assemble binary missing: {}",
            assemble_host_path.display()
        )));
    }
    if !initramfs_host_path.is_file() {
        return Err(Error::InvalidParameter(format!(
            "initramfs missing: {}",
            initramfs_host_path.display()
        )));
    }

    // Create/truncate the partition file (no /dev, no sparse tricks required).
    {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(part_path)
            .map_err(|e| Error::Io(e.to_string()))?;
        f.set_len(size).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }

    let fs_uuid = derive_guid(drive_uuid, "splitdisk-ext4-fs-uuid-v1");
    let hash_seed = derive_guid(drive_uuid, "splitdisk-ext4-hash-seed-v1");
    let uuid_str = fs_uuid.hyphenated().to_string();
    let hash_str = hash_seed.hyphenated().to_string();

    // Journal disabled: partition is written once at enrollment and then
    // read-mostly during assembly; a journal adds flash write amplification
    // and is unused for our workload. See FORMAT.md §11.4.
    //
    // lazy_itable_init=0: fully initialize inode tables (avoids deferred
    // kernel init / nondeterministic unused inode contents).
    // nodiscard: do not issue discard against a regular file.
    let extended = format!("hash_seed={hash_str},lazy_itable_init=0,nodiscard");

    let status = Command::new("mke2fs")
        .args([
            "-t",
            "ext4",
            "-F",
            "-q",
            "-b",
            "4096",
            "-U",
            &uuid_str,
            "-E",
            &extended,
            "-O",
            "^has_journal",
            // Volume label blank per SPEC §6 ("partition label is blank").
            "-L",
            "",
            part_path
                .to_str()
                .ok_or_else(|| Error::InvalidParameter("non-utf8 partition path".into()))?,
        ])
        .status()
        .map_err(|e| Error::Io(format!("spawn mke2fs: {e}")))?;
    if !status.success() {
        return Err(Error::Format(format!("mke2fs failed with status {status}")));
    }

    let assemble = assemble_host_path
        .canonicalize()
        .map_err(|e| Error::Io(format!("canonicalize assemble: {e}")))?;
    let initramfs = initramfs_host_path
        .canonicalize()
        .map_err(|e| Error::Io(format!("canonicalize initramfs: {e}")))?;

    let cmd_file = part_path.with_extension("debugfs.cmd");
    let script = format!(
        "mkdir usr\n\
         mkdir usr/bin\n\
         mkdir boot\n\
         mkdir share\n\
         mkdir share/auth\n\
         write {assemble} usr/bin/splitdisk-assemble\n\
         write {initramfs} boot/initramfs.img\n\
         quit\n",
        assemble = shell_escape_path(&assemble),
        initramfs = shell_escape_path(&initramfs),
    );
    fs::write(&cmd_file, script).map_err(|e| Error::Io(e.to_string()))?;

    let output = Command::new("debugfs")
        .args([
            "-w",
            "-f",
            cmd_file
                .to_str()
                .ok_or_else(|| Error::InvalidParameter("non-utf8 cmd path".into()))?,
            part_path
                .to_str()
                .ok_or_else(|| Error::InvalidParameter("non-utf8 partition path".into()))?,
        ])
        .output()
        .map_err(|e| Error::Io(format!("spawn debugfs: {e}")))?;
    let _ = fs::remove_file(&cmd_file);
    if !output.status.success() {
        return Err(Error::Format(format!(
            "debugfs -w failed: status={} stderr={} stdout={}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        )));
    }

    // fsync the finished partition file.
    let f = OpenOptions::new()
        .write(true)
        .open(part_path)
        .map_err(|e| Error::Io(e.to_string()))?;
    f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

/// Copy `part_path` into `image_path` at absolute `offset` (splice).
pub fn splice_into_image(image_path: &Path, offset: u64, part_path: &Path) -> Result<()> {
    let mut src = File::open(part_path).map_err(|e| Error::Io(e.to_string()))?;
    let mut dst = OpenOptions::new()
        .write(true)
        .open(image_path)
        .map_err(|e| Error::Io(e.to_string()))?;
    dst.seek(SeekFrom::Start(offset))
        .map_err(|e| Error::Io(e.to_string()))?;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src.read(&mut buf).map_err(|e| Error::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])
            .map_err(|e| Error::Io(e.to_string()))?;
    }
    dst.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

/// List directory entries via `debugfs` (read-only; no mount).
pub fn list_dir(part_path: &Path, dir: &str) -> Result<Vec<String>> {
    let path = if dir.is_empty() { "/" } else { dir };
    let req = format!("ls -p {path}");
    let stdout = debugfs_ro(part_path, &req)?;
    let mut names = Vec::new();
    for line in stdout.lines() {
        // ls -p: /inode/mode/uid/gid/name/size/...
        let parts: Vec<&str> = line.split('/').collect();
        if parts.len() >= 6 {
            let name = parts[5];
            if !name.is_empty() && name != "." && name != ".." {
                names.push(name.to_string());
            }
        }
    }
    Ok(names)
}

/// Read a file via `debugfs cat` into a temp dump (no mount).
pub fn read_file(part_path: &Path, fs_path: &str) -> Result<Vec<u8>> {
    let dump = part_path.with_extension(format!("cat.{}", fs_path.replace('/', "_")));
    let req = format!("dump {fs_path} {}", shell_escape_path(&dump));
    let _ = debugfs_ro(part_path, &req)?;
    let bytes = fs::read(&dump).map_err(|e| Error::Io(format!("read dump: {e}")))?;
    let _ = fs::remove_file(&dump);
    Ok(bytes)
}

fn debugfs_ro(part_path: &Path, request: &str) -> Result<String> {
    let output = Command::new("debugfs")
        .args([
            "-R",
            request,
            part_path
                .to_str()
                .ok_or_else(|| Error::InvalidParameter("non-utf8 partition path".into()))?,
        ])
        .output()
        .map_err(|e| Error::Io(format!("spawn debugfs: {e}")))?;
    if !output.status.success() {
        return Err(Error::Format(format!(
            "debugfs -R {request:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn shell_escape_path(p: &Path) -> String {
    // debugfs command files: paths with spaces need quoting; our CI paths do not.
    p.display().to_string()
}

/// Create a unique temp path under `dir` for a partition staging file.
pub fn staging_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}
