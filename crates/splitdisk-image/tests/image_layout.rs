//! Phase 4 image builder integration tests (file-backed only; no /dev, no mount).

use splitdisk_image::ext4_mke2fs;
use splitdisk_image::fat_esp::{self, GRUB_CFG};
use splitdisk_image::gpt_layout;
use splitdisk_image::initramfs;
use splitdisk_image::vendor::{
    BuiltBlob, VendoredBlob, BLOB_CCID_IFD, BLOB_GRUB_EFI, BLOB_KERNEL, KERNEL_UTS_VERSION_SNIPPET,
    PLACEHOLDER_BANNER,
};
use splitdisk_image::{build_base_image, plan_partitions, ImageRequest, ESP_SIZE_DEFAULT};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;

fn fixed_uuid() -> [u8; 16] {
    *b"PHASE3-TEST-UUID"
}

fn assemble_fixture() -> PathBuf {
    // Prefer release (stripped-ish) binary: debug builds are tens of MiB and
    // will not fit beside initramfs in a 64 MiB fixture image.
    let candidates = [
        std::env::var_os("SPLITDISK_ASSEMBLE_BIN").map(PathBuf::from),
        std::env::var_os("CARGO_TARGET_DIR")
            .map(|t| PathBuf::from(t).join("release").join("splitdisk-assemble")),
        Some(PathBuf::from(
            "/tmp/cargo-target/release/splitdisk-assemble",
        )),
        Some(PathBuf::from(
            "/tmp/cargo-target-p3/release/splitdisk-assemble",
        )),
        Some(PathBuf::from("target/release/splitdisk-assemble")),
        std::env::var_os("CARGO_TARGET_DIR")
            .map(|t| PathBuf::from(t).join("debug").join("splitdisk-assemble")),
    ];
    for c in candidates.into_iter().flatten() {
        if c.is_file() {
            return c;
        }
    }
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "splitdisk-assemble",
            "--release",
            "--offline",
            "--quiet",
        ])
        .status()
        .expect("spawn cargo build assemble");
    assert!(status.success(), "failed to build splitdisk-assemble");
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());
    let p = PathBuf::from(target).join("release/splitdisk-assemble");
    assert!(p.is_file(), "missing assemble binary at {}", p.display());
    p
}

#[test]
fn real_blob_pins_match_checked_in_values() {
    // Loading asserts BLAKE3 pins; requires scripts/build-vendor-blobs.sh first.
    let g = BuiltBlob::load(BLOB_GRUB_EFI).expect("grub pin");
    let k = BuiltBlob::load(BLOB_KERNEL).expect("kernel pin");
    let c = BuiltBlob::load(BLOB_CCID_IFD).expect("ccid pin");
    assert!(
        !g.bytes().starts_with(PLACEHOLDER_BANNER),
        "grub must not be synthetic"
    );
    assert!(
        !k.bytes().starts_with(PLACEHOLDER_BANNER),
        "kernel must not be synthetic"
    );
    assert!(
        !c.bytes().starts_with(PLACEHOLDER_BANNER),
        "ccid must not be synthetic"
    );
    assert_eq!(g.blake3_hex().len(), 64);
    assert_eq!(k.blake3_hex().len(), 64);
    assert_eq!(c.blake3_hex().len(), 64);
}

#[test]
fn kernel_embeds_fixed_kbuild_metadata() {
    let k = BuiltBlob::load(BLOB_KERNEL).expect("kernel blob");
    let hay = String::from_utf8_lossy(k.bytes());
    assert!(
        hay.contains(KERNEL_UTS_VERSION_SNIPPET),
        "bzImage UTS version string must match fixed Kbuild metadata"
    );
}

#[test]
fn initramfs_contains_spec_paths() {
    let init = splitdisk_image::vendor::synthetic_init_stub();
    let assemble = b"FAKE-ASSEMBLE-BIN-FOR-INITRAMFS-TEST";
    let ccid = BuiltBlob::load(BLOB_CCID_IFD).expect("ccid for initramfs test");
    let gz = initramfs::build_initramfs(
        &init,
        assemble,
        &[("usr/lib/pcsc/drivers/ifd-ccid.so", ccid.bytes())],
    )
    .unwrap();
    let names = initramfs::list_cpio_names(&gz).unwrap();
    for expected in [
        "init",
        "usr/bin/splitdisk-assemble",
        "usr/lib/pcsc/drivers/ifd-ccid.so",
        "dev",
        "proc",
        "sys",
        "tmp",
        "etc/reader.conf.d",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing {expected} in {names:?}"
        );
    }
}

#[test]
fn two_runs_structurally_equivalent_with_fixed_drive_uuid() {
    // GPT + FAT regions remain byte-identical. The ext4 system partition is
    // built with mke2fs+debugfs, which stamp wall-clock inode/superblock
    // times (and metadata_csum over those), so full-image byte identity is
    // not achievable without fragile post-processing. We therefore require:
    //   - identical length
    //   - byte-identical prefix through end of ESP (GPT + FAT)
    //   - structurally equivalent system partitions (same tree + file bytes)
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.img");
    let b = dir.path().join("b.img");
    let assemble = assemble_fixture();
    let size = 64 * 1024 * 1024;
    let uuid = fixed_uuid();
    for out in [&a, &b] {
        build_base_image(&ImageRequest {
            output: out.clone(),
            size,
            drive_uuid: uuid,
            assemble_bin: assemble.clone(),
        })
        .unwrap();
    }
    let ba = std::fs::read(&a).unwrap();
    let bb = std::fs::read(&b).unwrap();
    assert_eq!(ba.len(), size as usize);
    let layout = plan_partitions(size).unwrap();
    let prefix_end = layout.system_offset as usize;
    assert_eq!(
        &ba[..prefix_end],
        &bb[..prefix_end],
        "GPT+ESP must be byte-identical for fixed drive_uuid"
    );

    let pa = dir.path().join("a.ext4");
    let pb = dir.path().join("b.ext4");
    extract_byte_range(&a, layout.system_offset, layout.system_size, &pa);
    extract_byte_range(&b, layout.system_offset, layout.system_size, &pb);

    for d in ["", "usr", "usr/bin", "boot", "share", "share/auth"] {
        let mut la = ext4_mke2fs::list_dir(&pa, d).unwrap();
        let mut lb = ext4_mke2fs::list_dir(&pb, d).unwrap();
        la.sort();
        lb.sort();
        assert_eq!(la, lb, "dir listing mismatch at {d:?}");
    }
    for f in ["usr/bin/splitdisk-assemble", "boot/initramfs.img"] {
        let fa = ext4_mke2fs::read_file(&pa, f).unwrap();
        let fb = ext4_mke2fs::read_file(&pb, f).unwrap();
        assert_eq!(fa, fb, "file content mismatch for {f}");
    }
}

#[test]
fn gpt_and_partition_sizes_match_plan() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("gpt.img");
    let assemble = assemble_fixture();
    let size = 512 * 1024 * 1024;
    let layout = plan_partitions(size).unwrap();
    assert_eq!(layout.esp_size, ESP_SIZE_DEFAULT);
    build_base_image(&ImageRequest {
        output: img.clone(),
        size,
        drive_uuid: fixed_uuid(),
        assemble_bin: assemble,
    })
    .unwrap();

    let (n, esp_sec, sys_sec) = gpt_layout::inspect_partitions(&img).unwrap();
    assert_eq!(n, 2);
    assert_eq!(esp_sec * 512, layout.esp_size);
    assert_eq!(sys_sec * 512, layout.system_size);
}

#[test]
fn fat_esp_readback_matches_written_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("fat.img");
    let assemble = assemble_fixture();
    let size = 64 * 1024 * 1024;
    build_base_image(&ImageRequest {
        output: img.clone(),
        size,
        drive_uuid: fixed_uuid(),
        assemble_bin: assemble,
    })
    .unwrap();

    let layout = plan_partitions(size).unwrap();
    let grub = BuiltBlob::load(BLOB_GRUB_EFI).unwrap();
    let kernel = BuiltBlob::load(BLOB_KERNEL).unwrap();

    let mut part = open_part(&img, layout.esp_offset, layout.esp_size);
    let bootx64 = fat_esp::read_esp_file(&mut part, "EFI/BOOT/BOOTX64.EFI").unwrap();
    assert_eq!(bootx64, grub.bytes());
    let vmlinuz = fat_esp::read_esp_file(&mut part, "boot/vmlinuz").unwrap();
    assert_eq!(vmlinuz, kernel.bytes());
    let cfg = fat_esp::read_esp_file(&mut part, "boot/grub/grub.cfg").unwrap();
    assert_eq!(cfg, GRUB_CFG.as_bytes());
    let initrd = fat_esp::read_esp_file(&mut part, "boot/initramfs.img").unwrap();
    assert!(!initrd.is_empty());
    assert!(initramfs::list_cpio_names(&initrd).is_ok());
}

#[test]
fn ext4_system_readback_has_assemble_and_share_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("ext4.img");
    let assemble = assemble_fixture();
    let assemble_bytes = std::fs::read(&assemble).unwrap();
    let size = 64 * 1024 * 1024;
    build_base_image(&ImageRequest {
        output: img.clone(),
        size,
        drive_uuid: fixed_uuid(),
        assemble_bin: assemble,
    })
    .unwrap();

    let layout = plan_partitions(size).unwrap();
    let part_path = dir.path().join("system.ext4");
    extract_byte_range(&img, layout.system_offset, layout.system_size, &part_path);

    let root = ext4_mke2fs::list_dir(&part_path, "").unwrap();
    for d in ["usr", "boot", "share"] {
        assert!(root.iter().any(|x| x == d), "missing {d} in {root:?}");
    }
    let bin = ext4_mke2fs::read_file(&part_path, "usr/bin/splitdisk-assemble").unwrap();
    assert_eq!(bin, assemble_bytes);
    let initrd = ext4_mke2fs::read_file(&part_path, "boot/initramfs.img").unwrap();
    assert!(!initrd.is_empty());
    let share = ext4_mke2fs::list_dir(&part_path, "share").unwrap();
    assert!(share.iter().any(|x| x == "auth"));
}

fn open_part(path: &std::path::Path, offset: u64, size: u64) -> PartFile {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    PartFile { file, offset, size }
}

struct PartFile {
    file: std::fs::File,
    offset: u64,
    size: u64,
}

impl Read for PartFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pos = self.file.stream_position()?;
        if pos < self.offset {
            self.file.seek(SeekFrom::Start(self.offset))?;
        }
        let cur = self.file.stream_position()? - self.offset;
        if cur >= self.size {
            return Ok(0);
        }
        let n = buf.len().min((self.size - cur) as usize);
        self.file.read(&mut buf[..n])
    }
}

impl Write for PartFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let pos = self.file.stream_position()?;
        if pos < self.offset {
            self.file.seek(SeekFrom::Start(self.offset))?;
        }
        let cur = self.file.stream_position()? - self.offset;
        if cur >= self.size {
            return Ok(0);
        }
        let n = buf.len().min((self.size - cur) as usize);
        self.file.write(&buf[..n])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for PartFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => self.offset + n,
            SeekFrom::End(n) => (self.offset as i64 + self.size as i64 + n) as u64,
            SeekFrom::Current(n) => (self.file.stream_position()? as i64 + n) as u64,
        };
        self.file.seek(SeekFrom::Start(target))?;
        Ok(target - self.offset)
    }
}

#[test]
fn ext4_partition_passes_fsck_ext4_readonly() {
    // Honest external validation: extract the GPT system partition to a temp
    // file (no loop, no mount) and run `fsck.ext4 -n -f`. If this fails, do
    // NOT patch the writer in this corrective pass — see OPEN-QUESTIONS (h).
    let fsck = which_fsck_ext4();
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("fsck.img");
    let assemble = assemble_fixture();
    let size = 64 * 1024 * 1024;
    build_base_image(&ImageRequest {
        output: img.clone(),
        size,
        drive_uuid: fixed_uuid(),
        assemble_bin: assemble,
    })
    .unwrap();

    let layout = plan_partitions(size).unwrap();
    let part_path = dir.path().join("system.ext4");
    extract_byte_range(&img, layout.system_offset, layout.system_size, &part_path);

    let output = Command::new(&fsck)
        .args(["-n", "-f", part_path.to_str().unwrap()])
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", fsck.display()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!(
        "fsck.ext4 -n -f exit={}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code().unwrap_or(-1)
    );
    eprintln!("{combined}");
    assert!(
        output.status.success(),
        "fsck.ext4 rejected the in-tree ext4 writer output (exit {:?}).\n\
         Full output:\n{combined}\n\
         See docs/OPEN-QUESTIONS.md (h). Do not treat in-tree round-trip as proof of validity.",
        output.status.code()
    );
}

fn which_fsck_ext4() -> PathBuf {
    for candidate in ["fsck.ext4", "e2fsck"] {
        if let Ok(out) = Command::new("sh")
            .args(["-c", &format!("command -v {candidate}")])
            .output()
        {
            if out.status.success() {
                let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !p.is_empty() {
                    return PathBuf::from(p);
                }
            }
        }
    }
    panic!(
        "fsck.ext4 / e2fsck not found; install pinned e2fsprogs in the test image \
         (see Dockerfile). This test must not be skipped."
    );
}

fn extract_byte_range(image: &std::path::Path, offset: u64, len: u64, dest: &std::path::Path) {
    use std::io::Read as _;
    let mut src = std::fs::File::open(image).unwrap();
    src.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = vec![0u8; len as usize];
    src.read_exact(&mut buf).unwrap();
    std::fs::write(dest, &buf).unwrap();
}

#[test]
fn cached_blob_digests_are_64_hex() {
    for role in [BLOB_GRUB_EFI, BLOB_KERNEL, BLOB_CCID_IFD] {
        let hex = splitdisk_image::vendor::digest_cached_blob(role).expect(role);
        assert_eq!(hex.len(), 64, "{role}");
    }
}
