//! initramfs (cpio + gzip) assembly, SPEC §10.3.

use crate::error::{Error, Result};
use cpio::{newc, write_cpio};
use flate2::{Compression, GzBuilder};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

/// Fixed mtime for reproducible archives (SPEC §10.1).
const REPRO_MTIME: u32 = 1_000_000_000;

/// CCID IFD bundle bytes for pcsclite usbdropdir layout.
#[derive(Debug, Clone)]
pub struct CcidBundle {
    pub libccid_so: Vec<u8>,
    pub info_plist: Vec<u8>,
}

type Entry = (newc::Builder, Vec<u8>);

/// Build gzip-compressed newc cpio with SPEC §10.3 layout.
///
/// `extra_files` are additional `(archive_path_without_leading_slash, bytes)`
/// entries (e.g. pcscd + shared libraries staged by
/// `scripts/stage-initramfs-runtime.sh`).
pub fn build_initramfs(
    init_bin: &[u8],
    assemble_bin: &[u8],
    ccid: &CcidBundle,
    extra_files: &[(&str, &[u8])],
) -> Result<Vec<u8>> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut names: HashSet<String> = HashSet::new();

    for dir in [
        "dev",
        "proc",
        "sys",
        "tmp",
        "run",
        "run/pcscd",
        "var",
        "var/run",
        "var/run/pcscd",
        "etc",
        "etc/reader.conf.d",
        "usr",
        "usr/bin",
        "usr/sbin",
        "usr/lib",
        "usr/lib/pcsc",
        "usr/lib/pcsc/drivers",
        "usr/lib/pcsc/drivers/ifd-ccid.bundle",
        "usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents",
        "usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux",
        "lib",
        "lib64",
        "lib/x86_64-linux-gnu",
        "usr/lib/x86_64-linux-gnu",
    ] {
        add_dir(&mut entries, &mut names, dir);
    }

    add_file(
        &mut entries,
        &mut names,
        "init",
        0o100755,
        init_bin.to_vec(),
    );
    add_file(
        &mut entries,
        &mut names,
        "usr/bin/splitdisk-assemble",
        0o100755,
        assemble_bin.to_vec(),
    );
    add_file(
        &mut entries,
        &mut names,
        "usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist",
        0o100644,
        ccid.info_plist.clone(),
    );
    add_file(
        &mut entries,
        &mut names,
        "usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so",
        0o100755,
        ccid.libccid_so.clone(),
    );

    for (path, bytes) in extra_files {
        ensure_parent_dirs(&mut entries, &mut names, path);
        let mode = if path.contains(".so")
            || path.ends_with("pcscd")
            || Path::new(path).extension().is_none()
        {
            0o100755
        } else {
            0o100644
        };
        add_file(&mut entries, &mut names, path, mode, bytes.to_vec());
    }

    let mut cpio_buf = Vec::new();
    {
        let iter = entries
            .into_iter()
            .map(|(builder, data)| (builder, Cursor::new(data)));
        write_cpio(iter, &mut cpio_buf).map_err(|e| Error::Format(format!("cpio write: {e}")))?;
    }

    let mut enc = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::new(6));
    enc.write_all(&cpio_buf)
        .map_err(|e| Error::Io(format!("gzip write: {e}")))?;
    enc.finish()
        .map_err(|e| Error::Io(format!("gzip finish: {e}")))
}

/// Load every regular file under `root` as initramfs paths relative to `root`.
pub fn collect_extra_tree(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    if !root.is_dir() {
        return Ok(out);
    }
    walk(root, root, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    let rd = std::fs::read_dir(dir).map_err(|e| Error::Io(e.to_string()))?;
    for ent in rd {
        let ent = ent.map_err(|e| Error::Io(e.to_string()))?;
        let path = ent.path();
        // Use symlink_metadata so a dangling soname link does not abort the whole tree.
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| Error::Io(e.to_string()))?;
            let rel_s = rel.to_string_lossy().replace('\\', "/");
            let bytes = std::fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
            out.push((rel_s, bytes));
        } else if meta.file_type().is_symlink() {
            // Prefer following the link when the target exists (host or relative);
            // skip dangling links left by older staging that used `cp -a` without -L.
            if let Ok(bytes) = std::fs::read(&path) {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| Error::Io(e.to_string()))?;
                let rel_s = rel.to_string_lossy().replace('\\', "/");
                out.push((rel_s, bytes));
            }
        }
    }
    Ok(())
}

fn ensure_parent_dirs(entries: &mut Vec<Entry>, names: &mut HashSet<String>, path: &str) {
    let mut acc = PathBuf::new();
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        for comp in parent.components() {
            acc.push(comp);
            let s = acc.to_string_lossy().replace('\\', "/");
            if s.is_empty() || s == "." {
                continue;
            }
            add_dir(entries, names, &s);
        }
    }
}

fn add_dir(entries: &mut Vec<Entry>, names: &mut HashSet<String>, name: &str) {
    if names.insert(name.to_string()) {
        entries.push((dir_entry(name), Vec::new()));
    }
}

fn add_file(
    entries: &mut Vec<Entry>,
    names: &mut HashSet<String>,
    name: &str,
    mode: u32,
    data: Vec<u8>,
) {
    if names.insert(name.to_string()) {
        entries.push((file_entry(name, mode), data));
    }
}

fn dir_entry(name: &str) -> newc::Builder {
    newc::Builder::new(name)
        .mode(0o40755)
        .mtime(REPRO_MTIME)
        .uid(0)
        .gid(0)
        .nlink(2)
}

fn file_entry(name: &str, mode: u32) -> newc::Builder {
    newc::Builder::new(name)
        .mode(mode)
        .mtime(REPRO_MTIME)
        .uid(0)
        .gid(0)
        .nlink(1)
}

/// Decompress and list newc entry names (for tests).
pub fn list_cpio_names(gz_bytes: &[u8]) -> Result<Vec<String>> {
    use flate2::read::GzDecoder;
    let mut dec = GzDecoder::new(gz_bytes);
    let mut raw = Vec::new();
    dec.read_to_end(&mut raw)
        .map_err(|e| Error::Format(format!("gunzip: {e}")))?;

    let mut names = Vec::new();
    let mut rest: &[u8] = &raw;
    loop {
        let reader =
            newc::Reader::new(rest).map_err(|e| Error::Format(format!("cpio read: {e}")))?;
        let name = reader.entry().name().to_string();
        if reader.entry().is_trailer() {
            break;
        }
        names.push(name);
        rest = reader
            .finish()
            .map_err(|e| Error::Format(format!("cpio finish: {e}")))?;
    }
    Ok(names)
}
