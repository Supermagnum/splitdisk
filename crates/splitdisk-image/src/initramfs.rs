//! initramfs (cpio + gzip) assembly, SPEC §10.3.

use crate::error::{Error, Result};
use cpio::{newc, write_cpio};
use flate2::{Compression, GzBuilder};
use std::io::{Cursor, Read, Write};

/// Fixed mtime for reproducible archives (SPEC §10.1).
const REPRO_MTIME: u32 = 1_000_000_000;

/// Build gzip-compressed newc cpio with SPEC §10.3 layout.
///
/// `ccid_files` are `(archive_path_without_leading_slash, bytes)`.
pub fn build_initramfs(
    init_stub: &[u8],
    assemble_bin: &[u8],
    ccid_files: &[(&str, &[u8])],
) -> Result<Vec<u8>> {
    let mut entries: Vec<(newc::Builder, Vec<u8>)> = Vec::new();

    for dir in [
        "dev",
        "proc",
        "sys",
        "tmp",
        "etc",
        "etc/reader.conf.d",
        "usr",
        "usr/bin",
        "usr/lib",
        "usr/lib/pcsc",
        "usr/lib/pcsc/drivers",
    ] {
        entries.push((dir_entry(dir), Vec::new()));
    }

    entries.push((file_entry("init", 0o755), init_stub.to_vec()));
    entries.push((
        file_entry("usr/bin/splitdisk-assemble", 0o755),
        assemble_bin.to_vec(),
    ));

    for (path, bytes) in ccid_files {
        entries.push((file_entry(path, 0o644), bytes.to_vec()));
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
    let gz = enc
        .finish()
        .map_err(|e| Error::Io(format!("gzip finish: {e}")))?;
    Ok(gz)
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
