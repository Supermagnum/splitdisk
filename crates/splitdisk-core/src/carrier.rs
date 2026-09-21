//! Share carrier abstraction and regular-file implementation.

use crate::error::{Error, Result};
use crate::path::validate_carrier_path;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Abstraction over storage that holds share bytes (chunk + auth + meta).
pub trait ShareCarrier {
    /// Write `data` starting at absolute `offset`.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;

    /// Read exactly `buf.len()` bytes starting at `offset`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Persist writes (fsync).
    fn sync(&mut self) -> Result<()>;

    /// Current length in bytes.
    fn len(&mut self) -> Result<u64>;

    fn is_empty(&mut self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Regular-file carrier. Paths under `/dev` are rejected unless `raw-devices`.
pub struct FileCarrier {
    path: PathBuf,
    file: File,
}

impl FileCarrier {
    /// Create or open a share file for read/write.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        validate_carrier_path(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Open an existing share file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        validate_carrier_path(path)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ShareCarrier for FileCarrier {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut off = 0;
        while off < buf.len() {
            match self.file.read(&mut buf[off..]) {
                Ok(0) => return Err(Error::UnexpectedEof),
                Ok(n) => off += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    fn len(&mut self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

/// Append helper used by streaming writers that own a [`FileCarrier`].
impl Write for FileCarrier {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Read for FileCarrier {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for FileCarrier {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn file_carrier_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        {
            let mut c = FileCarrier::create(path).unwrap();
            c.write_at(0, b"hello").unwrap();
            c.write_at(5, b" world").unwrap();
            c.sync().unwrap();
        }
        let mut c = FileCarrier::open(path).unwrap();
        let mut buf = [0u8; 11];
        c.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello world");
        assert_eq!(c.len().unwrap(), 11);
    }

    #[test]
    fn rejects_dev() {
        let err = FileCarrier::create("/dev/null");
        assert!(matches!(err, Err(Error::RawDeviceRejected)));
    }
}
