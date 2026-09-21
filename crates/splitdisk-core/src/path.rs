//! Carrier path validation. Raw `/dev` paths are rejected unless `raw-devices`.

use crate::error::{Error, Result};
use std::path::Path;

/// Reject paths that refer to raw block devices when `raw-devices` is off.
///
/// Without the `raw-devices` feature (default), any path whose normalized
/// form starts with `/dev` (or `\\.\` style device prefixes on other hosts)
/// returns [`Error::RawDeviceRejected`].
pub fn validate_carrier_path(path: &Path) -> Result<()> {
    #[cfg(feature = "raw-devices")]
    {
        let _ = path;
        return Ok(());
    }

    #[cfg(not(feature = "raw-devices"))]
    {
        if is_raw_device_path(path) {
            return Err(Error::RawDeviceRejected);
        }
        Ok(())
    }
}

fn is_raw_device_path(path: &Path) -> bool {
    // Absolute /dev/...
    if path.starts_with("/dev") {
        return true;
    }
    // String form catches relative tricks like "///dev/sda" after components.
    let s = path.to_string_lossy();
    if s.contains("/dev/") || s.ends_with("/dev") {
        // Allow ordinary directory names that merely contain the letters,
        // but reject any path component exactly equal to climbing into /dev.
        let mut abs_like = false;
        for c in path.components() {
            use std::path::Component;
            match c {
                Component::RootDir => abs_like = true,
                Component::Normal(os) if abs_like && os == "dev" => return true,
                Component::Normal(_) => {}
                Component::CurDir | Component::ParentDir => {}
                Component::Prefix(_) => {}
            }
        }
        // Also reject explicit "/dev" prefix strings.
        if s.starts_with("/dev/") || s == "/dev" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn accepts_regular_files() {
        validate_carrier_path(Path::new("testdata/share0.bin")).unwrap();
        validate_carrier_path(Path::new("/tmp/share.img")).unwrap();
        validate_carrier_path(Path::new("./shares/a")).unwrap();
    }

    #[test]
    fn rejects_dev_paths() {
        assert!(matches!(
            validate_carrier_path(Path::new("/dev/sda")),
            Err(Error::RawDeviceRejected)
        ));
        assert!(matches!(
            validate_carrier_path(Path::new("/dev/nvme0n1p1")),
            Err(Error::RawDeviceRejected)
        ));
        let p = PathBuf::from("/dev");
        assert!(matches!(
            validate_carrier_path(&p),
            Err(Error::RawDeviceRejected)
        ));
    }
}
