//! Start `pcscd` as a subprocess (SPEC §10.3).
//!
//! Choice: **assemble** owns pcscd (not `/init`), matching SPEC's preferred
//! wording ("invoked as a subprocess by splitdisk-assemble at runtime").

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const MARK_START: &str = "SPLITDISK_PCSCD_STARTED";
const MARK_FAIL: &str = "SPLITDISK_PCSCD_FAIL";
const MARK_DRIVER: &str = "SPLITDISK_PCSCD_CCID_BUNDLE_OK";
const MARK_DRIVER_MISS: &str = "SPLITDISK_PCSCD_CCID_BUNDLE_MISSING";

fn log(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
    let _ = std::io::stderr().flush();
}

fn debug_mode() -> bool {
    Path::new("/etc/splitdisk-pcscd-debug").is_file()
}

fn pcscd_path() -> Option<&'static str> {
    ["/usr/sbin/pcscd", "/usr/bin/pcscd", "/sbin/pcscd"]
        .into_iter()
        .find(|&p| Path::new(p).is_file())
}

fn ccid_bundle_present() -> bool {
    Path::new("/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist").is_file()
        && Path::new("/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so").is_file()
}

/// Wait until a USB CCID-like device appears in sysfs (or timeout).
///
/// QEMU's `usb-ccid` enumerates after `/init` is already running. Without
/// udevd, pcscd will not see a hotplug event, so we delay start until the
/// device is visible under `/sys/bus/usb` (test/debug path).
fn wait_for_usb_reader(timeout_ms: u64) {
    let step = Duration::from_millis(100);
    let mut waited = 0u64;
    while waited < timeout_ms {
        if let Ok(rd) = fs::read_dir("/sys/bus/usb/devices") {
            for ent in rd.flatten() {
                let vendor = ent.path().join("idVendor");
                let product = ent.path().join("idProduct");
                let Ok(v) = fs::read_to_string(&vendor) else {
                    continue;
                };
                let Ok(p) = fs::read_to_string(&product) else {
                    continue;
                };
                let v = v.trim().to_ascii_lowercase();
                let p = p.trim().to_ascii_lowercase();
                // QEMU usb-ccid uses Gemalto/Gemplus 08e6:4433; also accept
                // any device whose bInterfaceClass is later probed by libccid.
                if v == "08e6" || p == "4433" {
                    log(&format!(
                        "SPLITDISK_USB_CCID_SYSFS: {} vendor={v} product={p}",
                        ent.file_name().to_string_lossy()
                    ));
                    return;
                }
            }
        }
        thread::sleep(step);
        waited += 100;
    }
    log("SPLITDISK_USB_CCID_SYSFS_TIMEOUT");
}

/// Spawn pcscd in the foreground as a child (stderr inherited for serial logs).
pub fn start_pcscd() -> Result<Child, String> {
    if ccid_bundle_present() {
        log(MARK_DRIVER);
    } else {
        log(MARK_DRIVER_MISS);
    }

    let bin = pcscd_path().ok_or_else(|| {
        let msg = format!("{MARK_FAIL}: pcscd binary not found");
        log(&msg);
        msg
    })?;

    let _ = fs::create_dir_all("/run/pcscd");
    let _ = fs::create_dir_all("/var/run/pcscd");

    let mut cmd = Command::new(bin);
    cmd.arg("--foreground");
    // Test-only: when /etc/splitdisk-pcscd-debug exists (dropped into the
    // initramfs by the QEMU USB-CCID probe), enable verbose IFD/ATR logs on
    // the serial console and wait for the emulated reader to show up.
    // Production images do not include that file.
    if debug_mode() {
        cmd.arg("--debug").arg("--apdu");
        log("SPLITDISK_PCSCD_DEBUG_ENABLED");
        wait_for_usb_reader(10_000);
    }
    let mut child = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            let msg = format!("{MARK_FAIL}: spawn {bin}: {e}");
            log(&msg);
            msg
        })?;

    // Extra settle so ifd-ccid can open the USB device and fetch ATR.
    let settle = if debug_mode() {
        Duration::from_millis(2000)
    } else {
        Duration::from_millis(500)
    };
    thread::sleep(settle);
    match child.try_wait() {
        Ok(Some(status)) => {
            let msg = format!("{MARK_FAIL}: exited early status={status}");
            log(&msg);
            Err(msg)
        }
        Ok(None) => {
            log(MARK_START);
            Ok(child)
        }
        Err(e) => {
            let msg = format!("{MARK_FAIL}: wait: {e}");
            log(&msg);
            Err(msg)
        }
    }
}
