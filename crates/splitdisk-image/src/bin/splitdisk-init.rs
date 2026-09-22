//! Minimal initramfs `/init` (SPEC §10.3): mount `/proc`, `/sys`, tmpfs `/tmp`,
//! then exec `splitdisk-assemble --agent`. No shell.
//!
//! Failures print greppable `SPLITDISK_INIT_FAIL_*` lines to stderr (serial).

use libc::{c_char, c_void, execv, mount, MS_NODEV, MS_NOEXEC, MS_NOSUID};
use std::ffi::CString;
use std::io::Write;
use std::ptr;
use std::thread;
use std::time::Duration;

fn log(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
    let _ = std::io::stderr().flush();
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = writeln!(f, "{msg}");
        let _ = f.flush();
    }
}

fn mount_one(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
    fail_tag: &str,
) -> bool {
    let source_c = CString::new(source).unwrap();
    let target_c = CString::new(target).unwrap();
    let fstype_c = CString::new(fstype).unwrap();
    let data_c = data.map(|d| CString::new(d).unwrap());
    let data_ptr = data_c
        .as_ref()
        .map(|c| c.as_ptr() as *const c_void)
        .unwrap_or(ptr::null());
    // SAFETY: pointers are valid CStrings; mount is the Linux syscall wrapper.
    let rc = unsafe {
        mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            fstype_c.as_ptr(),
            flags,
            data_ptr,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        log(&format!("SPLITDISK_INIT_FAIL_MOUNT_{fail_tag}: {err}"));
        return false;
    }
    true
}

fn hang() -> ! {
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn main() {
    log("SPLITDISK_INIT_STARTING");

    let mut ok = true;
    ok &= mount_one(
        "proc",
        "/proc",
        "proc",
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        None,
        "PROC",
    );
    ok &= mount_one(
        "sysfs",
        "/sys",
        "sysfs",
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        None,
        "SYS",
    );
    ok &= mount_one(
        "tmpfs",
        "/tmp",
        "tmpfs",
        MS_NOSUID | MS_NODEV,
        Some("mode=1777,size=32M"),
        "TMP",
    );
    let _ = std::fs::create_dir_all("/run");
    let _ = mount_one(
        "tmpfs",
        "/run",
        "tmpfs",
        MS_NOSUID | MS_NODEV,
        Some("mode=755,size=8M"),
        "RUN",
    );
    let _ = std::fs::create_dir_all("/run/pcscd");
    let _ = std::fs::create_dir_all("/var/run");

    if !ok {
        log("SPLITDISK_INIT_FAIL_MOUNTS");
        hang();
    }
    log("SPLITDISK_INIT_MOUNTS_OK");

    let assemble = CString::new("/usr/bin/splitdisk-assemble").unwrap_or_else(|_| {
        log("SPLITDISK_INIT_FAIL_PATH");
        hang();
    });
    let agent = CString::new("--agent").unwrap_or_else(|_| {
        log("SPLITDISK_INIT_FAIL_PATH");
        hang();
    });
    let argv: [*const c_char; 3] = [assemble.as_ptr(), agent.as_ptr(), ptr::null()];

    log("SPLITDISK_INIT_EXEC_ASSEMBLE");
    // SAFETY: assemble/agent are valid CStrings; argv is null-terminated.
    let rc = unsafe { execv(assemble.as_ptr(), argv.as_ptr()) };
    let _ = rc;
    let err = std::io::Error::last_os_error();
    log(&format!("SPLITDISK_INIT_FAIL_EXEC: {err}"));
    hang();
}
