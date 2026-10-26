use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use core::time::Duration;

use slimblade_protocol::UsbIdentity;

use crate::UsbDevice;

pub const USB_SYSFS_ROOT: &str = "/sys/bus/usb/devices";
pub const HIDRAW_SYSFS_ROOT: &str = "/sys/class/hidraw";

fn read_trimmed(path: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn read_hex_u16(path: &Path) -> io::Result<u16> {
    let value = read_trimmed(path)?;
    u16::from_str_radix(&value, 16)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Reads one USB device directory, returning `None` for non-device entries.
///
/// # Errors
///
/// Returns malformed identity fields and filesystem failures after an identity is present.
pub fn usb_device_from_directory(directory: &Path) -> io::Result<Option<UsbDevice>> {
    let vendor_path = directory.join("idVendor");
    let product_path = directory.join("idProduct");
    if !vendor_path.is_file() || !product_path.is_file() {
        return Ok(None);
    }
    let canonical = fs::canonicalize(directory)?;
    Ok(Some(UsbDevice {
        sysfs: canonical.to_string_lossy().into_owned(),
        identity: UsbIdentity {
            vendor_id: read_hex_u16(&vendor_path)?,
            product_id: read_hex_u16(&product_path)?,
        },
        bcd_device: read_trimmed(&directory.join("bcdDevice")).ok(),
        devnum: read_trimmed(&directory.join("devnum")).ok(),
    }))
}

/// Enumerates all current USB device identities.
///
/// # Errors
///
/// Returns an error if the USB sysfs directory cannot be read.
pub fn usb_devices(root: &Path) -> io::Result<Vec<UsbDevice>> {
    let mut devices = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if let Some(device) = usb_device_from_directory(&entry.path())? {
            devices.push(device);
        }
    }
    Ok(devices)
}

/// Resolves the USB parent corresponding to one hidraw node.
///
/// # Errors
///
/// Returns path-resolution and malformed-sysfs errors.
pub fn usb_parent_for_hidraw(device: &Path, hidraw_root: &Path) -> io::Result<Option<UsbDevice>> {
    let actual = fs::canonicalize(device)?;
    let name = actual
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hidraw path has no name"))?;
    let mut directory = fs::canonicalize(hidraw_root.join(name).join("device"))?;
    loop {
        if let Some(parent) = usb_device_from_directory(&directory)? {
            return Ok(Some(parent));
        }
        if !directory.pop() {
            return Ok(None);
        }
    }
}

/// Returns distinct current hidraw nodes, preferring the requested and stable paths.
///
/// # Errors
///
/// Returns an error only if `/dev` itself cannot be read.
pub fn loader_candidate_paths(preferred: &Path, dev_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut requested = vec![preferred.to_path_buf(), dev_root.join("slimblade-loader")];
    for entry in fs::read_dir(dev_root)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hidraw"))
        {
            requested.push(path);
        }
    }
    let mut candidates = Vec::new();
    for path in requested {
        let Ok(resolved) = fs::canonicalize(path) else {
            continue;
        };
        if !resolved
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hidraw"))
            || candidates.contains(&resolved)
        {
            continue;
        }
        candidates.push(resolved);
    }
    Ok(candidates)
}

/// Waits for a matching USB identity at one physical sysfs path.
///
/// # Errors
///
/// Returns sysfs enumeration errors.
pub fn wait_for_identity_at_path(
    sysfs_path: &str,
    identities: &[UsbIdentity],
    timeout: Duration,
) -> io::Result<Option<UsbDevice>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
    while Instant::now() < deadline {
        if let Some(device) = usb_devices(Path::new(USB_SYSFS_ROOT))?
            .into_iter()
            .find(|device| device.sysfs == sysfs_path && identities.contains(&device.identity))
        {
            return Ok(Some(device));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(None)
}

/// Requires a USB device to disappear from its physical path and remain absent.
///
/// # Errors
///
/// Returns sysfs enumeration errors.
pub fn observe_usb_silence(previous: &UsbDevice, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
    let mut saw_absence = false;
    while Instant::now() < deadline {
        let present = usb_devices(Path::new(USB_SYSFS_ROOT))?
            .iter()
            .any(|device| device.sysfs == previous.sysfs);
        if !present {
            saw_absence = true;
        } else if saw_absence {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(saw_absence)
}

/// Waits for a new matching enumeration at the same physical path.
///
/// A same-identity result is accepted only after absence or a changed USB
/// device number, preventing the pre-flash instance from satisfying recovery.
///
/// # Errors
///
/// Returns sysfs enumeration errors.
pub fn wait_for_reenumeration(
    previous: &UsbDevice,
    identities: &[UsbIdentity],
    timeout: Duration,
) -> io::Result<Option<UsbDevice>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
    let mut saw_absence = false;
    while Instant::now() < deadline {
        let current = usb_devices(Path::new(USB_SYSFS_ROOT))?
            .into_iter()
            .find(|device| device.sysfs == previous.sysfs && identities.contains(&device.identity));
        match current {
            None => saw_absence = true,
            Some(device)
                if saw_absence
                    || device.devnum != previous.devnum
                    || device.identity != previous.identity =>
            {
                return Ok(Some(device));
            },
            Some(_) => {},
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(None)
}
