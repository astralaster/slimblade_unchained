use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use slimblade_protocol::NormalReport;

const IOC_WRITE: libc::c_ulong = 1;
const IOC_READ: libc::c_ulong = 2;
const USBDEVFS_CONTROL: libc::c_ulong = ((IOC_READ | IOC_WRITE) << 30) | (0x18 << 16) | (0x55 << 8);
const USBDEVFS_DISCONNECT_CLAIM: libc::c_ulong =
    (IOC_READ << 30) | (0x108 << 16) | (0x55 << 8) | 0x1b;
const USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER: u32 = 1;

#[repr(C)]
struct UsbdevfsControlTransfer {
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    timeout_ms: u32,
    data: *mut libc::c_void,
}

#[repr(C)]
struct UsbdevfsDisconnectClaim {
    interface: u32,
    flags: u32,
    driver: [libc::c_char; 256],
}

fn read_decimal(path: &Path) -> io::Result<u16> {
    let value = fs::read_to_string(path)?;
    value
        .trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Resolves a USB sysfs device directory to its usbfs character-device node.
///
/// # Errors
///
/// Returns an error for missing or malformed `busnum` and `devnum` attributes.
pub fn device_node(sysfs_device: &Path) -> io::Result<PathBuf> {
    let bus = read_decimal(&sysfs_device.join("busnum"))?;
    let device = read_decimal(&sysfs_device.join("devnum"))?;
    Ok(PathBuf::from(format!("/dev/bus/usb/{bus:03}/{device:03}")))
}

/// Sends one exact 17-byte HID `SET_REPORT` through usbfs endpoint zero.
///
/// This path does not depend on a functioning hidraw interrupt endpoint.
///
/// # Errors
///
/// Returns open, ioctl, or short-transfer errors.
#[allow(
    unsafe_code,
    reason = "Linux usbfs exposes endpoint-zero control transfers only through ioctl"
)]
pub fn send_normal_report(sysfs_device: &Path, report: NormalReport) -> io::Result<()> {
    let node = device_node(sysfs_device)?;
    let file = open_usbfs(&node)?;
    disconnect_and_claim_vendor_interface(&file)?;
    let mut bytes = *report.as_bytes();
    let mut transfer = UsbdevfsControlTransfer {
        request_type: 0x21,
        request: 0x09,
        value: 0x0208,
        index: 1,
        length: u16::try_from(bytes.len())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        timeout_ms: 500,
        data: bytes.as_mut_ptr().cast(),
    };
    // SAFETY: `transfer` matches the native usbdevfs ABI and its data pointer
    // remains valid and writable for the synchronous ioctl duration.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), USBDEVFS_CONTROL, &raw mut transfer) };
    if result < 0_i32 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(result).ok() != Some(bytes.len()) {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("usbfs transferred {result} of {} bytes", bytes.len()),
        ));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Linux usbfs exposes atomic driver detach and interface claim only through ioctl"
)]
fn disconnect_and_claim_vendor_interface(file: &File) -> io::Result<()> {
    let mut driver = [0; 256];
    driver[..6].copy_from_slice(&[117, 115, 98, 104, 105, 100]);
    let mut claim = UsbdevfsDisconnectClaim {
        interface: 1,
        flags: USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER,
        driver,
    };
    // SAFETY: `claim` exactly matches the native usbdevfs ABI and remains
    // writable for the synchronous ioctl duration.
    let result =
        unsafe { libc::ioctl(file.as_raw_fd(), USBDEVFS_DISCONNECT_CLAIM, &raw mut claim) };
    if result < 0_i32 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_usbfs(node: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(node)
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        USBDEVFS_CONTROL, USBDEVFS_DISCONNECT_CLAIM, UsbdevfsControlTransfer,
        UsbdevfsDisconnectClaim,
    };

    #[test]
    fn native_control_transfer_matches_linux_x86_64_abi() {
        assert_eq!(size_of::<UsbdevfsControlTransfer>(), 24);
        assert_eq!(USBDEVFS_CONTROL, 0xc018_5500);
        assert_eq!(size_of::<UsbdevfsDisconnectClaim>(), 264);
        assert_eq!(USBDEVFS_DISCONNECT_CLAIM, 0x8108_551b);
    }
}
