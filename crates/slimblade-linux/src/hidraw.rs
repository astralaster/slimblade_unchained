use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread;

use core::time::Duration;
use std::time::Instant;

use slimblade_protocol::{
    BOOT_REPORT_LENGTH, BootReport, NORMAL_REPORT_LENGTH, NormalReport, UsbIdentity,
};

const HIDIOCGRAWINFO: libc::c_ulong = 0x8008_4803;
const HIDIOCGRDESCSIZE: libc::c_ulong = 0x8004_4801;
const HIDIOCGRDESC: libc::c_ulong = 0x9004_4802;
const READ_BUFFER_LENGTH: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RawInfo {
    bus_type: u32,
    vendor: u16,
    product: u16,
}

#[repr(C)]
struct RawDescriptor {
    size: u32,
    value: [u8; READ_BUFFER_LENGTH],
}

#[derive(Debug)]
pub struct Hidraw {
    file: File,
}

impl Hidraw {
    /// Opens a hidraw node without write access.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error from opening the node.
    pub fn open_read_only(path: &Path) -> io::Result<Self> {
        Self::open(path, false)
    }

    /// Opens a hidraw node for loader queries and writes.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error from opening the node.
    pub fn open_read_write(path: &Path) -> io::Result<Self> {
        Self::open(path, true)
    }

    fn open(path: &Path, write: bool) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        Ok(Self { file })
    }

    /// Reads the kernel-reported HID bus and USB identity.
    ///
    /// # Errors
    ///
    /// Returns an ioctl error if the file is not a usable hidraw node.
    #[allow(
        unsafe_code,
        reason = "Linux hidraw identity queries require the ioctl system call"
    )]
    pub fn identity(&self) -> io::Result<(u32, UsbIdentity)> {
        let mut info = RawInfo::default();
        // SAFETY: `info` is a live, writable `RawInfo`, its layout matches
        // `hidraw_devinfo`, and the file descriptor remains owned by `self`.
        let result = unsafe { libc::ioctl(self.file.as_raw_fd(), HIDIOCGRAWINFO, &raw mut info) };
        if result < 0_i32 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            info.bus_type,
            UsbIdentity {
                vendor_id: info.vendor,
                product_id: info.product,
            },
        ))
    }

    /// Reads the HID report descriptor through the kernel's bounded hidraw ioctl.
    ///
    /// # Errors
    ///
    /// Returns an ioctl error or rejects a kernel-reported size above 4096 bytes.
    #[allow(
        unsafe_code,
        reason = "Linux HID report-descriptor queries require ioctl system calls"
    )]
    pub fn report_descriptor(&self) -> io::Result<Vec<u8>> {
        let mut size = 0_u32;
        // SAFETY: `size` is a live writable `u32`, and the descriptor-size
        // ioctl writes exactly that kernel ABI type.
        let size_result =
            unsafe { libc::ioctl(self.file.as_raw_fd(), HIDIOCGRDESCSIZE, &raw mut size) };
        if size_result < 0_i32 {
            return Err(io::Error::last_os_error());
        }
        let size = usize::try_from(size)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if size > READ_BUFFER_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("kernel returned invalid report descriptor size {size}"),
            ));
        }
        let mut descriptor = RawDescriptor {
            size: u32::try_from(size)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            value: [0_u8; READ_BUFFER_LENGTH],
        };
        // SAFETY: `descriptor` exactly matches `hidraw_report_descriptor`, is
        // writable for the ioctl duration, and advertises at most 4096 bytes.
        let descriptor_result =
            unsafe { libc::ioctl(self.file.as_raw_fd(), HIDIOCGRDESC, &raw mut descriptor) };
        if descriptor_result < 0_i32 {
            return Err(io::Error::last_os_error());
        }
        let returned = usize::try_from(descriptor.size)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        descriptor
            .value
            .get(..returned)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("kernel returned invalid report descriptor size {returned}"),
                )
            })
    }

    /// Issues one HID output report and rejects a short write.
    ///
    /// # Errors
    ///
    /// Returns an I/O error from the device or for a short report write.
    pub fn write_report(&mut self, report: &[u8]) -> io::Result<()> {
        let written = self.file.write(report)?;
        if written != report.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short HID write: {written} of {} bytes", report.len()),
            ));
        }
        Ok(())
    }

    /// Waits for the next well-formed bootloader report.
    ///
    /// Unrelated input reports are ignored until the deadline.
    ///
    /// # Errors
    ///
    /// Returns non-retryable read errors from the hidraw node.
    pub fn read_boot_report(&mut self, timeout: Duration) -> io::Result<Option<BootReport>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
        let mut buffer = [0_u8; READ_BUFFER_LENGTH];
        loop {
            match self.file.read(&mut buffer) {
                Ok(0) => return Ok(None),
                Ok(length) => {
                    if length == BOOT_REPORT_LENGTH
                        && let Some(bytes) = buffer.get(..length)
                        && let Ok(report) = BootReport::parse(bytes)
                    {
                        return Ok(Some(report));
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }

    /// Waits for the next well-formed normal-mode vendor report.
    ///
    /// Unrelated input reports are ignored until the deadline.
    ///
    /// # Errors
    ///
    /// Returns non-retryable read errors from the hidraw node.
    pub fn read_normal_report(&mut self, timeout: Duration) -> io::Result<Option<NormalReport>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
        let mut buffer = [0_u8; READ_BUFFER_LENGTH];
        loop {
            match self.file.read(&mut buffer) {
                Ok(0) => return Ok(None),
                Ok(length) => {
                    if length == NORMAL_REPORT_LENGTH
                        && let Some(bytes) = buffer.get(..length)
                        && let Ok(report) = NormalReport::parse(bytes)
                    {
                        return Ok(Some(report));
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }
}
