#[cfg(test)]
extern crate alloc;

use core::fmt;

use slimblade_protocol::{BOOT_IDENTITIES, BootReport, KENSINGTON_WIRED_IDENTITY, UsbIdentity};

pub mod flash;
pub mod hidraw;
pub mod sysfs;
pub mod usbfs;

pub const RECOVERY_CARRIER_BCD_DEVICE: &str = "0451";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsbDevice {
    pub sysfs: String,
    pub identity: UsbIdentity,
    pub bcd_device: Option<String>,
    pub devnum: Option<String>,
}

impl UsbDevice {
    #[must_use]
    pub fn is_bootloader(&self) -> bool {
        BOOT_IDENTITIES.contains(&self.identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierIdentityError {
    WrongHidIdentity { actual: UsbIdentity },
    MissingUsbParent,
    ParentMismatch { actual: UsbIdentity },
    WrongDeviceVersion,
}

impl fmt::Display for CarrierIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongHidIdentity { actual } => write!(
                formatter,
                "HID identity is {:04x}:{:04x}, expected recovery carrier",
                actual.vendor_id, actual.product_id
            ),
            Self::MissingUsbParent => formatter.write_str("could not resolve USB parent"),
            Self::ParentMismatch { actual } => write!(
                formatter,
                "USB parent is {:04x}:{:04x}, expected recovery carrier",
                actual.vendor_id, actual.product_id
            ),
            Self::WrongDeviceVersion => {
                formatter.write_str("USB parent does not have recovery-carrier bcdDevice 0451")
            },
        }
    }
}

impl core::error::Error for CarrierIdentityError {}

/// Requires matching HID and USB-parent identities plus carrier version 4.51.
///
/// # Errors
///
/// Returns an error for a wrong HID identity, missing/mismatched parent, or wrong version.
pub fn require_recovery_carrier(
    hid_identity: UsbIdentity,
    usb_parent: Option<&UsbDevice>,
) -> Result<&UsbDevice, CarrierIdentityError> {
    if hid_identity != KENSINGTON_WIRED_IDENTITY {
        return Err(CarrierIdentityError::WrongHidIdentity {
            actual: hid_identity,
        });
    }
    let parent = usb_parent.ok_or(CarrierIdentityError::MissingUsbParent)?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY {
        return Err(CarrierIdentityError::ParentMismatch {
            actual: parent.identity,
        });
    }
    if parent.bcd_device.as_deref() != Some(RECOVERY_CARRIER_BCD_DEVICE) {
        return Err(CarrierIdentityError::WrongDeviceVersion);
    }
    Ok(parent)
}

/// Requires the previous USB path to disappear without any replacement appearing.
#[must_use]
pub fn observe_expected_usb_silence(previous: &UsbDevice, snapshots: &[Vec<UsbDevice>]) -> bool {
    let mut saw_absence = false;
    for snapshot in snapshots {
        let same_path = snapshot
            .iter()
            .find(|device| device.sysfs == previous.sysfs);
        if same_path.is_none() {
            saw_absence = true;
        } else if saw_absence {
            return false;
        }
    }
    saw_absence
}

/// Finds a new resident-loader instance on the previous physical USB path.
#[must_use]
pub fn boot_reenumeration<'snapshots>(
    previous: &UsbDevice,
    snapshots: &'snapshots [Vec<UsbDevice>],
) -> Option<&'snapshots UsbDevice> {
    let mut saw_absence = false;
    for snapshot in snapshots {
        let same_path = snapshot
            .iter()
            .find(|device| device.sysfs == previous.sysfs && device.is_bootloader());
        match same_path {
            None => saw_absence = true,
            Some(device) if saw_absence || device.devnum != previous.devnum => return Some(device),
            Some(_) => {},
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryError {
    Io,
    UnexpectedProtocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashStartError {
    LoaderUnavailable,
    UnexpectedProtocol,
    PrepareFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareError;

pub trait LoaderBackend {
    type Session;

    /// Opens a recognized loader and completes its non-writing `B2/d2` query.
    ///
    /// # Errors
    ///
    /// Distinguishes retryable I/O disappearance from a non-retryable protocol mismatch.
    fn open_queried(&mut self) -> Result<Self::Session, QueryError>;
    /// Sends the prepare/erase report, crossing the no-retry boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for a failed or short report write.
    fn write_prepare(
        &mut self,
        session: &mut Self::Session,
        packet: &BootReport,
    ) -> Result<(), PrepareError>;
}

/// Retries only discovery/query failures, then crosses the erase boundary exactly once.
///
/// # Errors
///
/// Returns without writing if discovery is exhausted, immediately on protocol mismatch, and
/// without reopening after the prepare write has been attempted.
pub fn begin_flash<B: LoaderBackend>(
    backend: &mut B,
    attempts: usize,
    prepare: &BootReport,
) -> Result<B::Session, FlashStartError> {
    let mut session = None;
    for _ in 0..attempts {
        match backend.open_queried() {
            Ok(opened) => {
                session = Some(opened);
                break;
            },
            Err(QueryError::Io) => {},
            Err(QueryError::UnexpectedProtocol) => {
                return Err(FlashStartError::UnexpectedProtocol);
            },
        }
    }
    let mut session = session.ok_or(FlashStartError::LoaderUnavailable)?;
    backend
        .write_prepare(&mut session, prepare)
        .map_err(|PrepareError| FlashStartError::PrepareFailed)?;
    Ok(session)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests expect scripted successful state transitions as assertions"
)]
mod tests {
    use super::*;

    fn device(identity: UsbIdentity, devnum: &str) -> UsbDevice {
        UsbDevice {
            sysfs: "/sys/devices/fake".to_owned(),
            identity,
            bcd_device: None,
            devnum: Some(devnum.to_owned()),
        }
    }

    #[test]
    fn carrier_identity_requires_bcd_451() {
        let mut parent = device(KENSINGTON_WIRED_IDENTITY, "30");
        parent.bcd_device = Some("0450".to_owned());
        assert_eq!(
            require_recovery_carrier(KENSINGTON_WIRED_IDENTITY, Some(&parent)),
            Err(CarrierIdentityError::WrongDeviceVersion)
        );
    }

    #[test]
    fn carrier_identity_accepts_bcd_451() {
        let mut parent = device(KENSINGTON_WIRED_IDENTITY, "30");
        parent.bcd_device = Some("0451".to_owned());
        assert_eq!(
            require_recovery_carrier(KENSINGTON_WIRED_IDENTITY, Some(&parent)),
            Ok(&parent)
        );
    }

    #[test]
    fn guard_silence_requires_disappearance_without_reenumeration() {
        let previous = device(BOOT_IDENTITIES[0], "30");
        assert!(observe_expected_usb_silence(
            &previous,
            &[vec![previous.clone()], vec![], vec![]]
        ));
    }

    #[test]
    fn guard_silence_rejects_reenumeration() {
        let previous = device(BOOT_IDENTITIES[0], "30");
        let replacement = device(KENSINGTON_WIRED_IDENTITY, "31");
        assert!(!observe_expected_usb_silence(
            &previous,
            &[vec![], vec![replacement]]
        ));
    }

    #[test]
    fn stub_result_requires_changed_loader_device_number() {
        let previous = device(BOOT_IDENTITIES[0], "30");
        let old = previous.clone();
        let new = device(BOOT_IDENTITIES[0], "31");
        assert_eq!(
            boot_reenumeration(&previous, &[vec![old], vec![new.clone()]]),
            Some(&new)
        );
    }

    struct ScriptedBackend {
        opens: Vec<Result<u8, QueryError>>,
        next_open: usize,
        open_count: usize,
        write_count: usize,
        prepare_result: Result<(), PrepareError>,
    }

    impl LoaderBackend for ScriptedBackend {
        type Session = u8;

        fn open_queried(&mut self) -> Result<Self::Session, QueryError> {
            self.open_count += 1;
            let result = self
                .opens
                .get(self.next_open)
                .copied()
                .unwrap_or(Err(QueryError::Io));
            self.next_open += 1;
            result
        }

        fn write_prepare(
            &mut self,
            _session: &mut Self::Session,
            _packet: &BootReport,
        ) -> Result<(), PrepareError> {
            self.write_count += 1;
            self.prepare_result
        }
    }

    fn backend(opens: impl IntoIterator<Item = Result<u8, QueryError>>) -> ScriptedBackend {
        ScriptedBackend {
            opens: opens.into_iter().collect(),
            next_open: 0,
            open_count: 0,
            write_count: 0,
            prepare_result: Ok(()),
        }
    }

    #[test]
    fn pre_erase_wait_retries_disappearing_loader() {
        let mut backend = backend([Err(QueryError::Io), Ok(12)]);
        assert_eq!(
            begin_flash(&mut backend, 2, &BootReport::prepare(32, 0)),
            Ok(12)
        );
        assert_eq!(backend.open_count, 2);
        assert_eq!(backend.write_count, 1);
    }

    #[test]
    fn unexpected_loader_protocol_is_not_retried() {
        let mut backend = backend([Err(QueryError::UnexpectedProtocol), Ok(12)]);
        assert_eq!(
            begin_flash(&mut backend, 2, &BootReport::prepare(32, 0)),
            Err(FlashStartError::UnexpectedProtocol)
        );
        assert_eq!(backend.open_count, 1);
        assert_eq!(backend.write_count, 0);
    }

    #[test]
    fn no_erase_when_loader_never_opens() {
        let mut backend = backend([Err(QueryError::Io), Err(QueryError::Io)]);
        assert_eq!(
            begin_flash(&mut backend, 2, &BootReport::prepare(32, 0)),
            Err(FlashStartError::LoaderUnavailable)
        );
        assert_eq!(backend.write_count, 0);
    }

    #[test]
    fn b0_failure_is_not_automatically_retried() {
        let mut backend = backend([Ok(12), Ok(13)]);
        backend.prepare_result = Err(PrepareError);
        assert_eq!(
            begin_flash(&mut backend, 2, &BootReport::prepare(32, 0)),
            Err(FlashStartError::PrepareFailed)
        );
        assert_eq!(backend.open_count, 1);
        assert_eq!(backend.write_count, 1);
    }

    #[test]
    fn stable_symlinks_are_scoped_to_correct_interfaces() {
        let rules = include_str!("../../../udev/70-slimblade-research.rules");
        assert!(rules.contains(r#"ENV{ID_USB_INTERFACE_NUM}=="01""#));
        assert!(rules.contains(r#"SYMLINK+="slimblade-vendor""#));
        assert_eq!(rules.matches(r#"SYMLINK+="slimblade-loader""#).count(), 3);
    }
}
