use core::fmt;
use core::time::Duration;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use slimblade_protocol::{BOOT_IDENTITIES, BootReport, DOWNLOAD_BLOCK_LENGTH, updater_crc32};

use crate::UsbDevice;
use crate::hidraw::Hidraw;
use crate::sysfs::{HIDRAW_SYSFS_ROOT, loader_candidate_paths, usb_parent_for_hidraw};

#[derive(Debug)]
pub struct QueriedLoader {
    pub path: PathBuf,
    pub usb_parent: UsbDevice,
    transport: Hidraw,
}

impl QueriedLoader {
    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut Hidraw {
        &mut self.transport
    }
}

#[derive(Debug)]
pub enum LoaderOpenError {
    Io(io::Error),
    UnexpectedProtocol(&'static str),
    Unavailable(String),
}

impl fmt::Display for LoaderOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "loader I/O failed: {error}"),
            Self::UnexpectedProtocol(message) => formatter.write_str(message),
            Self::Unavailable(message) => {
                write!(formatter, "loader unavailable before erase: {message}")
            },
        }
    }
}

impl core::error::Error for LoaderOpenError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnexpectedProtocol(_) | Self::Unavailable(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferStage {
    PrepareWrite,
    PrepareResponse,
    DownloadWrite { block: usize },
    DownloadEcho { block: usize },
}

#[derive(Debug)]
pub enum TransferError<E> {
    PayloadTooLarge,
    Transport { stage: TransferStage, source: E },
    PrepareIncomplete,
    UnknownEraseStatus(u8),
    PacketConstruction { block: usize },
    IncorrectEcho { block: usize },
}

impl<E: fmt::Display> fmt::Display for TransferError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => {
                formatter.write_str("payload length does not fit loader protocol")
            },
            Self::Transport { stage, source } => {
                write!(formatter, "transport failed at {stage:?}: {source}")
            },
            Self::PrepareIncomplete => {
                formatter.write_str("loader did not complete prepare/erase phase")
            },
            Self::UnknownEraseStatus(status) => write!(
                formatter,
                "loader returned unknown erase status {status:02x}"
            ),
            Self::PacketConstruction { block } => {
                write!(formatter, "could not construct download block {block}")
            },
            Self::IncorrectEcho { block } => {
                write!(formatter, "download block {block} was not echoed exactly")
            },
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for TransferError<E> {}

pub trait BootTransport {
    type Error;

    /// Issues exactly one report write.
    ///
    /// # Errors
    ///
    /// Returns transport-specific errors, including short writes.
    fn write(&mut self, report: &BootReport) -> Result<(), Self::Error>;

    /// Reads one bootloader report before the supplied timeout.
    ///
    /// # Errors
    ///
    /// Returns transport-specific read errors.
    fn read(&mut self, timeout: Duration) -> Result<Option<BootReport>, Self::Error>;
}

impl BootTransport for Hidraw {
    type Error = io::Error;

    fn write(&mut self, report: &BootReport) -> Result<(), Self::Error> {
        self.write_report(report.as_bytes())
    }

    fn read(&mut self, timeout: Duration) -> Result<Option<BootReport>, Self::Error> {
        self.read_boot_report(timeout)
    }
}

/// Performs the single-attempt erase and complete block transfer on an already queried loader.
///
/// No operation in this function retries a write. In particular, any error after the `B0` write
/// is returned to the caller without reopening the loader.
///
/// # Errors
///
/// Returns the exact stage at which transport or protocol verification failed.
pub fn transfer_payload<T, F>(
    transport: &mut T,
    payload: &[u8],
    timeout: Duration,
    mut progress: F,
) -> Result<usize, TransferError<T::Error>>
where
    T: BootTransport,
    F: FnMut(usize, usize),
{
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| TransferError::PayloadTooLarge)?;
    let prepare = BootReport::prepare(payload_length, updater_crc32(payload));
    transport
        .write(&prepare)
        .map_err(|source| TransferError::Transport {
            stage: TransferStage::PrepareWrite,
            source,
        })?;

    let prepare_timeout = timeout.max(Duration::from_secs(15));
    let deadline = Instant::now()
        .checked_add(prepare_timeout)
        .ok_or(TransferError::PrepareIncomplete)?;
    let mut saw_echo = false;
    let mut saw_complete = false;
    while Instant::now() < deadline {
        let response = transport
            .read(deadline.saturating_duration_since(Instant::now()))
            .map_err(|source| TransferError::Transport {
                stage: TransferStage::PrepareResponse,
                source,
            })?;
        let Some(response) = response else {
            break;
        };
        let bytes = response.as_bytes();
        if response.command_byte() == 0xb0 {
            saw_echo = true;
            continue;
        }
        if bytes.get(1..3) == Some(&[0x5b, 0xb5]) && bytes.get(3) == Some(&0x02) {
            match bytes.get(4).copied() {
                Some(0x00) => {},
                Some(0x01) => {
                    saw_complete = true;
                    break;
                },
                Some(status) => return Err(TransferError::UnknownEraseStatus(status)),
                None => return Err(TransferError::PrepareIncomplete),
            }
        }
    }
    if !saw_echo || !saw_complete {
        return Err(TransferError::PrepareIncomplete);
    }

    let block_count = payload.len().div_ceil(DOWNLOAD_BLOCK_LENGTH);
    for (zero_based, offset) in (0..payload.len())
        .step_by(DOWNLOAD_BLOCK_LENGTH)
        .enumerate()
    {
        let block = zero_based + 1;
        let packet = BootReport::download(payload, offset)
            .map_err(|_| TransferError::PacketConstruction { block })?;
        transport
            .write(&packet)
            .map_err(|source| TransferError::Transport {
                stage: TransferStage::DownloadWrite { block },
                source,
            })?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(TransferError::IncorrectEcho { block })?;
        let echoed = loop {
            let candidate = transport
                .read(deadline.saturating_duration_since(Instant::now()))
                .map_err(|source| TransferError::Transport {
                    stage: TransferStage::DownloadEcho { block },
                    source,
                })?;
            let Some(candidate) = candidate else {
                break None;
            };
            if candidate.command_byte() == 0xb1 {
                break Some(candidate);
            }
            if Instant::now() >= deadline {
                break None;
            }
        };
        if echoed != Some(packet) {
            return Err(TransferError::IncorrectEcho { block });
        }
        progress(block, block_count);
    }
    Ok(block_count)
}

fn open_queried_candidate(
    path: &Path,
    timeout: Duration,
) -> Result<Option<QueriedLoader>, LoaderOpenError> {
    let Some(parent) =
        usb_parent_for_hidraw(path, Path::new(HIDRAW_SYSFS_ROOT)).map_err(LoaderOpenError::Io)?
    else {
        return Ok(None);
    };
    if !BOOT_IDENTITIES.contains(&parent.identity) {
        return Ok(None);
    }
    let mut hidraw = Hidraw::open_read_write(path).map_err(LoaderOpenError::Io)?;
    let (_, identity) = hidraw.identity().map_err(LoaderOpenError::Io)?;
    if !BOOT_IDENTITIES.contains(&identity) {
        return Ok(None);
    }
    if parent.identity != identity {
        return Err(LoaderOpenError::UnexpectedProtocol(
            "hidraw loader identity and USB parent disagree",
        ));
    }
    hidraw
        .write_report(BootReport::query().as_bytes())
        .map_err(LoaderOpenError::Io)?;
    let response = hidraw
        .read_boot_report(timeout)
        .map_err(LoaderOpenError::Io)?;
    let Some(response) = response else {
        return Err(LoaderOpenError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "loader disappeared or did not answer B2",
        )));
    };
    if response.command_byte() != 0xb2 || response.as_bytes().get(2) != Some(&0xd2) {
        return Err(LoaderOpenError::UnexpectedProtocol(
            "loader returned an unexpected B2 device type",
        ));
    }
    Ok(Some(QueriedLoader {
        path: path.to_path_buf(),
        usb_parent: parent,
        transport: hidraw,
    }))
}

/// Finds, opens, and proves a BK3635 `d2` loader before any erase attempt.
///
/// I/O disappearance is retried only within this pre-erase function. A protocol mismatch is
/// returned immediately.
///
/// # Errors
///
/// Returns an I/O, protocol, or bounded-discovery failure.
pub fn wait_for_queried_loader(
    preferred: &Path,
    timeout: Duration,
) -> Result<QueriedLoader, LoaderOpenError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| LoaderOpenError::Unavailable("timeout overflow".to_owned()))?;
    let mut last_error = "no recognized loader hidraw node appeared".to_owned();
    while Instant::now() < deadline {
        let candidates =
            loader_candidate_paths(preferred, Path::new("/dev")).map_err(LoaderOpenError::Io)?;
        for candidate in candidates {
            let query_timeout = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(1))
                .max(Duration::from_millis(50));
            match open_queried_candidate(&candidate, query_timeout) {
                Ok(Some(session)) => return Ok(session),
                Ok(None) => {},
                Err(LoaderOpenError::Io(error)) => last_error = error.to_string(),
                Err(
                    error @ (LoaderOpenError::UnexpectedProtocol(_)
                    | LoaderOpenError::Unavailable(_)),
                ) => return Err(error),
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(LoaderOpenError::Unavailable(last_error))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "scripted protocol tests require successful setup"
)]
mod tests {
    use alloc::collections::VecDeque;
    use core::convert::Infallible;

    use super::*;

    #[derive(Debug)]
    struct ScriptedTransport {
        reads: VecDeque<Option<BootReport>>,
        writes: Vec<BootReport>,
        corrupt_block: Option<usize>,
    }

    impl BootTransport for ScriptedTransport {
        type Error = Infallible;

        fn write(&mut self, report: &BootReport) -> Result<(), Self::Error> {
            self.writes.push(*report);
            if report.command_byte() == 0xb1 {
                let block = self.writes.len() - 1;
                let echo = if self.corrupt_block == Some(block) {
                    BootReport::command(0xb1)
                } else {
                    *report
                };
                self.reads.push_back(Some(echo));
            }
            Ok(())
        }

        fn read(&mut self, _timeout: Duration) -> Result<Option<BootReport>, Self::Error> {
            Ok(self.reads.pop_front().flatten())
        }
    }

    fn erase_status(status: u8) -> BootReport {
        let mut bytes = [0_u8; 49];
        bytes[0] = 0x06;
        bytes[1] = 0x5b;
        bytes[2] = 0xb5;
        bytes[3] = 0x02;
        bytes[4] = status;
        BootReport::parse(&bytes).expect("fixed status report is valid")
    }

    fn transport(corrupt_block: Option<usize>) -> ScriptedTransport {
        ScriptedTransport {
            reads: VecDeque::from([
                Some(BootReport::prepare(64, 0)),
                Some(erase_status(0)),
                Some(erase_status(1)),
            ]),
            writes: Vec::new(),
            corrupt_block,
        }
    }

    #[test]
    fn full_official_geometry_writes_and_verifies_all_3748_blocks() {
        let payload = vec![0x5a; 119_920];
        let mut transport = transport(None);
        let mut last_progress = None;
        let blocks = transfer_payload(
            &mut transport,
            &payload,
            Duration::from_millis(1),
            |done, total| last_progress = Some((done, total)),
        )
        .expect("scripted transfer succeeds");
        assert_eq!(blocks, 3_748);
        assert_eq!(last_progress, Some((3_748, 3_748)));
        assert_eq!(transport.writes.len(), 3_749);
        assert_eq!(
            transport.writes.first().map(|report| report.command_byte()),
            Some(0xb0)
        );
        assert_eq!(
            transport
                .writes
                .last()
                .and_then(|report| report.as_bytes().get(2).copied()),
            Some(0xc1)
        );
    }

    #[test]
    fn incorrect_echo_stops_without_rewriting_block() {
        let payload = vec![0x5a; 96];
        let mut transport = transport(Some(2));
        assert!(matches!(
            transfer_payload(
                &mut transport,
                &payload,
                Duration::from_millis(1),
                |_, _| {}
            ),
            Err(TransferError::IncorrectEcho { block: 2 })
        ));
        assert_eq!(transport.writes.len(), 3);
    }

    #[test]
    fn prepare_requires_echo_and_completed_status() {
        let mut transport = ScriptedTransport {
            reads: VecDeque::from([Some(erase_status(1))]),
            writes: Vec::new(),
            corrupt_block: None,
        };
        assert!(matches!(
            transfer_payload(&mut transport, &[1], Duration::from_millis(1), |_, _| {}),
            Err(TransferError::PrepareIncomplete)
        ));
        assert_eq!(transport.writes.len(), 1);
    }
}
