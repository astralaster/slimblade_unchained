use core::fmt;

use slimblade_image::{
    APPLICATION_CODE_OFFSET, APPLICATION_HEADER_OFFSET, FirmwareIdentityError, ImageError,
    RECOVERY_GUARD, RECOVERY_GUARD_ARTIFACT, RECOVERY_STUB, refresh_header_crc, sha256,
};

use crate::{BranchError, ThumbAddress, decode_thumb_bl, encode_thumb_bl};

pub const LIVE_STUB_CODE_END: usize = 0x21c4;
pub const FINAL_ACTION_CALL: usize = 0x20b6;
pub const EXPERIMENT_ENTRY: usize = LIVE_STUB_CODE_END;
pub const EXPERIMENT_CODE: [u8; 2] = [0xfe, 0xe7];
pub const GUARD_CODE_END: usize = EXPERIMENT_ENTRY + EXPERIMENT_CODE.len();
pub const EXPECTED_DIFFERENCES: [usize; 7] =
    [0x2010, 0x2011, 0x2012, 0x2013, 0x20b8, 0x21c4, 0x21c5];

const PERSISTENT_CONTROLLER_START: u32 = 0x0080_3000;
const PERSISTENT_CONTROLLER_END: u32 = 0x0080_3100;
const PERSISTENT_WORD_ADDRESSES: [u32; 3] = [0x0000_8000, 0x0000_807c, 0x0000_807d];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    StubIdentity(FirmwareIdentityError),
    ExperimentEntryNotErased,
    Branch(BranchError),
    ImageLayout,
    Image(ImageError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StubIdentity(error) => write!(formatter, "live-proven recovery stub: {error}"),
            Self::ExperimentEntryNotErased => {
                formatter.write_str("experimental entry is not erased padding")
            },
            Self::Branch(error) => write!(formatter, "experiment branch: {error}"),
            Self::ImageLayout => formatter.write_str("recovery-stub image layout is truncated"),
            Self::Image(error) => write!(formatter, "application image: {error}"),
        }
    }
}

impl core::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::StubIdentity(error) => Some(error),
            Self::Branch(error) => Some(error),
            Self::Image(error) => Some(error),
            Self::ExperimentEntryNotErased | Self::ImageLayout => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IsolationError {
    InvalidRange {
        start: usize,
        end: usize,
        size: usize,
    },
    PersistentAddress {
        offset: usize,
        value: u32,
    },
    CallOutsideRange {
        source: usize,
        target: u32,
    },
    IndirectBranchLink {
        address: usize,
    },
    SoftwareInterrupt {
        address: usize,
    },
    WordUnavailable {
        offset: usize,
    },
    Branch(BranchError),
}

impl fmt::Display for IsolationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange { start, end, size } => write!(
                formatter,
                "experimental range {start:#x}..{end:#x} is invalid for {size:#x} bytes"
            ),
            Self::PersistentAddress { offset, value } => write!(
                formatter,
                "experiment contains persistent-storage address {value:#010x} at {offset:#x}"
            ),
            Self::CallOutsideRange { source, target } => write!(
                formatter,
                "experiment call at {source:#x} targets outside its isolated range: {target:#x}"
            ),
            Self::IndirectBranchLink { address } => {
                write!(
                    formatter,
                    "experiment contains an indirect Thumb BLX at {address:#x}"
                )
            },
            Self::SoftwareInterrupt { address } => {
                write!(
                    formatter,
                    "experiment contains a Thumb software interrupt at {address:#x}"
                )
            },
            Self::WordUnavailable { offset } => write!(formatter, "no word at {offset:#x}"),
            Self::Branch(error) => write!(formatter, "Thumb branch: {error}"),
        }
    }
}

impl core::error::Error for IsolationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Branch(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    StubIdentity(FirmwareIdentityError),
    Build(BuildError),
    DerivedGuard,
    RawGuardCode,
    EmbeddedCode,
    DifferenceSet { actual: Vec<usize> },
    MarkerFirstPrefix,
    SupportRoutines,
    LiveFinalTarget { actual: u32 },
    ExperimentTarget { actual: u32 },
    ExperimentCode,
    Isolation(IsolationError),
    ErasedPadding,
    Image(ImageError),
    HeaderCrc,
    CodeIdentity,
    GuardIdentity(FirmwareIdentityError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StubIdentity(error) => write!(formatter, "live-proven recovery stub: {error}"),
            Self::Build(error) => write!(formatter, "could not derive recovery guard: {error}"),
            Self::DerivedGuard => formatter.write_str("guard is not the exact audited derivation"),
            Self::RawGuardCode => formatter.write_str("raw guard code differs from derivation"),
            Self::EmbeddedCode => {
                formatter.write_str("container does not contain the supplied guard code")
            },
            Self::DifferenceSet { actual } => write!(
                formatter,
                "stub-to-guard difference set changed: {actual:x?}"
            ),
            Self::MarkerFirstPrefix => {
                formatter.write_str("marker-first executed prefix differs from live stub")
            },
            Self::SupportRoutines => {
                formatter.write_str("recovery support routines differ from live stub")
            },
            Self::LiveFinalTarget { actual } => write!(
                formatter,
                "live stub final call targets {actual:#x}, not watchdog reset"
            ),
            Self::ExperimentTarget { actual } => {
                write!(formatter, "guard enters {actual:#x}, not the experiment")
            },
            Self::ExperimentCode => formatter.write_str("experimental hang instruction changed"),
            Self::Isolation(error) => write!(formatter, "{error}"),
            Self::ErasedPadding => {
                formatter.write_str("bytes after guard code are not erased padding")
            },
            Self::Image(error) => write!(formatter, "guard image: {error}"),
            Self::HeaderCrc => formatter.write_str("guard application CRC is invalid"),
            Self::CodeIdentity => formatter.write_str("guard code differs from audited build"),
            Self::GuardIdentity(error) => write!(formatter, "marker-first recovery guard: {error}"),
        }
    }
}

impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::StubIdentity(error) | Self::GuardIdentity(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::Isolation(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolationReport {
    pub start: usize,
    pub end: usize,
    pub bytes: usize,
    pub persistent_address_literals: usize,
    pub out_of_range_direct_calls: usize,
    pub indirect_branch_links: usize,
    pub software_interrupts: usize,
    pub direct_call_targets: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryGuardReport {
    pub result: &'static str,
    pub base_stub_sha256: [u8; 32],
    pub code_bytes: usize,
    pub code_sha256: [u8; 32],
    pub container_bytes: usize,
    pub container_sha256: [u8; 32],
    pub application_crc: u32,
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub changed_offsets: Vec<usize>,
    pub live_stub_final_target: u32,
    pub guard_experiment_entry: u32,
    pub experiment_storage_isolation: IsolationReport,
}

/// Derives the marker-first guard and its transmitted code from the exact live-tested stub.
///
/// # Errors
///
/// Returns an error unless the stub identity and erased experiment slot are exact.
pub fn build(stub: &[u8]) -> Result<(Vec<u8>, Vec<u8>), BuildError> {
    RECOVERY_STUB
        .validate(stub)
        .map_err(BuildError::StubIdentity)?;
    if stub.get(EXPERIMENT_ENTRY..GUARD_CODE_END) != Some([0xff; 2].as_slice()) {
        return Err(BuildError::ExperimentEntryNotErased);
    }
    let branch = encode_thumb_bl(
        ThumbAddress::new(u32::try_from(FINAL_ACTION_CALL).map_err(|_| BuildError::ImageLayout)?)
            .map_err(BuildError::Branch)?,
        ThumbAddress::new(u32::try_from(EXPERIMENT_ENTRY).map_err(|_| BuildError::ImageLayout)?)
            .map_err(BuildError::Branch)?,
    )
    .map_err(BuildError::Branch)?;
    let mut image = stub.to_vec();
    image
        .get_mut(FINAL_ACTION_CALL..FINAL_ACTION_CALL + branch.len())
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(&branch);
    image
        .get_mut(EXPERIMENT_ENTRY..GUARD_CODE_END)
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(&EXPERIMENT_CODE);
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(BuildError::Image)?;
    let code = image
        .get(APPLICATION_CODE_OFFSET..GUARD_CODE_END)
        .ok_or(BuildError::ImageLayout)?
        .to_vec();
    Ok((image, code))
}

/// Conservatively rejects persistent-storage access and unsafe call forms in experimental code.
///
/// # Errors
///
/// Returns an error for invalid bounds, persistent addresses, out-of-range calls, indirect BLX,
/// or software interrupts.
pub fn verify_experiment_storage_isolation(
    image: &[u8],
    start: usize,
    end: usize,
) -> Result<IsolationReport, IsolationError> {
    if start >= end || end > image.len() {
        return Err(IsolationError::InvalidRange {
            start,
            end,
            size: image.len(),
        });
    }
    let experiment = image.get(start..end).ok_or(IsolationError::InvalidRange {
        start,
        end,
        size: image.len(),
    })?;

    for (relative, bytes) in experiment.windows(4).enumerate() {
        let value =
            u32::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| IsolationError::WordUnavailable {
                        offset: start + relative,
                    })?,
            );
        if (PERSISTENT_CONTROLLER_START..PERSISTENT_CONTROLLER_END).contains(&value)
            || PERSISTENT_WORD_ADDRESSES.contains(&value)
        {
            return Err(IsolationError::PersistentAddress {
                offset: start + relative,
                value,
            });
        }
    }

    let mut direct_call_targets = Vec::new();
    let direct_limit = end.saturating_sub(3);
    for address in (start..direct_limit).step_by(2) {
        let instruction = read_array(image, address)?;
        let high = u16::from_le_bytes([instruction[0], instruction[1]]);
        let low = u16::from_le_bytes([instruction[2], instruction[3]]);
        if high & 0xf800 == 0xf000 && low & 0xf800 == 0xf800 {
            let source = u32::try_from(address)
                .map_err(|_| IsolationError::WordUnavailable { offset: address })?;
            let target = decode_thumb_bl(
                instruction,
                ThumbAddress::new(source).map_err(IsolationError::Branch)?,
            )
            .map_err(IsolationError::Branch)?
            .get();
            let target_usize =
                usize::try_from(target).map_err(|_| IsolationError::CallOutsideRange {
                    source: address,
                    target,
                })?;
            if !(start..end).contains(&target_usize) {
                return Err(IsolationError::CallOutsideRange {
                    source: address,
                    target,
                });
            }
            direct_call_targets.push(target);
        }
    }

    for (index, bytes) in experiment.chunks_exact(2).enumerate() {
        let opcode = u16::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| IsolationError::WordUnavailable { offset: start })?,
        );
        let address = start
            .checked_add(index.saturating_mul(2))
            .ok_or(IsolationError::WordUnavailable { offset: start })?;
        if opcode & 0xff87 == 0x4780 {
            return Err(IsolationError::IndirectBranchLink { address });
        }
        if opcode & 0xff00 == 0xdf00 {
            return Err(IsolationError::SoftwareInterrupt { address });
        }
    }

    Ok(IsolationReport {
        start,
        end,
        bytes: experiment.len(),
        persistent_address_literals: 0,
        out_of_range_direct_calls: 0,
        indirect_branch_links: 0,
        software_interrupts: 0,
        direct_call_targets,
    })
}

/// Performs the complete marker-first recovery-guard audit.
///
/// # Errors
///
/// Returns the first failed derivation, prefix, control-flow, storage-isolation, padding, CRC, or
/// identity invariant.
pub fn verify(
    stub: &[u8],
    guard: &[u8],
    code: &[u8],
) -> Result<RecoveryGuardReport, VerificationError> {
    RECOVERY_STUB
        .validate(stub)
        .map_err(VerificationError::StubIdentity)?;
    let (expected_guard, expected_code) = build(stub).map_err(VerificationError::Build)?;
    if guard != expected_guard {
        return Err(VerificationError::DerivedGuard);
    }
    if code != expected_code {
        return Err(VerificationError::RawGuardCode);
    }
    if guard.get(APPLICATION_CODE_OFFSET..GUARD_CODE_END) != Some(code) {
        return Err(VerificationError::EmbeddedCode);
    }

    let differences: Vec<usize> = stub
        .iter()
        .zip(guard)
        .enumerate()
        .filter_map(|(offset, (before, after))| (before != after).then_some(offset))
        .collect();
    if differences.as_slice() != EXPECTED_DIFFERENCES {
        return Err(VerificationError::DifferenceSet {
            actual: differences,
        });
    }
    if guard.get(APPLICATION_CODE_OFFSET..FINAL_ACTION_CALL)
        != stub.get(APPLICATION_CODE_OFFSET..FINAL_ACTION_CALL)
    {
        return Err(VerificationError::MarkerFirstPrefix);
    }
    if guard.get(FINAL_ACTION_CALL + 4..LIVE_STUB_CODE_END)
        != stub.get(FINAL_ACTION_CALL + 4..LIVE_STUB_CODE_END)
    {
        return Err(VerificationError::SupportRoutines);
    }

    let live_target = thumb_target(stub, FINAL_ACTION_CALL)?;
    if live_target != 0x20fc {
        return Err(VerificationError::LiveFinalTarget {
            actual: live_target,
        });
    }
    let experiment_target = thumb_target(guard, FINAL_ACTION_CALL)?;
    let expected_entry = u32::try_from(EXPERIMENT_ENTRY)
        .map_err(|_| VerificationError::ExperimentTarget { actual: 0 })?;
    if experiment_target != expected_entry {
        return Err(VerificationError::ExperimentTarget {
            actual: experiment_target,
        });
    }
    if guard.get(EXPERIMENT_ENTRY..GUARD_CODE_END) != Some(EXPERIMENT_CODE.as_slice()) {
        return Err(VerificationError::ExperimentCode);
    }
    let experiment_storage_isolation =
        verify_experiment_storage_isolation(guard, EXPERIMENT_ENTRY, GUARD_CODE_END)
            .map_err(VerificationError::Isolation)?;
    let padding = guard
        .get(GUARD_CODE_END..)
        .ok_or(VerificationError::ErasedPadding)?;
    if padding.iter().any(|byte| *byte != 0xff) {
        return Err(VerificationError::ErasedPadding);
    }

    let header = slimblade_image::parse_header(guard, APPLICATION_HEADER_OFFSET)
        .map_err(VerificationError::Image)?;
    if !header
        .crc_is_valid(guard)
        .map_err(VerificationError::Image)?
    {
        return Err(VerificationError::HeaderCrc);
    }
    if !RECOVERY_GUARD_ARTIFACT.code_matches(code) {
        return Err(VerificationError::CodeIdentity);
    }
    let payload = RECOVERY_GUARD
        .validate(guard)
        .map_err(VerificationError::GuardIdentity)?;

    Ok(RecoveryGuardReport {
        result: "PASS",
        base_stub_sha256: sha256(stub),
        code_bytes: code.len(),
        code_sha256: sha256(code),
        container_bytes: guard.len(),
        container_sha256: sha256(guard),
        application_crc: header.crc,
        payload_bytes: payload.len(),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        changed_offsets: differences,
        live_stub_final_target: live_target,
        guard_experiment_entry: experiment_target,
        experiment_storage_isolation,
    })
}

fn thumb_target(image: &[u8], address: usize) -> Result<u32, VerificationError> {
    let instruction = read_array(image, address).map_err(VerificationError::Isolation)?;
    let source =
        u32::try_from(address).map_err(|_| VerificationError::ExperimentTarget { actual: 0 })?;
    Ok(decode_thumb_bl(
        instruction,
        ThumbAddress::new(source)
            .map_err(|error| VerificationError::Isolation(IsolationError::Branch(error)))?,
    )
    .map_err(|error| VerificationError::Isolation(IsolationError::Branch(error)))?
    .get())
}

fn read_array(bytes: &[u8], offset: usize) -> Result<[u8; 4], IsolationError> {
    let end = offset
        .checked_add(4)
        .ok_or(IsolationError::WordUnavailable { offset })?;
    bytes
        .get(offset..end)
        .ok_or(IsolationError::WordUnavailable { offset })?
        .try_into()
        .map_err(|_| IsolationError::WordUnavailable { offset })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests mutate bounded artifact fixtures and expect successful audits as assertions"
)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    struct Fixtures {
        stub: Vec<u8>,
        guard: Vec<u8>,
        code: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read recovery-guard fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build_dir = root.join("firmware/recovery_guard/build");
        Some(Fixtures {
            stub: read_if_present(
                root.join("firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.container.bin"),
            )?,
            guard: read_if_present(
                build_dir.join("DO_NOT_FLASH-marker-first-guard-hang-probe.container.bin"),
            )?,
            code: read_if_present(
                build_dir.join("DO_NOT_FLASH-marker-first-guard-hang-probe.code.bin"),
            )?,
        })
    }

    #[test]
    fn exact_guard_passes() {
        let Some(data) = fixtures() else { return };
        let report = verify(&data.stub, &data.guard, &data.code).expect("audited recovery guard");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.guard_experiment_entry, 0x21c4);
        assert_eq!(report.changed_offsets, EXPECTED_DIFFERENCES);
    }

    #[test]
    fn generator_reproduces_artifacts() {
        let Some(data) = fixtures() else { return };
        assert_eq!(build(&data.stub), Ok((data.guard, data.code)));
    }

    #[test]
    fn wrong_live_stub_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.stub[0] ^= 1;
        assert!(matches!(
            build(&data.stub),
            Err(BuildError::StubIdentity(_))
        ));
    }

    #[test]
    fn changed_guard_branch_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.guard[FINAL_ACTION_CALL] ^= 1;
        assert!(matches!(
            verify(&data.stub, &data.guard, &data.code),
            Err(VerificationError::DerivedGuard)
        ));
    }

    #[test]
    fn changed_experimental_instruction_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.code[EXPERIMENT_ENTRY - APPLICATION_CODE_OFFSET] ^= 1;
        assert!(matches!(
            verify(&data.stub, &data.guard, &data.code),
            Err(VerificationError::RawGuardCode)
        ));
    }

    #[test]
    fn storage_isolation_rejects_controller_literal() {
        let mut image = vec![0; 12];
        image[8..12].copy_from_slice(&0x0080_3000_u32.to_le_bytes());
        assert!(matches!(
            verify_experiment_storage_isolation(&image, 8, 12),
            Err(IsolationError::PersistentAddress { .. })
        ));
    }

    #[test]
    fn storage_isolation_rejects_marker_word_address() {
        let mut image = vec![0; 12];
        image[8..12].copy_from_slice(&0x0000_807c_u32.to_le_bytes());
        assert!(matches!(
            verify_experiment_storage_isolation(&image, 8, 12),
            Err(IsolationError::PersistentAddress { .. })
        ));
    }

    #[test]
    fn storage_isolation_rejects_call_into_guard_prefix() {
        let start = 0x100;
        let mut image = vec![0; 0x108];
        let branch = encode_thumb_bl(
            ThumbAddress::new(0x100).expect("aligned"),
            ThumbAddress::new(0x80).expect("aligned"),
        )
        .expect("in range");
        image[start..start + 4].copy_from_slice(&branch);
        assert!(matches!(
            verify_experiment_storage_isolation(&image, start, start + 4),
            Err(IsolationError::CallOutsideRange { .. })
        ));
    }

    #[test]
    fn storage_isolation_accepts_current_self_loop() {
        let mut image = vec![0; GUARD_CODE_END];
        image[EXPERIMENT_ENTRY..GUARD_CODE_END].copy_from_slice(&EXPERIMENT_CODE);
        let report = verify_experiment_storage_isolation(&image, EXPERIMENT_ENTRY, GUARD_CODE_END)
            .expect("isolated self-loop");
        assert_eq!(report.persistent_address_literals, 0);
        assert_eq!(report.out_of_range_direct_calls, 0);
    }

    #[test]
    fn storage_isolation_rejects_indirect_calls_and_software_interrupts() {
        assert!(matches!(
            verify_experiment_storage_isolation(&0x4780_u16.to_le_bytes(), 0, 2),
            Err(IsolationError::IndirectBranchLink { address: 0 })
        ));
        assert!(matches!(
            verify_experiment_storage_isolation(&0xdf00_u16.to_le_bytes(), 0, 2),
            Err(IsolationError::SoftwareInterrupt { address: 0 })
        ));
    }
}
