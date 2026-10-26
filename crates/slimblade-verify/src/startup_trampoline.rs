use core::fmt;

use slimblade_image::{
    APPLICATION_HEADER_OFFSET, FirmwareIdentityError, ImageError, RECOVERY_STUB, RESET_TRAMPOLINE,
    STACK_HEADER_OFFSET, STARTUP_TRAMPOLINE, STARTUP_TRAMPOLINE_ARTIFACT, V449_BCD_DEVICE_OFFSET,
    parse_header, refresh_header_crc, sha256,
};

use crate::{
    ArmAddress, ArmBranchKind, BranchError, decode_arm_branch,
    elf::{ArmExecutableError, ArmExecutableText, verify_arm_executable_text},
};

pub const TRAMPOLINE_ADDRESS: usize = 0x22b4;
pub const TRAMPOLINE_LIMIT: usize = 0x2300;
pub const AUDITED_CODE_SIZE: usize = 60;
pub const STOCK_RESET_CONTINUATION: u32 = 0x2068;
pub const ARM_RESUME_ADDRESS: u32 = 0x22d0;
pub const FINAL_BRANCH_ADDRESS: u32 = 0x22dc;
pub const THUMB_ENTRY_POINTER: u32 = 0x22e9;

const BASE_CODE: [u8; 8] = [0x00, 0x00, 0xa0, 0xe3, 0x6a, 0xff, 0xff, 0xea];
const THUMB_INTERWORKING: [u8; 4] = [0x00, 0x48, 0x00, 0x47];
const EXPECTED_WORDS: [(usize, u32); 13] = [
    (0x00, 0xe10f_a000),
    (0x04, 0xe1a0_b00d),
    (0x08, 0xe3a0_00d3),
    (0x0c, 0xe121_f000),
    (0x10, 0xe59f_d014),
    (0x14, 0xe59f_0014),
    (0x18, 0xe12f_ff10),
    (0x1c, 0xe121_f00a),
    (0x20, 0xe1a0_d00b),
    (0x24, 0xe3a0_0000),
    (0x2c, 0x0040_7f00),
    (0x30, THUMB_ENTRY_POINTER),
    (0x38, ARM_RESUME_ADDRESS),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    BaseIdentity(FirmwareIdentityError),
    EmptyCode,
    CodeOverlapsIrq { end: usize },
    BaseTrampolineChanged,
    BaseGapNotZero,
    ImageLayout,
    Image(ImageError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseIdentity(error) => write!(formatter, "reset trampoline: {error}"),
            Self::EmptyCode => formatter.write_str("startup trampoline code is empty"),
            Self::CodeOverlapsIrq { end } => write!(
                formatter,
                "startup trampoline ends at {end:#x} and overlaps the stock IRQ handler"
            ),
            Self::BaseTrampolineChanged => {
                formatter.write_str("v4.52 two-instruction trampoline changed")
            },
            Self::BaseGapNotZero => {
                formatter.write_str("v4.52 unused trampoline region is not zero-filled")
            },
            Self::ImageLayout => formatter.write_str("base image layout is truncated"),
            Self::Image(error) => write!(formatter, "container header: {error}"),
        }
    }
}

impl core::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BaseIdentity(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    BaseIdentity(FirmwareIdentityError),
    StubIdentity(FirmwareIdentityError),
    CodeSize { actual: usize },
    CodeHash,
    Build(BuildError),
    DerivedImageMismatch,
    ContainerIdentity(FirmwareIdentityError),
    WordUnavailable { offset: usize },
    WordChanged { offset: usize, actual: u32 },
    FinalBranchKind,
    FinalBranchTarget { actual: u32 },
    Branch(BranchError),
    ThumbInterworkingChanged,
    ThumbTargetEven,
    ArmTargetOdd,
    StubModeSetupChanged,
    StubArmExchangeChanged,
    StubStackChanged,
    StubThumbEntryChanged,
    ResetBranchChanged,
    InjectedCodeMismatch,
    UnusedGapChanged,
    StockInterruptWrappersChanged,
    DeviceVersion { actual: u8 },
    Header(ImageError),
    HeaderCrc { offset: usize },
    Elf(ArmExecutableError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseIdentity(error) => write!(formatter, "base reset trampoline: {error}"),
            Self::StubIdentity(error) => write!(formatter, "standalone recovery stub: {error}"),
            Self::CodeSize { actual } => {
                write!(
                    formatter,
                    "startup trampoline code is {actual} bytes, not 60"
                )
            },
            Self::CodeHash => formatter.write_str("startup trampoline code hash changed"),
            Self::Build(error) => {
                write!(formatter, "could not rebuild startup trampoline: {error}")
            },
            Self::DerivedImageMismatch => {
                formatter.write_str("image is not an exact derivation of v4.52")
            },
            Self::ContainerIdentity(error) => write!(formatter, "startup trampoline: {error}"),
            Self::WordUnavailable { offset } => {
                write!(formatter, "startup code has no word at +{offset:#x}")
            },
            Self::WordChanged { offset, actual } => {
                write!(
                    formatter,
                    "startup word at +{offset:#x} changed to {actual:#010x}"
                )
            },
            Self::FinalBranchKind => formatter.write_str("final instruction is not ARM B"),
            Self::FinalBranchTarget { actual } => write!(
                formatter,
                "final ARM branch targets {actual:#x}, not {STOCK_RESET_CONTINUATION:#x}"
            ),
            Self::Branch(error) => write!(formatter, "ARM branch: {error}"),
            Self::ThumbInterworkingChanged => formatter.write_str("Thumb ldr/bx sequence changed"),
            Self::ThumbTargetEven => formatter.write_str("ARM-to-Thumb target is not odd"),
            Self::ArmTargetOdd => formatter.write_str("Thumb-to-ARM target is not even"),
            Self::StubModeSetupChanged => formatter.write_str("mode setup differs from stub"),
            Self::StubArmExchangeChanged => formatter.write_str("ARM bx differs from stub"),
            Self::StubStackChanged => formatter.write_str("stack top differs from stub"),
            Self::StubThumbEntryChanged => formatter.write_str("stub Thumb entry pointer changed"),
            Self::ResetBranchChanged => formatter.write_str("v4.52 reset branch changed"),
            Self::InjectedCodeMismatch => {
                formatter.write_str("container code differs from linked code")
            },
            Self::UnusedGapChanged => formatter.write_str("unused pre-IRQ gap changed"),
            Self::StockInterruptWrappersChanged => {
                formatter.write_str("stock IRQ/FIQ wrappers changed")
            },
            Self::DeviceVersion { actual } => {
                write!(formatter, "bcdDevice low byte is {actual:#04x}, not 0x53")
            },
            Self::Header(error) => write!(formatter, "container header: {error}"),
            Self::HeaderCrc { offset } => {
                write!(formatter, "header CRC at {offset:#x} is invalid")
            },
            Self::Elf(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BaseIdentity(error)
            | Self::StubIdentity(error)
            | Self::ContainerIdentity(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::Branch(error) => Some(error),
            Self::Header(error) => Some(error),
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupTrampolineReport {
    pub result: &'static str,
    pub base_sha256: [u8; 32],
    pub stub_sha256: [u8; 32],
    pub code_bytes: usize,
    pub code_sha256: [u8; 32],
    pub container_bytes: usize,
    pub container_sha256: [u8; 32],
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub arm_to_thumb_target: u32,
    pub thumb_to_arm_target: u32,
    pub stock_return_target: u32,
    pub usb_bcd_device: u16,
}

/// Replaces the two-instruction v4.52 trampoline with the linked startup trampoline.
///
/// # Errors
///
/// Returns an error unless the base identity, code bounds, and unused gap are exact.
pub fn build(base: &[u8], code: &[u8]) -> Result<Vec<u8>, BuildError> {
    RESET_TRAMPOLINE
        .validate(base)
        .map_err(BuildError::BaseIdentity)?;
    if code.is_empty() {
        return Err(BuildError::EmptyCode);
    }
    let code_end = TRAMPOLINE_ADDRESS
        .checked_add(code.len())
        .ok_or(BuildError::CodeOverlapsIrq { end: usize::MAX })?;
    if code_end > TRAMPOLINE_LIMIT {
        return Err(BuildError::CodeOverlapsIrq { end: code_end });
    }
    if base.get(TRAMPOLINE_ADDRESS..TRAMPOLINE_ADDRESS + BASE_CODE.len())
        != Some(BASE_CODE.as_slice())
    {
        return Err(BuildError::BaseTrampolineChanged);
    }
    let unused = base
        .get(TRAMPOLINE_ADDRESS + BASE_CODE.len()..TRAMPOLINE_LIMIT)
        .ok_or(BuildError::ImageLayout)?;
    if unused.iter().any(|byte| *byte != 0) {
        return Err(BuildError::BaseGapNotZero);
    }

    let mut image = base.to_vec();
    let gap = image
        .get_mut(TRAMPOLINE_ADDRESS..TRAMPOLINE_LIMIT)
        .ok_or(BuildError::ImageLayout)?;
    gap.fill(0);
    gap.get_mut(..code.len())
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(code);
    *image
        .get_mut(V449_BCD_DEVICE_OFFSET)
        .ok_or(BuildError::ImageLayout)? = 0x53;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(BuildError::Image)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(BuildError::Image)?;
    Ok(image)
}

/// Performs the complete structural and cryptographic startup-trampoline audit.
///
/// # Errors
///
/// Returns the first failed identity, instruction, interworking, container, or ELF invariant.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the ordered startup audit contiguous makes the recovery boundary reviewable"
)]
pub fn verify(
    base: &[u8],
    image: &[u8],
    code: &[u8],
    elf_bytes: &[u8],
    stub: &[u8],
) -> Result<StartupTrampolineReport, VerificationError> {
    RESET_TRAMPOLINE
        .validate(base)
        .map_err(VerificationError::BaseIdentity)?;
    RECOVERY_STUB
        .validate(stub)
        .map_err(VerificationError::StubIdentity)?;
    if code.len() != AUDITED_CODE_SIZE {
        return Err(VerificationError::CodeSize { actual: code.len() });
    }
    if !STARTUP_TRAMPOLINE_ARTIFACT.code_matches(code) {
        return Err(VerificationError::CodeHash);
    }
    let expected = build(base, code).map_err(VerificationError::Build)?;
    if image != expected {
        return Err(VerificationError::DerivedImageMismatch);
    }
    let payload = STARTUP_TRAMPOLINE
        .validate(image)
        .map_err(VerificationError::ContainerIdentity)?;

    for (offset, expected) in EXPECTED_WORDS {
        let actual = read_u32(code, offset)?;
        if actual != expected {
            return Err(VerificationError::WordChanged { offset, actual });
        }
    }

    let branch = read_u32(code, 0x28)?.to_le_bytes();
    let (kind, target) = decode_arm_branch(
        branch,
        ArmAddress::new(FINAL_BRANCH_ADDRESS).map_err(VerificationError::Branch)?,
    )
    .map_err(VerificationError::Branch)?;
    if kind != ArmBranchKind::Branch {
        return Err(VerificationError::FinalBranchKind);
    }
    if target.get() != STOCK_RESET_CONTINUATION {
        return Err(VerificationError::FinalBranchTarget {
            actual: target.get(),
        });
    }
    if code.get(0x34..0x38) != Some(THUMB_INTERWORKING.as_slice()) {
        return Err(VerificationError::ThumbInterworkingChanged);
    }
    if read_u32(code, 0x30)? & 1 == 0 {
        return Err(VerificationError::ThumbTargetEven);
    }
    if read_u32(code, 0x38)? & 1 != 0 {
        return Err(VerificationError::ArmTargetOdd);
    }

    if code.get(0x08..0x10) != stub.get(0x2064..0x206c) {
        return Err(VerificationError::StubModeSetupChanged);
    }
    if code.get(0x18..0x1c) != stub.get(0x2074..0x2078) {
        return Err(VerificationError::StubArmExchangeChanged);
    }
    if read_u32(code, 0x2c)? != read_u32(stub, 0x2078)? {
        return Err(VerificationError::StubStackChanged);
    }
    if read_u32(stub, 0x207c)? != 0x2081 {
        return Err(VerificationError::StubThumbEntryChanged);
    }

    if image.get(0x2064..0x2068) != base.get(0x2064..0x2068) {
        return Err(VerificationError::ResetBranchChanged);
    }
    let code_end = TRAMPOLINE_ADDRESS
        .checked_add(code.len())
        .ok_or(VerificationError::InjectedCodeMismatch)?;
    if image.get(TRAMPOLINE_ADDRESS..code_end) != Some(code) {
        return Err(VerificationError::InjectedCodeMismatch);
    }
    let gap = image
        .get(code_end..TRAMPOLINE_LIMIT)
        .ok_or(VerificationError::UnusedGapChanged)?;
    if gap.iter().any(|byte| *byte != 0) {
        return Err(VerificationError::UnusedGapChanged);
    }
    if image.get(0x2300..0x2330) != base.get(0x2300..0x2330) {
        return Err(VerificationError::StockInterruptWrappersChanged);
    }
    let device_version = image
        .get(V449_BCD_DEVICE_OFFSET)
        .copied()
        .ok_or(VerificationError::DeviceVersion { actual: 0 })?;
    if device_version != 0x53 {
        return Err(VerificationError::DeviceVersion {
            actual: device_version,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(VerificationError::Header)?;
        if !header
            .crc_is_valid(image)
            .map_err(VerificationError::Header)?
        {
            return Err(VerificationError::HeaderCrc { offset });
        }
    }
    verify_arm_executable_text(
        elf_bytes,
        ArmExecutableText {
            entry: 0x22b4,
            address: 0x22b4,
            size: 60,
        },
    )
    .map_err(VerificationError::Elf)?;

    Ok(StartupTrampolineReport {
        result: "PASS",
        base_sha256: sha256(base),
        stub_sha256: sha256(stub),
        code_bytes: code.len(),
        code_sha256: sha256(code),
        container_bytes: image.len(),
        container_sha256: sha256(image),
        payload_bytes: payload.len(),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        arm_to_thumb_target: THUMB_ENTRY_POINTER,
        thumb_to_arm_target: ARM_RESUME_ADDRESS,
        stock_return_target: STOCK_RESET_CONTINUATION,
        usb_bcd_device: 0x0453,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, VerificationError> {
    let end = offset
        .checked_add(4)
        .ok_or(VerificationError::WordUnavailable { offset })?;
    let word: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(VerificationError::WordUnavailable { offset })?
        .try_into()
        .map_err(|_| VerificationError::WordUnavailable { offset })?;
    Ok(u32::from_le_bytes(word))
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
        base: Vec<u8>,
        image: Vec<u8>,
        code: Vec<u8>,
        elf: Vec<u8>,
        stub: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read generated startup-trampoline fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build = root.join("firmware/startup_trampoline/build");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/reset_trampoline/build/DO_NOT_FLASH-stock-reset-trampoline.container.bin",
            ))?,
            image: read_if_present(
                build.join("DO_NOT_FLASH-stock-startup-trampoline.container.bin"),
            )?,
            code: read_if_present(build.join("DO_NOT_FLASH-stock-startup-trampoline.code.bin"))?,
            elf: read_if_present(build.join("DO_NOT_FLASH-stock-startup-trampoline.elf"))?,
            stub: read_if_present(
                root.join("firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.container.bin"),
            )?,
        })
    }

    #[test]
    fn exact_build_passes_and_generator_reproduces_container() {
        let Some(data) = fixtures() else {
            return;
        };
        assert_eq!(build(&data.base, &data.code), Ok(data.image.clone()));
        let report = verify(&data.base, &data.image, &data.code, &data.elf, &data.stub)
            .expect("audited startup trampoline");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.code_bytes, 60);
        assert_eq!(report.payload_crc, 0x4e9c_5e53);
        assert_eq!(report.arm_to_thumb_target, 0x22e9);
        assert_eq!(report.thumb_to_arm_target, 0x22d0);
        assert_eq!(report.stock_return_target, 0x2068);
    }

    #[test]
    fn even_thumb_pointer_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.code[0x30] &= 0xfe;
        assert!(matches!(
            verify(&data.base, &data.image, &data.code, &data.elf, &data.stub),
            Err(VerificationError::CodeHash)
        ));
    }

    #[test]
    fn changed_mode_setup_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.code[0x08] ^= 1;
        assert!(verify(&data.base, &data.image, &data.code, &data.elf, &data.stub).is_err());
    }

    #[test]
    fn changed_base_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.base[0] ^= 1;
        assert!(matches!(
            verify(&data.base, &data.image, &data.code, &data.elf, &data.stub),
            Err(VerificationError::BaseIdentity(_))
        ));
    }

    #[test]
    fn changed_standalone_reference_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.stub[0x2064] ^= 1;
        assert!(matches!(
            verify(&data.base, &data.image, &data.code, &data.elf, &data.stub),
            Err(VerificationError::StubIdentity(_))
        ));
    }

    #[test]
    fn oversized_code_is_rejected() {
        let Some(data) = fixtures() else {
            return;
        };
        let code = vec![0; TRAMPOLINE_LIMIT - TRAMPOLINE_ADDRESS + 1];
        assert!(matches!(
            build(&data.base, &code),
            Err(BuildError::CodeOverlapsIrq { .. })
        ));
    }
}
