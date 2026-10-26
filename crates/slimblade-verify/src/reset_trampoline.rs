#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "all audited firmware addresses and artifact sizes are fixed below u32::MAX"
)]

use core::fmt;

use slimblade_image::{
    APPLICATION_HEADER_OFFSET, FirmwareIdentityError, ImageError, RECOVERY_CARRIER,
    RESET_TRAMPOLINE, RESET_TRAMPOLINE_ARTIFACT, STACK_HEADER_OFFSET, V449_BCD_DEVICE_OFFSET,
    parse_header, refresh_header_crc, sha256,
};

use crate::{
    ArmAddress, ArmBranchKind, BranchError, decode_arm_branch,
    elf::{ArmExecutableError, ArmExecutableText, verify_arm_executable_text},
    encode_arm_b,
};

pub const RESET_HANDLER: usize = 0x2064;
pub const STOCK_RESET_CONTINUATION: usize = 0x2068;
pub const TRAMPOLINE_ADDRESS: usize = 0x22b4;
pub const TRAMPOLINE_LIMIT: usize = 0x2300;
pub const AUDITED_CODE_SIZE: usize = 8;
pub const STOCK_FIRST_RESET_INSTRUCTION: [u8; 4] = [0x00, 0x00, 0xa0, 0xe3];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    BaseIdentity(FirmwareIdentityError),
    EmptyCode,
    CodeOverlapsIrq { end: usize },
    CarrierGapNotZero,
    Branch(BranchError),
    Image(ImageError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseIdentity(error) => write!(formatter, "recovery carrier: {error}"),
            Self::EmptyCode => formatter.write_str("trampoline code is empty"),
            Self::CodeOverlapsIrq { end } => write!(
                formatter,
                "trampoline ends at {end:#x} and overlaps the stock IRQ handler"
            ),
            Self::CarrierGapNotZero => {
                formatter.write_str("carrier trampoline region is not zero-filled")
            },
            Self::Branch(error) => write!(formatter, "reset branch: {error}"),
            Self::Image(error) => write!(formatter, "container header: {error}"),
        }
    }
}

impl core::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BaseIdentity(error) => Some(error),
            Self::Branch(error) => Some(error),
            Self::Image(error) => Some(error),
            Self::EmptyCode | Self::CodeOverlapsIrq { .. } | Self::CarrierGapNotZero => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    BaseIdentity(FirmwareIdentityError),
    CodeSize { actual: usize },
    CodeHash,
    Build(BuildError),
    DerivedImageMismatch,
    ContainerIdentity(FirmwareIdentityError),
    ResetVectorRegionChanged,
    ResetVectorTarget { actual: u32 },
    StockFirstInstructionChanged,
    ResetBranchEncoding,
    ResetBranchTarget,
    DisplacedInstruction,
    StockReturnTarget,
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
            Self::BaseIdentity(error) => write!(formatter, "base carrier: {error}"),
            Self::CodeSize { actual } => {
                write!(formatter, "trampoline code is {actual} bytes, not 8")
            },
            Self::CodeHash => formatter.write_str("trampoline code hash changed"),
            Self::Build(error) => write!(formatter, "could not rebuild trampoline: {error}"),
            Self::DerivedImageMismatch => {
                formatter.write_str("image is not an exact derivation of the carrier")
            },
            Self::ContainerIdentity(error) => write!(formatter, "trampoline image: {error}"),
            Self::ResetVectorRegionChanged => {
                formatter.write_str("reset vector or literal table changed")
            },
            Self::ResetVectorTarget { actual } => {
                write!(formatter, "reset vector targets {actual:#x}, not 0x2064")
            },
            Self::StockFirstInstructionChanged => {
                formatter.write_str("recorded stock first reset instruction changed")
            },
            Self::ResetBranchEncoding => formatter.write_str("reset branch encoding changed"),
            Self::ResetBranchTarget => formatter.write_str("reset branch target is wrong"),
            Self::DisplacedInstruction => {
                formatter.write_str("trampoline does not replay displaced stock instruction")
            },
            Self::StockReturnTarget => {
                formatter.write_str("trampoline does not return to stock 0x2068")
            },
            Self::InjectedCodeMismatch => {
                formatter.write_str("injected trampoline differs from linked code")
            },
            Self::UnusedGapChanged => formatter.write_str("unused pre-IRQ gap changed"),
            Self::StockInterruptWrappersChanged => {
                formatter.write_str("stock IRQ/FIQ wrappers changed")
            },
            Self::DeviceVersion { actual } => {
                write!(formatter, "bcdDevice low byte is {actual:#04x}, not 0x52")
            },
            Self::Header(error) => write!(formatter, "application header: {error}"),
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
            Self::BaseIdentity(error) | Self::ContainerIdentity(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::Header(error) => Some(error),
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetTrampolineReport {
    pub result: &'static str,
    pub base_carrier_sha256: [u8; 32],
    pub code_bytes: usize,
    pub code_sha256: [u8; 32],
    pub container_bytes: usize,
    pub container_sha256: [u8; 32],
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub reset_branch_target: u32,
    pub stock_return_target: u32,
    pub usb_bcd_device: u16,
}

/// Injects the audited reset trampoline into the exact recovery-carrier image.
///
/// # Errors
///
/// Returns an error unless the carrier identity, code size, and injection gap are valid.
#[allow(
    clippy::indexing_slicing,
    reason = "exact carrier identity and explicit code bounds are checked before fixed offsets are accessed"
)]
pub fn build(base: &[u8], code: &[u8]) -> Result<Vec<u8>, BuildError> {
    RECOVERY_CARRIER
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
    if base[TRAMPOLINE_ADDRESS..TRAMPOLINE_LIMIT]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(BuildError::CarrierGapNotZero);
    }

    let reset_handler = ArmAddress::new(RESET_HANDLER as u32).map_err(BuildError::Branch)?;
    let trampoline = ArmAddress::new(TRAMPOLINE_ADDRESS as u32).map_err(BuildError::Branch)?;
    let reset_branch = encode_arm_b(reset_handler, trampoline).map_err(BuildError::Branch)?;
    let mut image = base.to_vec();
    image[RESET_HANDLER..RESET_HANDLER + 4].copy_from_slice(&reset_branch);
    image[TRAMPOLINE_ADDRESS..code_end].copy_from_slice(code);
    image[V449_BCD_DEVICE_OFFSET] = 0x52;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(BuildError::Image)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(BuildError::Image)?;
    Ok(image)
}

/// Performs the complete structural and cryptographic reset-trampoline audit.
///
/// # Errors
///
/// Returns the first failed identity, layout, branch, header, or ELF invariant.
#[allow(
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "the ordered audit checks fixed offsets only after exact artifact validation; keeping the checklist contiguous aids review"
)]
pub fn verify(
    base: &[u8],
    image: &[u8],
    code: &[u8],
    elf_bytes: &[u8],
) -> Result<ResetTrampolineReport, VerificationError> {
    RECOVERY_CARRIER
        .validate(base)
        .map_err(VerificationError::BaseIdentity)?;
    if code.len() != AUDITED_CODE_SIZE {
        return Err(VerificationError::CodeSize { actual: code.len() });
    }
    if !RESET_TRAMPOLINE_ARTIFACT.code_matches(code) {
        return Err(VerificationError::CodeHash);
    }
    let expected = build(base, code).map_err(VerificationError::Build)?;
    if image != expected {
        return Err(VerificationError::DerivedImageMismatch);
    }
    let payload = RESET_TRAMPOLINE
        .validate(image)
        .map_err(VerificationError::ContainerIdentity)?;

    if base[0x2020..RESET_HANDLER] != image[0x2020..RESET_HANDLER] {
        return Err(VerificationError::ResetVectorRegionChanged);
    }
    let reset_vector_target = read_u32(image, 0x2040);
    if reset_vector_target != RESET_HANDLER as u32 {
        return Err(VerificationError::ResetVectorTarget {
            actual: reset_vector_target,
        });
    }
    if base[RESET_HANDLER..RESET_HANDLER + 4] != STOCK_FIRST_RESET_INSTRUCTION {
        return Err(VerificationError::StockFirstInstructionChanged);
    }

    let expected_reset = encode_arm_b(
        ArmAddress::new(RESET_HANDLER as u32).map_err(|_| VerificationError::ResetBranchTarget)?,
        ArmAddress::new(TRAMPOLINE_ADDRESS as u32)
            .map_err(|_| VerificationError::ResetBranchTarget)?,
    )
    .map_err(|_| VerificationError::ResetBranchTarget)?;
    let reset_branch: [u8; 4] = image[RESET_HANDLER..RESET_HANDLER + 4]
        .try_into()
        .map_err(|_| VerificationError::ResetBranchEncoding)?;
    if reset_branch != expected_reset {
        return Err(VerificationError::ResetBranchEncoding);
    }
    let (_, reset_target) = decode_arm_branch(
        reset_branch,
        ArmAddress::new(RESET_HANDLER as u32).map_err(|_| VerificationError::ResetBranchTarget)?,
    )
    .map_err(|_| VerificationError::ResetBranchTarget)?;
    if reset_target.get() != TRAMPOLINE_ADDRESS as u32 {
        return Err(VerificationError::ResetBranchTarget);
    }

    if code[..4] != STOCK_FIRST_RESET_INSTRUCTION {
        return Err(VerificationError::DisplacedInstruction);
    }
    let return_branch: [u8; 4] = code[4..8]
        .try_into()
        .map_err(|_| VerificationError::StockReturnTarget)?;
    let (kind, return_target) = decode_arm_branch(
        return_branch,
        ArmAddress::new((TRAMPOLINE_ADDRESS + 4) as u32)
            .map_err(|_| VerificationError::StockReturnTarget)?,
    )
    .map_err(|_| VerificationError::StockReturnTarget)?;
    if kind != ArmBranchKind::Branch || return_target.get() != STOCK_RESET_CONTINUATION as u32 {
        return Err(VerificationError::StockReturnTarget);
    }
    if image[TRAMPOLINE_ADDRESS..TRAMPOLINE_ADDRESS + code.len()] != code[..] {
        return Err(VerificationError::InjectedCodeMismatch);
    }
    if image[TRAMPOLINE_ADDRESS + code.len()..TRAMPOLINE_LIMIT]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(VerificationError::UnusedGapChanged);
    }
    if image[0x2300..0x2330] != base[0x2300..0x2330] {
        return Err(VerificationError::StockInterruptWrappersChanged);
    }
    if image[V449_BCD_DEVICE_OFFSET] != 0x52 {
        return Err(VerificationError::DeviceVersion {
            actual: image[V449_BCD_DEVICE_OFFSET],
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
            size: 8,
        },
    )
    .map_err(VerificationError::Elf)?;

    Ok(ResetTrampolineReport {
        result: "PASS",
        base_carrier_sha256: sha256(base),
        code_bytes: code.len(),
        code_sha256: sha256(code),
        container_bytes: image.len(),
        container_sha256: sha256(image),
        payload_bytes: payload.len(),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        reset_branch_target: TRAMPOLINE_ADDRESS as u32,
        stock_return_target: STOCK_RESET_CONTINUATION as u32,
        usb_bcd_device: 0x0452,
    })
}

#[allow(
    clippy::indexing_slicing,
    reason = "the only caller reads a fixed field after exact artifact identity validation"
)]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests mutate bounded fixtures and expect successful verification as assertions"
)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    struct Fixtures {
        base: Vec<u8>,
        image: Vec<u8>,
        code: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read generated reset-trampoline fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build = root.join("firmware/reset_trampoline/build");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.container.bin",
            ))?,
            image: read_if_present(
                build.join("DO_NOT_FLASH-stock-reset-trampoline.container.bin"),
            )?,
            code: read_if_present(build.join("DO_NOT_FLASH-stock-reset-trampoline.code.bin"))?,
            elf: read_if_present(build.join("DO_NOT_FLASH-stock-reset-trampoline.elf"))?,
        })
    }

    #[test]
    fn exact_build_passes_and_generator_reproduces_container() {
        let Some(data) = fixtures() else {
            return;
        };
        assert_eq!(build(&data.base, &data.code), Ok(data.image.clone()));
        let report = verify(&data.base, &data.image, &data.code, &data.elf)
            .expect("audited reset trampoline");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.code_bytes, 8);
        assert_eq!(report.payload_crc, 0xdb03_4cd6);
        assert_eq!(report.reset_branch_target, 0x22b4);
        assert_eq!(report.stock_return_target, 0x2068);
    }

    #[test]
    fn wrong_base_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.base[0] ^= 1;
        assert!(matches!(
            build(&data.base, &data.code),
            Err(BuildError::BaseIdentity(_))
        ));
    }

    #[test]
    fn corrupt_reset_branch_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.image[RESET_HANDLER] ^= 1;
        assert!(verify(&data.base, &data.image, &data.code, &data.elf).is_err());
    }

    #[test]
    fn corrupt_return_branch_is_rejected() {
        let Some(mut data) = fixtures() else {
            return;
        };
        data.code[4] ^= 1;
        assert!(matches!(
            verify(&data.base, &data.image, &data.code, &data.elf),
            Err(VerificationError::CodeHash)
        ));
    }

    #[test]
    fn oversized_trampoline_is_rejected() {
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
