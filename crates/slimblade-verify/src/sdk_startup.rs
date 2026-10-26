use core::fmt;

use slimblade_image::{
    FirmwareIdentityError, OFFICIAL_V449, STOCK_INTERRUPT_WRAPPERS_ARTIFACT,
    STOCK_STARTUP_ARTIFACT, sha256,
};

use crate::{
    ArmAddress, BranchError, decode_arm_blx, decode_arm_branch,
    elf::{
        ELF_MACHINE_ARM, ELF_TYPE_EXECUTABLE, Elf32, ElfError, SECTION_FLAG_ALLOCATE,
        SECTION_FLAG_EXECUTE,
    },
};

pub const STARTUP_ADDRESS: usize = 0x2020;
pub const STARTUP_END: usize = 0x21ac;
pub const STARTUP_SIZE: usize = STARTUP_END - STARTUP_ADDRESS;
pub const WRAPPERS_ADDRESS: usize = 0x2300;
pub const WRAPPERS_END: usize = 0x2330;
pub const WRAPPERS_SIZE: usize = WRAPPERS_END - WRAPPERS_ADDRESS;

const VECTOR_LITERALS: [u32; 8] = [0x2064, 0x2060, 0x2060, 0x2060, 0x2060, 0, 0x2320, 0x2300];
const RESET_CALLS: [(usize, u32); 3] = [(0x2098, 0x20b4), (0x209c, 0x2140), (0x20a0, 0x2114)];
const WRAPPER_WORDS: [(usize, u32); 6] = [
    (0x00, 0xe92d_500f),
    (0x08, 0xe8bd_500f),
    (0x0c, 0xe25e_f004),
    (0x20, 0xe92d_500f),
    (0x28, 0xe8bd_500f),
    (0x2c, 0xe25e_f004),
];
const INTERRUPT_TARGETS: [(usize, u32); 2] = [(0x2304, 0x3e78), (0x2324, 0x60e0)];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    StockIdentity(FirmwareIdentityError),
    StartupSize { actual: usize },
    StartupDifference { address: usize },
    StartupIdentity,
    VectorTargets,
    ResetCall { source: usize, actual: u32 },
    ThumbEntry { actual: u32 },
    WrappersSize { actual: usize },
    WrappersDifference,
    WrappersIdentity,
    ReservedGap,
    WrapperInstructions,
    InterruptTarget { source: usize, actual: u32 },
    Elf(SdkElfError),
    WordUnavailable { offset: usize },
    Branch(BranchError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StockIdentity(error) => {
                write!(formatter, "stock input is not official v4.49: {error}")
            },
            Self::StartupSize { actual } => {
                write!(formatter, "rebuilt startup is {actual} bytes, not 396")
            },
            Self::StartupDifference { address } => write!(
                formatter,
                "rebuilt startup differs from stock at {address:#x}"
            ),
            Self::StartupIdentity => formatter.write_str("startup differs from audited build"),
            Self::VectorTargets => formatter.write_str("vector targets changed"),
            Self::ResetCall { source, actual } => {
                write!(formatter, "reset call at {source:#x} targets {actual:#x}")
            },
            Self::ThumbEntry { actual } => write!(formatter, "Thumb entry changed to {actual:#x}"),
            Self::WrappersSize { actual } => write!(
                formatter,
                "interrupt-wrapper span is {actual} bytes, not 48"
            ),
            Self::WrappersDifference => {
                formatter.write_str("rebuilt interrupt wrappers differ from stock")
            },
            Self::WrappersIdentity => formatter.write_str("wrappers differ from audited build"),
            Self::ReservedGap => formatter.write_str("reserved IRQ/FIQ gap is not zero"),
            Self::WrapperInstructions => {
                formatter.write_str("interrupt save, restore, or exception return changed")
            },
            Self::InterruptTarget { source, actual } => write!(
                formatter,
                "interrupt call at {source:#x} targets {actual:#x}"
            ),
            Self::Elf(error) => write!(formatter, "{error}"),
            Self::WordUnavailable { offset } => write!(formatter, "no word at {offset:#x}"),
            Self::Branch(error) => write!(formatter, "branch: {error}"),
        }
    }
}

impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::StockIdentity(error) => Some(error),
            Self::Elf(error) => Some(error),
            Self::Branch(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkElfError {
    Elf(ElfError),
    WrongType { actual: u16 },
    WrongMachine { actual: u16 },
    WrongEntry { actual: u32 },
    StartupMissing,
    StartupLayout { address: u32, size: u32, flags: u32 },
    IrqMissing,
    IrqLayout { address: u32, size: u32 },
    FiqMissing,
    FiqLayout { address: u32, size: u32 },
    Relocation,
    WritableAllocated,
}

impl fmt::Display for SdkElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => write!(formatter, "ELF: {error}"),
            Self::WrongType { actual } => write!(formatter, "ELF type is {actual}, not executable"),
            Self::WrongMachine { actual } => write!(formatter, "ELF machine is {actual}, not ARM"),
            Self::WrongEntry { actual } => {
                write!(formatter, "ELF entry is {actual:#x}, not 0x2020")
            },
            Self::StartupMissing => formatter.write_str("ELF has no .startup section"),
            Self::StartupLayout {
                address,
                size,
                flags,
            } => write!(
                formatter,
                "ELF startup has address {address:#x}, size {size:#x}, flags {flags:#x}"
            ),
            Self::IrqMissing => formatter.write_str("ELF has no .irq_wrapper section"),
            Self::IrqLayout { address, size } => write!(
                formatter,
                "ELF IRQ wrapper has address {address:#x}, size {size:#x}"
            ),
            Self::FiqMissing => formatter.write_str("ELF has no .fiq_wrapper section"),
            Self::FiqLayout { address, size } => write!(
                formatter,
                "ELF FIQ wrapper has address {address:#x}, size {size:#x}"
            ),
            Self::Relocation => formatter.write_str("ELF contains relocations"),
            Self::WritableAllocated => formatter.write_str("ELF contains writable allocated data"),
        }
    }
}

impl core::error::Error for SdkElfError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdkStartupReport {
    pub result: &'static str,
    pub stock_sha256: [u8; 32],
    pub startup_bytes: usize,
    pub startup_sha256: [u8; 32],
    pub byte_exact: bool,
    pub elf_entry: u32,
    pub reset_target: u32,
    pub thumb_application_entry: u32,
    pub reset_calls: [u32; 3],
    pub interrupt_wrapper_bytes: usize,
    pub interrupt_wrapper_sha256: [u8; 32],
    pub interrupt_dispatch: [u32; 2],
}

/// Verifies the source-built startup and interrupt wrappers against exact stock v4.49 bytes.
///
/// # Errors
///
/// Returns the first failed stock, byte-parity, control-flow, wrapper, or ELF invariant.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the ordered startup and wrapper audit contiguous makes byte parity reviewable"
)]
pub fn verify(
    stock: &[u8],
    code: &[u8],
    wrappers: &[u8],
    elf_bytes: &[u8],
) -> Result<SdkStartupReport, VerificationError> {
    OFFICIAL_V449
        .validate(stock)
        .map_err(VerificationError::StockIdentity)?;
    if code.len() != STARTUP_SIZE {
        return Err(VerificationError::StartupSize { actual: code.len() });
    }
    let stock_startup =
        stock
            .get(STARTUP_ADDRESS..STARTUP_END)
            .ok_or(VerificationError::StartupDifference {
                address: STARTUP_ADDRESS,
            })?;
    if code != stock_startup {
        let relative = code
            .iter()
            .zip(stock_startup)
            .position(|(built, original)| built != original)
            .unwrap_or(0);
        return Err(VerificationError::StartupDifference {
            address: STARTUP_ADDRESS + relative,
        });
    }
    if !STOCK_STARTUP_ARTIFACT.code_matches(code) {
        return Err(VerificationError::StartupIdentity);
    }

    let mut vector_literals = [0_u32; 8];
    for (index, offset) in (0x20..0x40).step_by(4).enumerate() {
        *vector_literals
            .get_mut(index)
            .ok_or(VerificationError::VectorTargets)? = read_u32(code, offset)?;
    }
    if vector_literals != VECTOR_LITERALS {
        return Err(VerificationError::VectorTargets);
    }
    let mut reset_calls = [0_u32; 3];
    for (index, (source, expected)) in RESET_CALLS.into_iter().enumerate() {
        let actual = arm_branch_target(code, source)?;
        if actual != expected {
            return Err(VerificationError::ResetCall { source, actual });
        }
        *reset_calls
            .get_mut(index)
            .ok_or(VerificationError::ResetCall { source, actual })? = actual;
    }
    let thumb_application_entry = read_u32(code, 0x2170 - STARTUP_ADDRESS)?;
    if thumb_application_entry != 0x19879 {
        return Err(VerificationError::ThumbEntry {
            actual: thumb_application_entry,
        });
    }

    if wrappers.len() != WRAPPERS_SIZE {
        return Err(VerificationError::WrappersSize {
            actual: wrappers.len(),
        });
    }
    if wrappers
        != stock
            .get(WRAPPERS_ADDRESS..WRAPPERS_END)
            .ok_or(VerificationError::WrappersDifference)?
    {
        return Err(VerificationError::WrappersDifference);
    }
    if !STOCK_INTERRUPT_WRAPPERS_ARTIFACT.code_matches(wrappers) {
        return Err(VerificationError::WrappersIdentity);
    }
    let reserved = wrappers
        .get(0x10..0x20)
        .ok_or(VerificationError::ReservedGap)?;
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(VerificationError::ReservedGap);
    }
    for (offset, expected) in WRAPPER_WORDS {
        if read_u32(wrappers, offset)? != expected {
            return Err(VerificationError::WrapperInstructions);
        }
    }
    let mut interrupt_dispatch = [0_u32; 2];
    for (index, (source, expected)) in INTERRUPT_TARGETS.into_iter().enumerate() {
        let actual = arm_blx_target(wrappers, source)?;
        if actual != expected {
            return Err(VerificationError::InterruptTarget { source, actual });
        }
        *interrupt_dispatch
            .get_mut(index)
            .ok_or(VerificationError::InterruptTarget { source, actual })? = actual;
    }
    verify_elf(elf_bytes).map_err(VerificationError::Elf)?;

    Ok(SdkStartupReport {
        result: "PASS",
        stock_sha256: sha256(stock),
        startup_bytes: code.len(),
        startup_sha256: sha256(code),
        byte_exact: true,
        elf_entry: 0x2020,
        reset_target: 0x2064,
        thumb_application_entry,
        reset_calls,
        interrupt_wrapper_bytes: wrappers.len(),
        interrupt_wrapper_sha256: sha256(wrappers),
        interrupt_dispatch,
    })
}

fn arm_branch_target(code: &[u8], address: usize) -> Result<u32, VerificationError> {
    let offset = address
        .checked_sub(STARTUP_ADDRESS)
        .ok_or(VerificationError::WordUnavailable { offset: address })?;
    let instruction = read_array(code, offset)?;
    let source =
        u32::try_from(address).map_err(|_| VerificationError::WordUnavailable { offset })?;
    let (_, target) = decode_arm_branch(
        instruction,
        ArmAddress::new(source).map_err(VerificationError::Branch)?,
    )
    .map_err(VerificationError::Branch)?;
    Ok(target.get())
}

fn arm_blx_target(wrappers: &[u8], address: usize) -> Result<u32, VerificationError> {
    let offset = address
        .checked_sub(WRAPPERS_ADDRESS)
        .ok_or(VerificationError::WordUnavailable { offset: address })?;
    let instruction = read_array(wrappers, offset)?;
    let source =
        u32::try_from(address).map_err(|_| VerificationError::WordUnavailable { offset })?;
    Ok(decode_arm_blx(
        instruction,
        ArmAddress::new(source).map_err(VerificationError::Branch)?,
    )
    .map_err(VerificationError::Branch)?
    .get())
}

fn verify_elf(elf_bytes: &[u8]) -> Result<(), SdkElfError> {
    let elf = Elf32::parse(elf_bytes).map_err(SdkElfError::Elf)?;
    if elf.elf_type() != ELF_TYPE_EXECUTABLE {
        return Err(SdkElfError::WrongType {
            actual: elf.elf_type(),
        });
    }
    if elf.machine() != ELF_MACHINE_ARM {
        return Err(SdkElfError::WrongMachine {
            actual: elf.machine(),
        });
    }
    if elf.entry() != 0x2020 {
        return Err(SdkElfError::WrongEntry {
            actual: elf.entry(),
        });
    }
    let mut startup_found = false;
    let mut irq_found = false;
    let mut fiq_found = false;
    for section in elf.sections() {
        let section = section.map_err(SdkElfError::Elf)?;
        match section.name {
            ".startup" => {
                startup_found = true;
                if section.address != 0x2020
                    || section.size != 0x18c
                    || section.flags & (SECTION_FLAG_ALLOCATE | SECTION_FLAG_EXECUTE)
                        != SECTION_FLAG_ALLOCATE | SECTION_FLAG_EXECUTE
                {
                    return Err(SdkElfError::StartupLayout {
                        address: section.address,
                        size: section.size,
                        flags: section.flags,
                    });
                }
            },
            ".irq_wrapper" => {
                irq_found = true;
                if section.address != 0x2300 || section.size != 0x10 {
                    return Err(SdkElfError::IrqLayout {
                        address: section.address,
                        size: section.size,
                    });
                }
            },
            ".fiq_wrapper" => {
                fiq_found = true;
                if section.address != 0x2320 || section.size != 0x10 {
                    return Err(SdkElfError::FiqLayout {
                        address: section.address,
                        size: section.size,
                    });
                }
            },
            _ => {},
        }
        if section.is_relocation() {
            return Err(SdkElfError::Relocation);
        }
        if section.is_writable_allocated() {
            return Err(SdkElfError::WritableAllocated);
        }
    }
    if !startup_found {
        return Err(SdkElfError::StartupMissing);
    }
    if !irq_found {
        return Err(SdkElfError::IrqMissing);
    }
    if !fiq_found {
        return Err(SdkElfError::FiqMissing);
    }
    Ok(())
}

fn read_array(bytes: &[u8], offset: usize) -> Result<[u8; 4], VerificationError> {
    let end = offset
        .checked_add(4)
        .ok_or(VerificationError::WordUnavailable { offset })?;
    bytes
        .get(offset..end)
        .ok_or(VerificationError::WordUnavailable { offset })?
        .try_into()
        .map_err(|_| VerificationError::WordUnavailable { offset })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, VerificationError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
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
        stock: Vec<u8>,
        code: Vec<u8>,
        wrappers: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read SDK-startup fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build_dir = root.join("vendor/bk3633_sdk/SDK/projects/slimblade_wired/build");
        Some(Fixtures {
            stock: read_if_present(PathBuf::from("/tmp/slimblade-v449.bin"))?,
            code: read_if_present(build_dir.join("stock-startup-reference.bin"))?,
            wrappers: read_if_present(
                build_dir.join("stock-startup-reference.interrupt-wrappers.bin"),
            )?,
            elf: read_if_present(build_dir.join("stock-startup-reference.elf"))?,
        })
    }

    #[test]
    fn exact_source_build_passes() {
        let Some(data) = fixtures() else { return };
        let report = verify(&data.stock, &data.code, &data.wrappers, &data.elf)
            .expect("audited SDK startup");
        assert_eq!(report.result, "PASS");
        assert!(report.byte_exact);
        assert_eq!(report.reset_calls[1], 0x2140);
        assert_eq!(report.interrupt_dispatch[0], 0x3e78);
    }

    #[test]
    fn single_instruction_byte_change_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.code[0x7c] ^= 1;
        assert_eq!(
            verify(&data.stock, &data.code, &data.wrappers, &data.elf),
            Err(VerificationError::StartupDifference { address: 0x209c })
        );
    }

    #[test]
    fn wrong_stock_reference_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.stock[0x100] ^= 1;
        assert!(matches!(
            verify(&data.stock, &data.code, &data.wrappers, &data.elf),
            Err(VerificationError::StockIdentity(_))
        ));
    }

    #[test]
    fn single_wrapper_byte_change_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.wrappers[4] ^= 1;
        assert_eq!(
            verify(&data.stock, &data.code, &data.wrappers, &data.elf),
            Err(VerificationError::WrappersDifference)
        );
    }

    #[test]
    fn elf_entry_change_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.elf[24..28].copy_from_slice(&0x2064_u32.to_le_bytes());
        assert_eq!(
            verify(&data.stock, &data.code, &data.wrappers, &data.elf),
            Err(VerificationError::Elf(SdkElfError::WrongEntry {
                actual: 0x2064
            }))
        );
    }
}
