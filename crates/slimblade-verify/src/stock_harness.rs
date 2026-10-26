use core::fmt;

use slimblade_image::{
    APPLICATION_HEADER_OFFSET, FirmwareIdentityError, ImageError, STACK_HEADER_OFFSET,
    STARTUP_TRAMPOLINE, STOCK_HARNESS, STOCK_HARNESS_ARTIFACT, V449_BCD_DEVICE_OFFSET,
    parse_header, refresh_header_crc, sha256,
};

use crate::{
    ArmAddress, ArmBranchKind, BranchError, decode_arm_branch,
    elf::{ELF_MACHINE_ARM, ELF_TYPE_EXECUTABLE, Elf32, ElfError},
    encode_arm_b,
};

pub const INJECTION_ADDRESS: usize = 0x21ac;
pub const INJECTION_LIMIT: usize = 0x2300;
pub const AUDITED_INJECTION_SIZE: usize = INJECTION_LIMIT - INJECTION_ADDRESS;
pub const RESET_BRANCH_ADDRESS: usize = 0x2064;
pub const STARTUP_TRAMPOLINE_ADDRESS: u32 = 0x22cc;
pub const ARM_RESUME_ADDRESS: u32 = 0x22e8;
pub const FINAL_BRANCH_ADDRESS: u32 = 0x22f4;
const FINAL_BRANCH_OFFSET: usize = 0x0148;
pub const STOCK_RESET_CONTINUATION: u32 = 0x2068;
pub const THUMB_MARKER_ENTRY: u32 = 0x221b;

const DEVICE_VERSION_LOW: u8 = 0x55;
const CARRIER_DISPATCH: [u8; 18] = [
    0x0d, 0x28, 0x04, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x0f, 0x28, 0x0a, 0xd0, 0x0a, 0xe0, 0x34, 0x4b,
    0x18, 0x47,
];
const CRITICAL_WORDS: [(usize, u32); 18] = [
    (0x00e0, 0x0001_895d),
    (0x00e4, 0x0000_807c),
    (0x00e8, 0x0080_3000),
    (0x00ec, 0x7856_3412),
    (0x00f0, 0x0000_807d),
    (0x00f4, 0x19d2_bc9a),
    (0x00f8, 0x0001_78eb),
    (0x00fc, 0x0080_001c),
    (0x0100, ARM_RESUME_ADDRESS),
    (0x0104, 0x0080_6000),
    (0x0108, 0x0080_00c0),
    (0x010c, 0x00aa_5aaa),
    (0x0110, 0x005a_0050),
    (0x0114, 0x00a5_0050),
    (0x0118, 0x0000_58a9),
    (0x011c, 0x0000_a958),
    (0x014c, 0x0040_7f00),
    (0x0150, THUMB_MARKER_ENTRY),
];
const ARM_TRAMPOLINE_WORDS: [(usize, u32); 10] = [
    (0x0120, 0xe10f_a000),
    (0x0124, 0xe1a0_b00d),
    (0x0128, 0xe3a0_00d3),
    (0x012c, 0xe121_f000),
    (0x0130, 0xe59f_d014),
    (0x0134, 0xe59f_0014),
    (0x0138, 0xe12f_ff10),
    (0x013c, 0xe121_f00a),
    (0x0140, 0xe1a0_d00b),
    (0x0144, 0xe3a0_0000),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    BaseIdentity(FirmwareIdentityError),
    InjectionSize { actual: usize },
    InjectionIdentity,
    ImageLayout,
    Branch(BranchError),
    Image(ImageError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseIdentity(error) => write!(formatter, "v4.53 base: {error}"),
            Self::InjectionSize { actual } => write!(
                formatter,
                "stock-harness injection is {actual} bytes, not {AUDITED_INJECTION_SIZE}"
            ),
            Self::InjectionIdentity => {
                formatter.write_str("stock-harness injection identity changed")
            },
            Self::ImageLayout => formatter.write_str("v4.53 image layout is truncated"),
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
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Build(BuildError),
    DerivedImage,
    ContainerIdentity(FirmwareIdentityError),
    EmbeddedInjection,
    ResetBranchKind,
    ResetBranchTarget { actual: u32 },
    FinalBranchKind,
    FinalBranchTarget { actual: u32 },
    Branch(BranchError),
    BytesChanged { offset: usize },
    WordUnavailable { offset: usize },
    WordChanged { offset: usize, actual: u32 },
    ThumbEntryEven,
    ArmResumeOdd,
    StockInterruptWrappersChanged,
    StockUsbDispatchChanged,
    DeviceVersion { actual: u8 },
    Header(ImageError),
    HeaderCrc { offset: usize },
    Elf(ElfError),
    ElfType { actual: u16 },
    ElfMachine { actual: u16 },
    ElfEntry { actual: u32 },
    ElfSectionMissing { name: &'static str },
    ElfSectionGeometry { name: &'static str },
    ElfUnexpectedExecutable { name: String },
    ElfRelocation,
    ElfWritableAllocated,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => write!(formatter, "could not rebuild stock harness: {error}"),
            Self::DerivedImage => formatter.write_str("image is not an exact v4.53 derivation"),
            Self::ContainerIdentity(error) => write!(formatter, "stock harness: {error}"),
            Self::EmbeddedInjection => {
                formatter.write_str("container does not embed the audited injection exactly")
            },
            Self::ResetBranchKind => formatter.write_str("reset patch is not an ARM B"),
            Self::ResetBranchTarget { actual } => write!(
                formatter,
                "reset patch targets {actual:#x}, not {STARTUP_TRAMPOLINE_ADDRESS:#x}"
            ),
            Self::FinalBranchKind => formatter.write_str("startup return is not an ARM B"),
            Self::FinalBranchTarget { actual } => write!(
                formatter,
                "startup return targets {actual:#x}, not {STOCK_RESET_CONTINUATION:#x}"
            ),
            Self::Branch(error) => write!(formatter, "ARM branch: {error}"),
            Self::BytesChanged { offset } => {
                write!(
                    formatter,
                    "critical instruction bytes changed at +{offset:#x}"
                )
            },
            Self::WordUnavailable { offset } => {
                write!(formatter, "injection has no word at +{offset:#x}")
            },
            Self::WordChanged { offset, actual } => write!(
                formatter,
                "critical injection word at +{offset:#x} changed to {actual:#010x}"
            ),
            Self::ThumbEntryEven => formatter.write_str("marker startup entry is not Thumb-tagged"),
            Self::ArmResumeOdd => formatter.write_str("startup resume address is not ARM-aligned"),
            Self::StockInterruptWrappersChanged => {
                formatter.write_str("stock IRQ/FIQ wrappers changed")
            },
            Self::StockUsbDispatchChanged => {
                formatter.write_str("stock USB command dispatch patch changed")
            },
            Self::DeviceVersion { actual } => {
                write!(formatter, "bcdDevice low byte is {actual:#04x}, not 0x55")
            },
            Self::Header(error) => write!(formatter, "container header: {error}"),
            Self::HeaderCrc { offset } => {
                write!(formatter, "header CRC at {offset:#x} is invalid")
            },
            Self::Elf(error) => write!(formatter, "ELF: {error}"),
            Self::ElfType { actual } => write!(formatter, "ELF type is {actual}, not executable"),
            Self::ElfMachine { actual } => write!(formatter, "ELF machine is {actual}, not ARM"),
            Self::ElfEntry { actual } => write!(
                formatter,
                "ELF entry is {actual:#x}, not {STARTUP_TRAMPOLINE_ADDRESS:#x}"
            ),
            Self::ElfSectionMissing { name } => write!(formatter, "ELF has no {name} section"),
            Self::ElfSectionGeometry { name } => {
                write!(formatter, "ELF {name} address or size changed")
            },
            Self::ElfUnexpectedExecutable { name } => {
                write!(
                    formatter,
                    "ELF contains unexpected executable section {name}"
                )
            },
            Self::ElfRelocation => formatter.write_str("ELF contains relocations"),
            Self::ElfWritableAllocated => {
                formatter.write_str("ELF contains writable allocated data")
            },
        }
    }
}

impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::ContainerIdentity(error) => Some(error),
            Self::Branch(error) => Some(error),
            Self::Header(error) => Some(error),
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockHarnessReport {
    pub result: &'static str,
    pub base_sha256: [u8; 32],
    pub injection_bytes: usize,
    pub injection_sha256: [u8; 32],
    pub container_bytes: usize,
    pub container_sha256: [u8; 32],
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub reset_target: u32,
    pub marker_entry: u32,
    pub stock_return_target: u32,
    pub usb_bcd_device: u16,
}

/// Overlays the exact reviewed marker/carrier and reset trampoline on the exact v4.53 image.
///
/// # Errors
///
/// Returns an error unless both input identities and all image bounds are exact.
pub fn build(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, BuildError> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(BuildError::BaseIdentity)?;
    if injection.len() != AUDITED_INJECTION_SIZE {
        return Err(BuildError::InjectionSize {
            actual: injection.len(),
        });
    }
    if !STOCK_HARNESS_ARTIFACT.code_matches(injection) {
        return Err(BuildError::InjectionIdentity);
    }

    let mut image = base.to_vec();
    image
        .get_mut(INJECTION_ADDRESS..INJECTION_LIMIT)
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(injection);
    let reset_branch = encode_arm_b(
        ArmAddress::new(u32::try_from(RESET_BRANCH_ADDRESS).map_err(|_| BuildError::ImageLayout)?)
            .map_err(BuildError::Branch)?,
        ArmAddress::new(STARTUP_TRAMPOLINE_ADDRESS).map_err(BuildError::Branch)?,
    )
    .map_err(BuildError::Branch)?;
    image
        .get_mut(RESET_BRANCH_ADDRESS..RESET_BRANCH_ADDRESS + reset_branch.len())
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(&reset_branch);
    *image
        .get_mut(V449_BCD_DEVICE_OFFSET)
        .ok_or(BuildError::ImageLayout)? = DEVICE_VERSION_LOW;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(BuildError::Image)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(BuildError::Image)?;
    Ok(image)
}

/// Audits the complete marker-first stock harness and its linked ELF.
///
/// # Errors
///
/// Returns the first failed binary identity, instruction, branch, container, or ELF invariant.
#[allow(
    clippy::too_many_lines,
    reason = "a contiguous ordered audit keeps the recovery boundary reviewable"
)]
pub fn verify(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<StockHarnessReport, VerificationError> {
    let expected = build(base, injection).map_err(VerificationError::Build)?;
    if image != expected {
        return Err(VerificationError::DerivedImage);
    }
    if image.get(INJECTION_ADDRESS..INJECTION_LIMIT) != Some(injection) {
        return Err(VerificationError::EmbeddedInjection);
    }

    verify_branch(
        image,
        RESET_BRANCH_ADDRESS,
        STARTUP_TRAMPOLINE_ADDRESS,
        true,
    )?;
    verify_branch(
        injection,
        FINAL_BRANCH_OFFSET,
        STOCK_RESET_CONTINUATION,
        false,
    )?;

    if injection.get(..CARRIER_DISPATCH.len()) != Some(CARRIER_DISPATCH.as_slice()) {
        return Err(VerificationError::BytesChanged { offset: 0 });
    }
    for (offset, expected) in CRITICAL_WORDS.into_iter().chain(ARM_TRAMPOLINE_WORDS) {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(VerificationError::WordChanged { offset, actual });
        }
    }
    if read_u32(injection, 0x0150)? & 1 == 0 {
        return Err(VerificationError::ThumbEntryEven);
    }
    if read_u32(injection, 0x0100)? & 1 != 0 {
        return Err(VerificationError::ArmResumeOdd);
    }
    if image.get(0x2300..0x2330) != base.get(0x2300..0x2330) {
        return Err(VerificationError::StockInterruptWrappersChanged);
    }
    if image.get(0x18f9a..0x18fbe) != base.get(0x18f9a..0x18fbe) {
        return Err(VerificationError::StockUsbDispatchChanged);
    }
    let device_version = image
        .get(V449_BCD_DEVICE_OFFSET)
        .copied()
        .ok_or(VerificationError::DeviceVersion { actual: 0 })?;
    if device_version != DEVICE_VERSION_LOW {
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
    verify_elf(elf_bytes)?;

    let payload = STOCK_HARNESS
        .validate(image)
        .map_err(VerificationError::ContainerIdentity)?;
    Ok(StockHarnessReport {
        result: "PASS",
        base_sha256: sha256(base),
        injection_bytes: injection.len(),
        injection_sha256: sha256(injection),
        container_bytes: image.len(),
        container_sha256: sha256(image),
        payload_bytes: payload.len(),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        reset_target: STARTUP_TRAMPOLINE_ADDRESS,
        marker_entry: THUMB_MARKER_ENTRY,
        stock_return_target: STOCK_RESET_CONTINUATION,
        usb_bcd_device: 0x0455,
    })
}

fn verify_branch(
    bytes: &[u8],
    offset: usize,
    expected_target: u32,
    reset: bool,
) -> Result<(), VerificationError> {
    let instruction = read_array(bytes, offset)?;
    let absolute = if reset {
        u32::try_from(offset).map_err(|_| VerificationError::WordUnavailable { offset })?
    } else {
        u32::try_from(INJECTION_ADDRESS + offset)
            .map_err(|_| VerificationError::WordUnavailable { offset })?
    };
    let (kind, target) = decode_arm_branch(
        instruction,
        ArmAddress::new(absolute).map_err(VerificationError::Branch)?,
    )
    .map_err(VerificationError::Branch)?;
    if kind != ArmBranchKind::Branch {
        return Err(if reset {
            VerificationError::ResetBranchKind
        } else {
            VerificationError::FinalBranchKind
        });
    }
    if target.get() != expected_target {
        return Err(if reset {
            VerificationError::ResetBranchTarget {
                actual: target.get(),
            }
        } else {
            VerificationError::FinalBranchTarget {
                actual: target.get(),
            }
        });
    }
    Ok(())
}

fn verify_elf(elf_bytes: &[u8]) -> Result<(), VerificationError> {
    let elf = Elf32::parse(elf_bytes).map_err(VerificationError::Elf)?;
    if elf.elf_type() != ELF_TYPE_EXECUTABLE {
        return Err(VerificationError::ElfType {
            actual: elf.elf_type(),
        });
    }
    if elf.machine() != ELF_MACHINE_ARM {
        return Err(VerificationError::ElfMachine {
            actual: elf.machine(),
        });
    }
    if elf.entry() != STARTUP_TRAMPOLINE_ADDRESS {
        return Err(VerificationError::ElfEntry {
            actual: elf.entry(),
        });
    }
    let mut carrier = false;
    let mut trampoline = false;
    for section in elf.sections() {
        let section = section.map_err(VerificationError::Elf)?;
        if section.is_relocation() {
            return Err(VerificationError::ElfRelocation);
        }
        if section.is_writable_allocated() {
            return Err(VerificationError::ElfWritableAllocated);
        }
        if !section.is_allocated_executable() {
            continue;
        }
        match section.name {
            ".carrier" => {
                carrier = true;
                if section.address != 0x21ac || section.size != 0x120 {
                    return Err(VerificationError::ElfSectionGeometry { name: ".carrier" });
                }
            },
            ".trampoline" => {
                trampoline = true;
                if section.address != 0x22cc || section.size != 0x34 {
                    return Err(VerificationError::ElfSectionGeometry {
                        name: ".trampoline",
                    });
                }
            },
            name => {
                return Err(VerificationError::ElfUnexpectedExecutable {
                    name: name.to_owned(),
                });
            },
        }
    }
    if !carrier {
        return Err(VerificationError::ElfSectionMissing { name: ".carrier" });
    }
    if !trampoline {
        return Err(VerificationError::ElfSectionMissing {
            name: ".trampoline",
        });
    }
    Ok(())
}

fn read_array(bytes: &[u8], offset: usize) -> Result<[u8; 4], VerificationError> {
    bytes
        .get(offset..offset.saturating_add(4))
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
    reason = "tests mutate bounded generated fixtures and expect audited results"
)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    struct Fixtures {
        base: Vec<u8>,
        injection: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read generated stock-harness fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let harness = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(
                harness.join("harness/DO_NOT_FLASH-stock-harness.injection.bin"),
            )?,
            elf: read_if_present(
                harness.join("thumbv5te-none-eabi/release/slimblade-stock-harness"),
            )?,
        })
    }

    #[test]
    fn exact_build_and_audit_pass() {
        let Some(data) = fixtures() else { return };
        let image = build(&data.base, &data.injection).expect("build exact stock harness");
        let report = verify(&data.base, &image, &data.injection, &data.elf)
            .expect("audit exact stock harness");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.injection_bytes, 340);
        assert_eq!(report.reset_target, 0x22cc);
        assert_eq!(report.marker_entry, 0x221b);
        assert_eq!(report.stock_return_target, 0x2068);
    }

    #[test]
    fn one_byte_injection_change_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[0x30] ^= 1;
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::InjectionIdentity)
        ));
    }

    #[test]
    fn changed_base_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.base[0] ^= 1;
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::BaseIdentity(_))
        ));
    }

    #[test]
    fn reset_branch_corruption_is_rejected() {
        let Some(data) = fixtures() else { return };
        let mut image = build(&data.base, &data.injection).expect("build exact stock harness");
        image[RESET_BRANCH_ADDRESS] ^= 1;
        assert!(verify(&data.base, &image, &data.injection, &data.elf).is_err());
    }
}
