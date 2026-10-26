use core::fmt;

use slimblade_image::{
    APPLICATION_HEADER_OFFSET, ArtifactIdentity, FirmwareIdentity, FirmwareIdentityError,
    ImageError, LATE_MARKER_PROBE, LATE_MARKER_PROBE_ARTIFACT, STACK_HEADER_OFFSET,
    STARTUP_TRAMPOLINE, V449_BCD_DEVICE_OFFSET, parse_header, refresh_header_crc, sha256,
};

use crate::{
    ArmAddress, ArmBranchKind, BranchError, decode_arm_branch,
    elf::{ELF_MACHINE_ARM, ELF_TYPE_EXECUTABLE, Elf32, ElfError},
    encode_arm_b,
};

pub const INJECTION_ADDRESS: usize = 0x21ac;
pub const INJECTION_LIMIT: usize = 0x2300;
pub const INJECTION_SIZE: usize = INJECTION_LIMIT - INJECTION_ADDRESS;
pub const RESET_BRANCH_ADDRESS: usize = 0x2064;
pub const TRAMPOLINE_ADDRESS: u32 = 0x22cc;
pub const STOCK_CONTINUATION: u32 = 0x2068;
pub const STOCK_RESUME_POINTER: u32 = 0x2213;
const FINAL_BRANCH_OFFSET: usize = 0x0148;
const CARRIER_EXECUTABLE_BYTES: usize = 0x0114;
const CARRIER_EXECUTABLE_SIZE: u32 = 0x0114;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProbeSpec {
    pub artifact: ArtifactIdentity,
    pub identity: FirmwareIdentity,
    pub dispatch: [u8; 18],
    pub marker_entry_tail: [u8; 2],
    pub response_shim: Option<[u8; 8]>,
    pub gap: [u8; 12],
    pub probe_section_size: u32,
    pub device_version_low: u8,
    pub usb_bcd_device: u16,
}

const LATE_MARKER_SPEC: ProbeSpec = ProbeSpec {
    artifact: LATE_MARKER_PROBE_ARTIFACT,
    identity: LATE_MARKER_PROBE,
    dispatch: DISPATCH,
    marker_entry_tail: [0x10, 0xbd],
    response_shim: None,
    gap: [0; 12],
    probe_section_size: 0,
    device_version_low: 0x56,
    usb_bcd_device: 0x0456,
};

const DISPATCH: [u8; 18] = [
    0x0d, 0x28, 0x04, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x0f, 0x28, 0x06, 0xd0, 0x06, 0xe0, 0x31, 0x4b,
    0x18, 0x47,
];
const MARKER_ENTRY_PREFIX: [u8; 6] = [0x10, 0xb5, 0x00, 0xf0, 0x05, 0xf8];
const STOCK_RESUME: [u8; 4] = [0x23, 0x48, 0x00, 0x47];
const CRITICAL_WORDS: [(usize, u32); 17] = [
    (0x00d4, 0x0001_895d),
    (0x00d8, 0x0080_3000),
    (0x00dc, 0x0000_807c),
    (0x00e0, 0x7856_3412),
    (0x00e4, 0x0000_807d),
    (0x00e8, 0x19d2_bc9a),
    (0x00ec, 0x0001_78eb),
    (0x00f0, 0x0080_001c),
    (0x00f4, 0x0000_22e8),
    (0x00f8, 0x0080_6000),
    (0x00fc, 0x0080_00c0),
    (0x0100, 0x00aa_5aaa),
    (0x0104, 0x005a_0050),
    (0x0108, 0x00a5_0050),
    (0x010c, 0x0000_58a9),
    (0x0110, 0x0000_a958),
    (0x0150, STOCK_RESUME_POINTER),
];
const ARM_WORDS: [(usize, u32); 12] = [
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
    (0x014c, 0x0040_7f00),
    (0x0150, STOCK_RESUME_POINTER),
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
            Self::InjectionSize { actual } => {
                write!(
                    formatter,
                    "stock-marker injection is {actual} bytes, not {INJECTION_SIZE}"
                )
            },
            Self::InjectionIdentity => formatter.write_str("stock-marker injection hash changed"),
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
    BytesChanged { offset: usize },
    WordUnavailable { offset: usize },
    WordChanged { offset: usize, actual: u32 },
    ResetBranch,
    StockBranch,
    Branch(BranchError),
    StartupMarkerCall,
    UnusedGap,
    InterruptWrappers,
    StockDispatch,
    DeviceVersion { actual: u8 },
    Header(ImageError),
    HeaderCrc { offset: usize },
    Elf(ElfError),
    ElfInvariant(&'static str),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => {
                write!(formatter, "could not rebuild stock-marker probe: {error}")
            },
            Self::DerivedImage => formatter.write_str("image is not an exact v4.53 derivation"),
            Self::ContainerIdentity(error) => write!(formatter, "stock-marker probe: {error}"),
            Self::BytesChanged { offset } => write!(formatter, "bytes changed at +{offset:#x}"),
            Self::WordUnavailable { offset } => write!(formatter, "no word at +{offset:#x}"),
            Self::WordChanged { offset, actual } => {
                write!(formatter, "word at +{offset:#x} changed to {actual:#010x}")
            },
            Self::ResetBranch => formatter.write_str("reset branch does not target 0x22cc"),
            Self::StockBranch => formatter.write_str("trampoline does not return to stock 0x2068"),
            Self::Branch(error) => write!(formatter, "ARM branch: {error}"),
            Self::StartupMarkerCall => {
                formatter.write_str("reset-side Thumb wrapper is not the no-marker stock resume")
            },
            Self::UnusedGap => formatter.write_str("pre-trampoline gap is not zero-filled"),
            Self::InterruptWrappers => formatter.write_str("stock IRQ/FIQ wrappers changed"),
            Self::StockDispatch => formatter.write_str("stock USB dispatcher patch changed"),
            Self::DeviceVersion { actual } => {
                write!(formatter, "unexpected bcdDevice low byte {actual:#04x}")
            },
            Self::Header(error) => write!(formatter, "container header: {error}"),
            Self::HeaderCrc { offset } => write!(formatter, "header CRC at {offset:#x} is invalid"),
            Self::Elf(error) => write!(formatter, "ELF: {error}"),
            Self::ElfInvariant(message) => formatter.write_str(message),
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
pub struct LateMarkerReport {
    pub result: &'static str,
    pub injection_bytes: usize,
    pub injection_sha256: [u8; 32],
    pub container_bytes: usize,
    pub container_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub late_marker_entry: u32,
    pub stock_resume_pointer: u32,
    pub usb_bcd_device: u16,
}

/// Builds the compatibility probe only from exact v4.53 and exact linked injection identities.
///
/// # Errors
///
/// Returns an error for any identity, size, branch, layout, or header mismatch.
pub fn build(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, BuildError> {
    build_with_spec(base, injection, LATE_MARKER_SPEC)
}

pub(crate) fn build_with_spec(
    base: &[u8],
    injection: &[u8],
    spec: ProbeSpec,
) -> Result<Vec<u8>, BuildError> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(BuildError::BaseIdentity)?;
    if injection.len() != INJECTION_SIZE {
        return Err(BuildError::InjectionSize {
            actual: injection.len(),
        });
    }
    if !spec.artifact.code_matches(injection) {
        return Err(BuildError::InjectionIdentity);
    }
    let mut image = base.to_vec();
    image
        .get_mut(INJECTION_ADDRESS..INJECTION_LIMIT)
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(injection);
    let branch = encode_arm_b(
        ArmAddress::new(u32::try_from(RESET_BRANCH_ADDRESS).map_err(|_| BuildError::ImageLayout)?)
            .map_err(BuildError::Branch)?,
        ArmAddress::new(TRAMPOLINE_ADDRESS).map_err(BuildError::Branch)?,
    )
    .map_err(BuildError::Branch)?;
    image
        .get_mut(RESET_BRANCH_ADDRESS..RESET_BRANCH_ADDRESS + 4)
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(&branch);
    *image
        .get_mut(V449_BCD_DEVICE_OFFSET)
        .ok_or(BuildError::ImageLayout)? = spec.device_version_low;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(BuildError::Image)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(BuildError::Image)?;
    Ok(image)
}

/// Audits the complete late-marker compatibility probe.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, container, or ELF invariant.
#[allow(
    clippy::too_many_lines,
    reason = "a contiguous ordered audit keeps the recovery boundary reviewable"
)]
pub fn verify(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<LateMarkerReport, VerificationError> {
    verify_with_spec(base, image, injection, elf_bytes, LATE_MARKER_SPEC)
}

#[allow(
    clippy::too_many_lines,
    reason = "a contiguous ordered audit keeps the recovery boundary reviewable"
)]
pub(crate) fn verify_with_spec(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
    spec: ProbeSpec,
) -> Result<LateMarkerReport, VerificationError> {
    let expected = build_with_spec(base, injection, spec).map_err(VerificationError::Build)?;
    if image != expected {
        return Err(VerificationError::DerivedImage);
    }
    require_bytes(injection, 0, &spec.dispatch)?;
    require_bytes(injection, 0x12, &MARKER_ENTRY_PREFIX)?;
    require_bytes(injection, 0x18, &spec.marker_entry_tail)?;
    if let Some(response_shim) = spec.response_shim {
        require_bytes(injection, 0x1a, &response_shim)?;
    }
    require_bytes(injection, 0x66, &STOCK_RESUME)?;
    for (offset, expected) in CRITICAL_WORDS.into_iter().chain(ARM_WORDS) {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(VerificationError::WordChanged { offset, actual });
        }
    }
    if read_u32(injection, 0x150)? != STOCK_RESUME_POINTER {
        return Err(VerificationError::StartupMarkerCall);
    }
    if injection.get(CARRIER_EXECUTABLE_BYTES..0x120) != Some(spec.gap.as_slice()) {
        return Err(VerificationError::UnusedGap);
    }
    verify_arm_branch(
        image,
        RESET_BRANCH_ADDRESS,
        u32::try_from(RESET_BRANCH_ADDRESS).map_err(|_| VerificationError::WordUnavailable {
            offset: RESET_BRANCH_ADDRESS,
        })?,
        TRAMPOLINE_ADDRESS,
    )
    .map_err(|error| match error {
        VerificationError::Branch(branch) => VerificationError::Branch(branch),
        _ => VerificationError::ResetBranch,
    })?;
    verify_arm_branch(injection, FINAL_BRANCH_OFFSET, 0x22f4, STOCK_CONTINUATION).map_err(
        |error| match error {
            VerificationError::Branch(branch) => VerificationError::Branch(branch),
            _ => VerificationError::StockBranch,
        },
    )?;
    if image.get(0x2300..0x2330) != base.get(0x2300..0x2330) {
        return Err(VerificationError::InterruptWrappers);
    }
    if image.get(0x18f9a..0x18fbe) != base.get(0x18f9a..0x18fbe) {
        return Err(VerificationError::StockDispatch);
    }
    let version = image
        .get(V449_BCD_DEVICE_OFFSET)
        .copied()
        .ok_or(VerificationError::DeviceVersion { actual: 0 })?;
    if version != spec.device_version_low {
        return Err(VerificationError::DeviceVersion { actual: version });
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
    verify_elf(elf_bytes, spec)?;
    let payload = spec
        .identity
        .validate(image)
        .map_err(VerificationError::ContainerIdentity)?;
    Ok(LateMarkerReport {
        result: "PASS",
        injection_bytes: injection.len(),
        injection_sha256: sha256(injection),
        container_bytes: image.len(),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        late_marker_entry: 0x21be,
        stock_resume_pointer: STOCK_RESUME_POINTER,
        usb_bcd_device: spec.usb_bcd_device,
    })
}

fn require_bytes(bytes: &[u8], offset: usize, expected: &[u8]) -> Result<(), VerificationError> {
    if bytes.get(offset..offset.saturating_add(expected.len())) == Some(expected) {
        Ok(())
    } else {
        Err(VerificationError::BytesChanged { offset })
    }
}

fn verify_arm_branch(
    bytes: &[u8],
    offset: usize,
    source: u32,
    target: u32,
) -> Result<(), VerificationError> {
    let (kind, actual) = decode_arm_branch(
        read_array(bytes, offset)?,
        ArmAddress::new(source).map_err(VerificationError::Branch)?,
    )
    .map_err(VerificationError::Branch)?;
    if kind == ArmBranchKind::Branch && actual.get() == target {
        Ok(())
    } else {
        Err(VerificationError::ResetBranch)
    }
}

fn verify_elf(bytes: &[u8], spec: ProbeSpec) -> Result<(), VerificationError> {
    let elf = Elf32::parse(bytes).map_err(VerificationError::Elf)?;
    if elf.elf_type() != ELF_TYPE_EXECUTABLE
        || elf.machine() != ELF_MACHINE_ARM
        || elf.entry() != TRAMPOLINE_ADDRESS
    {
        return Err(VerificationError::ElfInvariant(
            "ELF header identity changed",
        ));
    }
    let mut carrier = false;
    let mut probe = spec.probe_section_size == 0;
    let mut trampoline = false;
    for section in elf.sections() {
        let section = section.map_err(VerificationError::Elf)?;
        if section.is_relocation() || section.is_writable_allocated() {
            return Err(VerificationError::ElfInvariant(
                "ELF has relocations or writable allocated data",
            ));
        }
        if !section.is_allocated_executable() {
            continue;
        }
        match section.name {
            ".carrier" if section.address == 0x21ac && section.size == CARRIER_EXECUTABLE_SIZE => {
                carrier = true;
            },
            ".probe" if section.address == 0x22c0 && section.size == spec.probe_section_size => {
                probe = true;
            },
            ".trampoline" if section.address == 0x22cc && section.size == 0x34 => {
                trampoline = true;
            },
            _ => {
                return Err(VerificationError::ElfInvariant(
                    "ELF executable section geometry changed",
                ));
            },
        }
    }
    if !carrier || !probe || !trampoline {
        return Err(VerificationError::ElfInvariant(
            "ELF is missing a reviewed executable section",
        ));
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
        container: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read late-marker fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(
                target.join("late-marker/DO_NOT_FLASH-late-marker-probe.injection.bin"),
            )?,
            container: read_if_present(
                target.join("late-marker/DO_NOT_FLASH-late-marker-probe.container.bin"),
            )?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-late-marker-probe"),
            )?,
        })
    }

    #[test]
    fn exact_probe_rebuilds_and_passes() {
        let Some(data) = fixtures() else { return };
        assert_eq!(
            build(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify(&data.base, &data.container, &data.injection, &data.elf)
            .expect("audit exact late-marker probe");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.late_marker_entry, 0x21be);
        assert_eq!(report.stock_resume_pointer, 0x2213);
        assert_eq!(report.payload_crc, 0xf3ce_f231);
    }

    #[test]
    fn changed_late_marker_call_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[0x16] ^= 1;
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::InjectionIdentity)
        ));
    }

    #[test]
    fn startup_pointer_to_marker_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[0x150..0x154].copy_from_slice(&0x21cf_u32.to_le_bytes());
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
}
