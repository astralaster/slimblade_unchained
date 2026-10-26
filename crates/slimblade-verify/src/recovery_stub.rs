use core::fmt;

use slimblade_image::{
    APPLICATION_CODE_OFFSET, APPLICATION_HEADER_OFFSET, APPLICATION_PREFIX_OFFSET, APPLICATION_UID,
    FirmwareIdentityError, ImageError, OFFICIAL_APPLICATION_END_OFFSET, OFFICIAL_V449,
    OFFICIAL_V449_SIZE, RECOVERY_CARRIER, RECOVERY_STUB, RECOVERY_STUB_ARTIFACT,
    STARTUP_TRAMPOLINE, make_application_container, parse_header, sha256,
};

use crate::{
    BranchError, ThumbAddress, decode_thumb_bl,
    elf::{ELF_MACHINE_ARM, ELF_TYPE_EXECUTABLE, Elf32, ElfError},
};

pub const AUDITED_CODE_SIZE: usize = 420;
pub const EXPECTED_PAYLOAD_SIZE: usize = OFFICIAL_V449_SIZE - APPLICATION_PREFIX_OFFSET;
pub const EXPECTED_BLOCK_COUNT: usize = EXPECTED_PAYLOAD_SIZE.div_ceil(32);

const ERASED_PREFIX: [u8; 16] = [0xff; 16];
const RESET_SEQUENCE: [u8; 28] = [
    0xd3, 0x00, 0xa0, 0xe3, 0x00, 0xf0, 0x21, 0xe1, 0x04, 0xd0, 0x9f, 0xe5, 0x04, 0x00, 0x9f, 0xe5,
    0x10, 0xff, 0x2f, 0xe1, 0x00, 0x7f, 0x40, 0x00, 0x81, 0x20, 0x00, 0x00,
];
const STORAGE_SEQUENCE: [u8; 52] = [
    0x0c, 0x49, 0x0d, 0x4a, 0x0a, 0x60, 0x0d, 0x4a, 0x0a, 0x60, 0xa5, 0x22, 0x0a, 0x61, 0xc3, 0x22,
    0x4a, 0x61, 0x4a, 0x68, 0x7c, 0x23, 0x9a, 0x43, 0x02, 0x43, 0x4a, 0x60, 0x01, 0x20, 0x10, 0x43,
    0x48, 0x60, 0x48, 0x68, 0xc0, 0x07, 0xfc, 0xd1, 0x00, 0x20, 0x08, 0x60, 0x08, 0x60, 0x08, 0x61,
    0x48, 0x61, 0x70, 0x47,
];
const ERASE_WRITE_SEQUENCE: [u8; 40] = [
    0x80, 0xb5, 0x01, 0x20, 0xc0, 0x03, 0x03, 0x49, 0x08, 0x60, 0x28, 0x20, 0x00, 0xf0, 0x2c, 0xf8,
    0x80, 0xbd, 0xc0, 0x46, 0x08, 0x30, 0x80, 0x00, 0x80, 0xb5, 0x03, 0x4a, 0x10, 0x60, 0x51, 0x60,
    0x24, 0x20, 0x00, 0xf0, 0x21, 0xf8, 0x80, 0xbd,
];
const DELAY_SEQUENCE: [u8; 76] = [
    0x70, 0xb5, 0x0d, 0x00, 0x04, 0x00, 0x0c, 0xe0, 0x6a, 0x22, 0x01, 0x20, 0x00, 0xf0, 0x10, 0xf8,
    0x10, 0x00, 0x52, 0x1e, 0x12, 0x06, 0x12, 0x0e, 0x00, 0x28, 0xf6, 0xd1, 0x00, 0x2d, 0x00, 0xd0,
    0xc0, 0x46, 0x20, 0x00, 0x64, 0x1e, 0x24, 0x04, 0x24, 0x0c, 0x00, 0x28, 0xec, 0xd1, 0x70, 0xbd,
    0x05, 0xe0, 0x00, 0x21, 0x49, 0x1c, 0x09, 0x06, 0x09, 0x0e, 0x11, 0x29, 0xfa, 0xd3, 0x01, 0x00,
    0x40, 0x1e, 0x00, 0x06, 0x00, 0x0e, 0x00, 0x29, 0xf3, 0xd1, 0x70, 0x47,
];
const WATCHDOG_SEQUENCE: [u8; 44] = [
    0x0a, 0x49, 0x01, 0x20, 0x08, 0x60, 0x2d, 0x20, 0x42, 0x04, 0x09, 0x48, 0x02, 0x60, 0xa5, 0x23,
    0x1b, 0x04, 0x03, 0x60, 0x07, 0x4c, 0x08, 0x4d, 0x25, 0x60, 0x00, 0x24, 0x0c, 0x60, 0x50, 0x21,
    0x01, 0x60, 0x50, 0x32, 0x02, 0x60, 0x50, 0x33, 0x03, 0x60, 0xfe, 0xe7,
];

const CALL_GRAPH: [(usize, u32); 8] = [
    (0x2080, 0x2084),
    (0x2098, 0x20d0),
    (0x20a2, 0x20e8),
    (0x20aa, 0x20e8),
    (0x20b2, 0x2178),
    (0x20b6, 0x20fc),
    (0x20dc, 0x2138),
    (0x20f2, 0x2138),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    StockIdentity(FirmwareIdentityError),
    CarrierIdentity(FirmwareIdentityError),
    StartupIdentity(FirmwareIdentityError),
    StubIdentity(FirmwareIdentityError),
    Image(ImageError),
    ContainerSize,
    HeaderCrc,
    HeaderGeometry,
    ApplicationUid,
    PrefixPadding,
    CodeSize { actual: usize },
    EmbeddedCode,
    ErasedPadding,
    VectorGeometry,
    ResetSequence,
    StartupOperations,
    StartupLiteral,
    StartupState,
    CallGraph,
    StorageUnlock,
    StorageSequence,
    StorageCarrierMismatch,
    MarkerSequence,
    EraseWriteSequence,
    DelaySequence,
    DelayStockMismatch,
    WatchdogSequence,
    Elf(StubElfError),
    CodeIdentity,
    DerivedContainer,
    PayloadSize,
    WordUnavailable { offset: usize },
    Branch(BranchError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StockIdentity(error) => write!(formatter, "stock v4.49: {error}"),
            Self::CarrierIdentity(error) => write!(formatter, "live recovery carrier: {error}"),
            Self::StartupIdentity(error) => write!(formatter, "live-tested v4.53: {error}"),
            Self::StubIdentity(error) => write!(formatter, "recovery stub: {error}"),
            Self::Image(error) => write!(formatter, "application image: {error}"),
            Self::ContainerSize => formatter.write_str("container size differs from stock"),
            Self::HeaderCrc => formatter.write_str("application CRC is invalid"),
            Self::HeaderGeometry => {
                formatter.write_str("application header geometry differs from stock")
            },
            Self::ApplicationUid => formatter.write_str("application UID is wrong"),
            Self::PrefixPadding => {
                formatter.write_str("non-transmitted application prefix is not erased padding")
            },
            Self::CodeSize { actual } => {
                write!(formatter, "raw recovery code is {actual} bytes, not 420")
            },
            Self::EmbeddedCode => {
                formatter.write_str("container does not contain the supplied raw code")
            },
            Self::ErasedPadding => {
                formatter.write_str("bytes after recovery code are not erased padding")
            },
            Self::VectorGeometry => formatter.write_str("vector table geometry differs from stock"),
            Self::ResetSequence => formatter.write_str("minimal reset sequence changed"),
            Self::StartupOperations => formatter
                .write_str("standalone reset operations differ from the live-tested trampoline"),
            Self::StartupLiteral => {
                formatter.write_str("startup literal placement or value changed")
            },
            Self::StartupState => formatter.write_str("startup entry does not request Thumb state"),
            Self::CallGraph => formatter.write_str("standalone recovery call graph changed"),
            Self::StorageUnlock => {
                formatter.write_str("storage unlock order or controller base changed")
            },
            Self::StorageSequence => {
                formatter.write_str("emitted storage-controller instruction sequence changed")
            },
            Self::StorageCarrierMismatch => formatter
                .write_str("storage-controller core differs from live-proven carrier bytes"),
            Self::MarkerSequence => formatter.write_str("loader marker address or bytes changed"),
            Self::EraseWriteSequence => formatter.write_str("erase/write command emission changed"),
            Self::DelaySequence => formatter.write_str("stock-equivalent assembly delay changed"),
            Self::DelayStockMismatch => formatter.write_str("delay instructions differ from stock"),
            Self::WatchdogSequence => formatter.write_str("watchdog/reset sequence changed"),
            Self::Elf(error) => write!(formatter, "{error}"),
            Self::CodeIdentity => formatter.write_str("raw code differs from the audited build"),
            Self::DerivedContainer => {
                formatter.write_str("container is not the exact generated recovery image")
            },
            Self::PayloadSize => formatter.write_str("transmitted payload size changed"),
            Self::WordUnavailable { offset } => write!(formatter, "no word at {offset:#x}"),
            Self::Branch(error) => write!(formatter, "Thumb branch: {error}"),
        }
    }
}

impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::StockIdentity(error)
            | Self::CarrierIdentity(error)
            | Self::StartupIdentity(error)
            | Self::StubIdentity(error) => Some(error),
            Self::Image(error) => Some(error),
            Self::Elf(error) => Some(error),
            Self::Branch(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StubElfError {
    Elf(ElfError),
    WrongType { actual: u16 },
    WrongMachine { actual: u16 },
    WrongEntry { actual: u32 },
    VectorsMissing,
    WrongVectors { address: u32, size: u32 },
    TextMissing,
    WrongTextAddress { actual: u32 },
    Relocation,
    WritableAllocated,
}

impl fmt::Display for StubElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => write!(formatter, "ELF: {error}"),
            Self::WrongType { actual } => write!(formatter, "ELF type is {actual}, not executable"),
            Self::WrongMachine { actual } => write!(formatter, "ELF machine is {actual}, not ARM"),
            Self::WrongEntry { actual } => {
                write!(formatter, "ELF entry is {actual:#x}, not 0x2020")
            },
            Self::VectorsMissing => formatter.write_str("ELF has no .vectors section"),
            Self::WrongVectors { address, size } => write!(
                formatter,
                "ELF .vectors is at {address:#x} with size {size:#x}"
            ),
            Self::TextMissing => formatter.write_str("ELF has no .text section"),
            Self::WrongTextAddress { actual } => {
                write!(formatter, "ELF .text address is {actual:#x}, not 0x2080")
            },
            Self::Relocation => formatter.write_str("ELF contains relocations"),
            Self::WritableAllocated => formatter.write_str("ELF contains writable allocated data"),
        }
    }
}

impl core::error::Error for StubElfError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryStubReport {
    pub result: &'static str,
    pub stock_sha256: [u8; 32],
    pub code_bytes: usize,
    pub code_sha256: [u8; 32],
    pub container_bytes: usize,
    pub container_sha256: [u8; 32],
    pub application_crc: u32,
    pub application_end: usize,
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub b1_blocks: usize,
    pub elf_entry: u32,
    pub startup_stack: u32,
    pub call_targets: [u32; 8],
}

/// Builds the standalone recovery container from linked code.
///
/// # Errors
///
/// Returns an error if the code is empty or does not fit the recorded application geometry.
pub fn build(code: &[u8]) -> Result<Vec<u8>, ImageError> {
    make_application_container(code, 3, Some(OFFICIAL_APPLICATION_END_OFFSET))
}

/// Performs the complete structural and cryptographic recovery-stub audit.
///
/// # Errors
///
/// Returns the first failed reference, header, instruction, call, MMIO, ELF, or identity invariant.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the ordered recovery audit contiguous makes the safety boundary reviewable"
)]
pub fn verify(
    stock: &[u8],
    container: &[u8],
    code: &[u8],
    elf_bytes: &[u8],
    carrier: &[u8],
    startup_trampoline: &[u8],
) -> Result<RecoveryStubReport, VerificationError> {
    OFFICIAL_V449
        .validate(stock)
        .map_err(VerificationError::StockIdentity)?;
    RECOVERY_CARRIER
        .validate(carrier)
        .map_err(VerificationError::CarrierIdentity)?;
    if container.len() != stock.len() {
        return Err(VerificationError::ContainerSize);
    }

    let stock_header =
        parse_header(stock, APPLICATION_HEADER_OFFSET).map_err(VerificationError::Image)?;
    let stub_header =
        parse_header(container, APPLICATION_HEADER_OFFSET).map_err(VerificationError::Image)?;
    if !stub_header
        .crc_is_valid(container)
        .map_err(VerificationError::Image)?
    {
        return Err(VerificationError::HeaderCrc);
    }
    if stub_header.end_offset().map_err(VerificationError::Image)?
        != OFFICIAL_APPLICATION_END_OFFSET
        || !same_header_geometry(stock_header, stub_header)
    {
        return Err(VerificationError::HeaderGeometry);
    }
    if stub_header.uid != APPLICATION_UID {
        return Err(VerificationError::ApplicationUid);
    }
    if container.get(APPLICATION_PREFIX_OFFSET..APPLICATION_HEADER_OFFSET)
        != Some(ERASED_PREFIX.as_slice())
    {
        return Err(VerificationError::PrefixPadding);
    }
    if code.len() != AUDITED_CODE_SIZE {
        return Err(VerificationError::CodeSize { actual: code.len() });
    }
    let code_end = APPLICATION_CODE_OFFSET
        .checked_add(code.len())
        .ok_or(VerificationError::EmbeddedCode)?;
    if container.get(APPLICATION_CODE_OFFSET..code_end) != Some(code) {
        return Err(VerificationError::EmbeddedCode);
    }
    let padding = container
        .get(code_end..)
        .ok_or(VerificationError::ErasedPadding)?;
    if padding.iter().any(|byte| *byte != 0xff) {
        return Err(VerificationError::ErasedPadding);
    }

    if container.get(0x2020..0x2040) != stock.get(0x2020..0x2040)
        || read_u32(container, 0x2040)? != 0x2064
        || read_u32(stock, 0x2040)? != 0x2064
        || [0x2044, 0x2048, 0x204c, 0x2050]
            .into_iter()
            .any(|offset| read_u32(container, offset) != Ok(0x2060))
        || read_u32(container, 0x2054)? != 0
        || [0x2058, 0x205c]
            .into_iter()
            .any(|offset| read_u32(container, offset) != Ok(0x2060))
        || read_u32(container, 0x2060)? != 0xeaff_fffe
    {
        return Err(VerificationError::VectorGeometry);
    }
    if container.get(0x2064..0x2080) != Some(RESET_SEQUENCE.as_slice()) {
        return Err(VerificationError::ResetSequence);
    }
    let startup_stack = verify_startup(container, startup_trampoline)?;

    let mut call_targets = [0_u32; 8];
    for (index, (source, expected)) in CALL_GRAPH.into_iter().enumerate() {
        let instruction = read_array(container, source)?;
        let source_u32 = u32::try_from(source).map_err(|_| VerificationError::CallGraph)?;
        let target = decode_thumb_bl(
            instruction,
            ThumbAddress::new(source_u32).map_err(VerificationError::Branch)?,
        )
        .map_err(|_| VerificationError::CallGraph)?
        .get();
        if target != expected {
            return Err(VerificationError::CallGraph);
        }
        let slot = call_targets
            .get_mut(index)
            .ok_or(VerificationError::CallGraph)?;
        *slot = target;
    }

    if [read_u32(stock, 0x177e4)?, read_u32(stock, 0x177ec)?] != [0x58a9, 0xa958]
        || [read_u32(container, 0x2170)?, read_u32(container, 0x2174)?] != [0x58a9, 0xa958]
        || read_u32(container, 0x216c)? != 0x0080_3000
    {
        return Err(VerificationError::StorageUnlock);
    }
    if container.get(0x2138..0x216c) != Some(STORAGE_SEQUENCE.as_slice()) {
        return Err(VerificationError::StorageSequence);
    }
    if container.get(0x2142..0x216c) != carrier.get(0x224c..0x2276) {
        return Err(VerificationError::StorageCarrierMismatch);
    }
    if [
        read_u32(container, 0x20c4)?,
        read_u32(container, 0x20c8)?,
        read_u32(container, 0x20cc)?,
    ] != [0x807c, 0x7856_3412, 0x19d2_bc9a]
        || read_u32(container, 0x20e4)? != 0x0080_3008
        || read_u32(container, 0x20f8)? != 0x0080_3008
    {
        return Err(VerificationError::MarkerSequence);
    }
    if container.get(0x20d0..0x20f8) != Some(ERASE_WRITE_SEQUENCE.as_slice()) {
        return Err(VerificationError::EraseWriteSequence);
    }
    if container.get(0x2178..0x21c4) != Some(DELAY_SEQUENCE.as_slice()) {
        return Err(VerificationError::DelaySequence);
    }
    if container.get(0x21a8..0x21c4) != stock.get(0x178ce..0x178ea)
        || container.get(0x2178..0x217e) != stock.get(0x178ea..0x178f0)
        || container.get(0x2180..0x2184) != stock.get(0x178f2..0x178f6)
        || container.get(0x2188..0x2196) != stock.get(0x178fa..0x17908)
        || container.get(0x219a..0x21a2) != stock.get(0x1790e..0x17916)
    {
        return Err(VerificationError::DelayStockMismatch);
    }
    if [
        read_u32(container, 0x2128)?,
        read_u32(container, 0x212c)?,
        read_u32(container, 0x2130)?,
        read_u32(container, 0x2134)?,
    ] != [0x0080_001c, 0x0080_6000, 0x0080_00c0, 0x00aa_5aaa]
        || [
            read_u32(stock, 0x19cd0)?,
            read_u32(stock, 0x19cd4)?,
            read_u32(stock, 0x19cdc)?,
        ] != [0x00aa_5aaa, 0x0080_00c0, 0x0080_6000]
        || container.get(0x20fc..0x2128) != Some(WATCHDOG_SEQUENCE.as_slice())
    {
        return Err(VerificationError::WatchdogSequence);
    }

    verify_elf(elf_bytes).map_err(VerificationError::Elf)?;
    if !RECOVERY_STUB_ARTIFACT.code_matches(code) {
        return Err(VerificationError::CodeIdentity);
    }
    let expected = build(code).map_err(VerificationError::Image)?;
    if container != expected {
        return Err(VerificationError::DerivedContainer);
    }
    let payload = RECOVERY_STUB
        .validate(container)
        .map_err(VerificationError::StubIdentity)?;
    if payload.len() != EXPECTED_PAYLOAD_SIZE {
        return Err(VerificationError::PayloadSize);
    }

    Ok(RecoveryStubReport {
        result: "PASS",
        stock_sha256: sha256(stock),
        code_bytes: code.len(),
        code_sha256: sha256(code),
        container_bytes: container.len(),
        container_sha256: sha256(container),
        application_crc: stub_header.crc,
        application_end: stub_header.end_offset().map_err(VerificationError::Image)?,
        payload_bytes: payload.len(),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        b1_blocks: EXPECTED_BLOCK_COUNT,
        elf_entry: 0x2020,
        startup_stack,
        call_targets,
    })
}

const fn same_header_geometry(
    stock: slimblade_image::ImageHeader,
    stub: slimblade_image::ImageHeader,
) -> bool {
    stock.version == stub.version
        && stock.length_words == stub.length_words
        && stock.uid == stub.uid
        && stock.crc_status == stub.crc_status
        && stock.section_status == stub.section_status
        && stock.rom_version == stub.rom_version
}

fn verify_startup(stub: &[u8], reference: &[u8]) -> Result<u32, VerificationError> {
    STARTUP_TRAMPOLINE
        .validate(reference)
        .map_err(VerificationError::StartupIdentity)?;
    let masks = [
        0xffff_ffff,
        0xffff_ffff,
        0xffff_f000,
        0xffff_f000,
        0xffff_ffff,
    ];
    for ((stub_address, reference_address), mask) in (0x2064..0x2078)
        .step_by(4)
        .zip((0x22bc..0x22d0).step_by(4))
        .zip(masks)
    {
        if read_u32(stub, stub_address)? & mask != read_u32(reference, reference_address)? & mask {
            return Err(VerificationError::StartupOperations);
        }
    }
    let (stub_stack_address, stub_stack) = arm_pc_literal(stub, 0x206c, 13)?;
    let (reference_stack_address, reference_stack) = arm_pc_literal(reference, 0x22c4, 13)?;
    let (stub_entry_address, stub_entry) = arm_pc_literal(stub, 0x2070, 0)?;
    let (reference_entry_address, reference_entry) = arm_pc_literal(reference, 0x22c8, 0)?;
    if (stub_stack_address, reference_stack_address) != (0x2078, 0x22e0)
        || stub_stack != 0x0040_7f00
        || reference_stack != stub_stack
        || (stub_entry_address, reference_entry_address) != (0x207c, 0x22e4)
        || stub_entry != 0x2081
        || reference_entry != 0x22e9
    {
        return Err(VerificationError::StartupLiteral);
    }
    if stub_entry & reference_entry & 1 != 1 {
        return Err(VerificationError::StartupState);
    }
    Ok(stub_stack)
}

fn arm_pc_literal(
    image: &[u8],
    address: usize,
    register: u32,
) -> Result<(usize, u32), VerificationError> {
    let instruction = read_u32(image, address)?;
    if instruction & 0xffff_f000 != 0xe59f_0000 | register << 12_u32 {
        return Err(VerificationError::StartupLiteral);
    }
    let displacement =
        usize::try_from(instruction & 0x0fff).map_err(|_| VerificationError::StartupLiteral)?;
    let literal_address = address
        .checked_add(8)
        .and_then(|value| value.checked_add(displacement))
        .ok_or(VerificationError::StartupLiteral)?;
    Ok((literal_address, read_u32(image, literal_address)?))
}

fn verify_elf(elf_bytes: &[u8]) -> Result<(), StubElfError> {
    let elf = Elf32::parse(elf_bytes).map_err(StubElfError::Elf)?;
    if elf.elf_type() != ELF_TYPE_EXECUTABLE {
        return Err(StubElfError::WrongType {
            actual: elf.elf_type(),
        });
    }
    if elf.machine() != ELF_MACHINE_ARM {
        return Err(StubElfError::WrongMachine {
            actual: elf.machine(),
        });
    }
    if elf.entry() != 0x2020 {
        return Err(StubElfError::WrongEntry {
            actual: elf.entry(),
        });
    }
    let mut vectors_found = false;
    let mut text_found = false;
    for section in elf.sections() {
        let section = section.map_err(StubElfError::Elf)?;
        if section.name == ".vectors" {
            vectors_found = true;
            if section.address != 0x2020 || section.size != 0x60 {
                return Err(StubElfError::WrongVectors {
                    address: section.address,
                    size: section.size,
                });
            }
        } else if section.name == ".text" {
            text_found = true;
            if section.address != 0x2080 {
                return Err(StubElfError::WrongTextAddress {
                    actual: section.address,
                });
            }
        }
        if section.is_relocation() {
            return Err(StubElfError::Relocation);
        }
        if section.is_writable_allocated() {
            return Err(StubElfError::WritableAllocated);
        }
    }
    if !vectors_found {
        return Err(StubElfError::VectorsMissing);
    }
    if !text_found {
        return Err(StubElfError::TextMissing);
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

    use slimblade_image::refresh_header_crc;

    use super::*;

    struct Fixtures {
        stock: Vec<u8>,
        container: Vec<u8>,
        code: Vec<u8>,
        elf: Vec<u8>,
        carrier: Vec<u8>,
        startup: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read recovery-stub fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build_dir = root.join("firmware/recovery_stub/build");
        Some(Fixtures {
            stock: read_if_present(PathBuf::from("/tmp/slimblade-v449.bin"))?,
            container: read_if_present(build_dir.join("DO_NOT_FLASH-recovery-stub.container.bin"))?,
            code: read_if_present(build_dir.join("DO_NOT_FLASH-recovery-stub.code.bin"))?,
            elf: read_if_present(build_dir.join("DO_NOT_FLASH-recovery-stub.elf"))?,
            carrier: read_if_present(root.join("firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.container.bin"))?,
            startup: read_if_present(root.join("firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin"))?,
        })
    }

    fn verify_fixtures(data: &Fixtures) -> Result<RecoveryStubReport, VerificationError> {
        verify(
            &data.stock,
            &data.container,
            &data.code,
            &data.elf,
            &data.carrier,
            &data.startup,
        )
    }

    #[test]
    fn audited_build_passes_and_generator_reproduces_container() {
        let Some(data) = fixtures() else { return };
        assert_eq!(build(&data.code), Ok(data.container.clone()));
        let report = verify_fixtures(&data).expect("audited recovery stub");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.b1_blocks, 3_748);
        assert_eq!(report.startup_stack, 0x0040_7f00);
    }

    #[test]
    fn reversed_unlock_order_is_rejected_even_with_valid_crc() {
        let Some(mut data) = fixtures() else { return };
        let first = 0x2170 - 0x2020;
        let second = 0x2174 - 0x2020;
        for index in 0..4 {
            data.code.swap(first + index, second + index);
            data.container.swap(0x2170 + index, 0x2174 + index);
        }
        refresh_header_crc(&mut data.container, APPLICATION_HEADER_OFFSET)
            .expect("valid mutated header");
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::StorageUnlock)
        ));
    }

    #[test]
    fn changed_container_padding_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        *data.container.last_mut().expect("nonempty container") = 0;
        assert!(verify_fixtures(&data).is_err());
    }

    #[test]
    fn changed_header_crc_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.container[APPLICATION_HEADER_OFFSET] ^= 1;
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::HeaderCrc)
        ));
    }

    #[test]
    fn wrong_stock_reference_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        *data.stock.last_mut().expect("nonempty stock") ^= 1;
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::StockIdentity(_))
        ));
    }

    #[test]
    fn wrong_live_carrier_reference_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.carrier[0x224c] ^= 1;
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::CarrierIdentity(_))
        ));
    }

    #[test]
    fn wrong_live_startup_reference_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.startup[0x22bc] ^= 1;
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::StartupIdentity(_))
        ));
    }

    #[test]
    fn changed_standalone_stack_load_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.container[0x206c..0x2070].copy_from_slice(&0xe59f_d008_u32.to_le_bytes());
        let offset = 0x206c - 0x2020;
        data.code[offset..offset + 4].copy_from_slice(&0xe59f_d008_u32.to_le_bytes());
        refresh_header_crc(&mut data.container, APPLICATION_HEADER_OFFSET)
            .expect("valid mutated header");
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::ResetSequence)
        ));
    }

    #[test]
    fn changed_standalone_call_target_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.container[0x2098] ^= 1;
        data.code[0x2098 - 0x2020] ^= 1;
        refresh_header_crc(&mut data.container, APPLICATION_HEADER_OFFSET)
            .expect("valid mutated header");
        assert!(matches!(
            verify_fixtures(&data),
            Err(VerificationError::CallGraph)
        ));
    }
}
