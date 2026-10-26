use core::fmt;

use slimblade_image::{
    APPLICATION_HEADER_OFFSET, APPLICATION_PREFIX_OFFSET, FirmwareIdentityError, ImageError,
    OFFICIAL_V449, OFFICIAL_V449_SIZE, RECOVERY_CARRIER, RECOVERY_CARRIER_ARTIFACT,
    STACK_HEADER_OFFSET, V449_BCD_DEVICE_OFFSET, parse_header, refresh_header_crc, sha256,
};

use crate::{
    BranchError, ThumbAddress, decode_thumb_bl,
    elf::{ArmExecutableError, ArmExecutableText, verify_arm_executable_text},
    encode_thumb_bl,
};

pub const CARRIER_ADDRESS: usize = 0x21ac;
pub const CARRIER_LIMIT: usize = 0x2300;
pub const DISPATCH_CALL: usize = 0x18fba;
pub const AUDITED_CODE_SIZE: usize = 264;
pub const EXPECTED_PAYLOAD_SIZE: usize = OFFICIAL_V449_SIZE - APPLICATION_PREFIX_OFFSET;
pub const EXPECTED_BLOCK_COUNT: usize = EXPECTED_PAYLOAD_SIZE.div_ceil(32);

const DISPATCH_BRANCHES: [(usize, [u8; 2]); 3] = [
    (0x18f9a, [0x0e, 0xd0]),
    (0x18fae, [0x04, 0xd0]),
    (0x18fb2, [0x02, 0xd0]),
];
const CARRIER_DISPATCH: [u8; 18] = [
    0x0d, 0x28, 0x04, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x0f, 0x28, 0x0a, 0xd0, 0x0a, 0xe0, 0x2f, 0x4b,
    0x18, 0x47,
];
const READ_ONLY_PROBE: [u8; 16] = [
    0x10, 0xb5, 0x2e, 0x48, 0x2f, 0x49, 0x88, 0x60, 0x20, 0x20, 0x00, 0xf0, 0x3b, 0xf8, 0x10, 0xbd,
];
const STORAGE_SEQUENCE: [u8; 52] = [
    0x0f, 0x49, 0x19, 0x4a, 0x0a, 0x60, 0x19, 0x4a, 0x0a, 0x60, 0xa5, 0x22, 0x0a, 0x61, 0xc3, 0x22,
    0x4a, 0x61, 0x4a, 0x68, 0x7c, 0x23, 0x9a, 0x43, 0x02, 0x43, 0x4a, 0x60, 0x01, 0x20, 0x10, 0x43,
    0x48, 0x60, 0x48, 0x68, 0xc0, 0x07, 0xfc, 0xd1, 0x00, 0x20, 0x08, 0x60, 0x08, 0x60, 0x08, 0x61,
    0x48, 0x61, 0x70, 0x47,
];
const CRITICAL_LITERALS: [(usize, u32); 15] = [
    (0x2278, 0x0001_895d),
    (0x227c, 0x0000_807c),
    (0x2280, 0x0080_3000),
    (0x2284, 0x7856_3412),
    (0x2288, 0x0000_807d),
    (0x228c, 0x19d2_bc9a),
    (0x2290, 0x0001_78eb),
    (0x2294, 0x0080_001c),
    (0x2298, 0x0080_6000),
    (0x229c, 0x0080_00c0),
    (0x22a0, 0x00aa_5aaa),
    (0x22a4, 0x005a_0050),
    (0x22a8, 0x00a5_0050),
    (0x22ac, 0x0000_58a9),
    (0x22b0, 0x0000_a958),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    StockIdentity(FirmwareIdentityError),
    EmptyCode,
    CodeTooLarge { end: usize },
    StockGapNotZero,
    ImageLayout,
    Branch(BranchError),
    Image(ImageError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StockIdentity(error) => write!(formatter, "official v4.49: {error}"),
            Self::EmptyCode => formatter.write_str("carrier code is empty"),
            Self::CodeTooLarge { end } => {
                write!(formatter, "carrier code ends at {end:#x}, beyond 0x2300")
            },
            Self::StockGapNotZero => {
                formatter.write_str("stock carrier region is not entirely zero-filled")
            },
            Self::ImageLayout => formatter.write_str("stock image layout is truncated"),
            Self::Branch(error) => write!(formatter, "dispatcher call: {error}"),
            Self::Image(error) => write!(formatter, "stock image: {error}"),
        }
    }
}

impl core::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::StockIdentity(error) => Some(error),
            Self::Branch(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    StockIdentity(FirmwareIdentityError),
    CodeSize { actual: usize },
    SafetyMargin,
    StockGapNotZero,
    ContainerSize,
    Build(BuildError),
    DerivedImage,
    EmbeddedCode,
    UnusedGap,
    InterruptWrappers,
    DispatcherPatch { offset: usize },
    DispatcherCall,
    CarrierDispatch,
    ReadOnlyProbe,
    ResetProbe,
    CriticalLiteral { offset: usize, actual: u32 },
    StorageUnlock,
    StorageSequence,
    Header(ImageError),
    HeaderCrc { offset: usize },
    DeviceVersion { actual: u8 },
    Elf(ArmExecutableError),
    CodeIdentity,
    CarrierIdentity(FirmwareIdentityError),
    PayloadSize,
    WordUnavailable { offset: usize },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StockIdentity(error) => write!(formatter, "official v4.49: {error}"),
            Self::CodeSize { actual } => {
                write!(formatter, "carrier code is {actual} bytes, not 264")
            },
            Self::SafetyMargin => formatter.write_str("carrier safety margin vanished"),
            Self::StockGapNotZero => formatter.write_str("stock carrier gap is not zero-filled"),
            Self::ContainerSize => formatter.write_str("carrier size differs from stock"),
            Self::Build(error) => write!(formatter, "could not derive carrier: {error}"),
            Self::DerivedImage => formatter.write_str("carrier is not a clean stock-derived build"),
            Self::EmbeddedCode => formatter.write_str("injected bytes differ from linked code"),
            Self::UnusedGap => formatter.write_str("unused carrier safety margin changed"),
            Self::InterruptWrappers => formatter.write_str("stock IRQ/FIQ handlers changed"),
            Self::DispatcherPatch { offset } => {
                write!(formatter, "dispatcher patch at {offset:#x} changed")
            },
            Self::DispatcherCall => formatter.write_str("dispatcher call or stock target changed"),
            Self::CarrierDispatch => {
                formatter.write_str("carrier dispatch or stock-recovery tail call changed")
            },
            Self::ReadOnlyProbe => formatter.write_str("read-only storage probe changed"),
            Self::ResetProbe => formatter.write_str("reset-only probe changed"),
            Self::CriticalLiteral { offset, actual } => write!(
                formatter,
                "critical literal at {offset:#x} changed to {actual:#010x}"
            ),
            Self::StorageUnlock => formatter.write_str("storage unlock order differs from stock"),
            Self::StorageSequence => {
                formatter.write_str("storage-controller instruction sequence changed")
            },
            Self::Header(error) => write!(formatter, "image header: {error}"),
            Self::HeaderCrc { offset } => write!(formatter, "header CRC at {offset:#x} is invalid"),
            Self::DeviceVersion { actual } => write!(
                formatter,
                "carrier bcdDevice byte is {actual:#04x}, not 0x51"
            ),
            Self::Elf(error) => write!(formatter, "{error}"),
            Self::CodeIdentity => formatter.write_str("carrier code differs from audited build"),
            Self::CarrierIdentity(error) => write!(formatter, "recovery carrier: {error}"),
            Self::PayloadSize => formatter.write_str("wire payload size changed"),
            Self::WordUnavailable { offset } => write!(formatter, "no word at {offset:#x}"),
        }
    }
}

impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::StockIdentity(error) | Self::CarrierIdentity(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::Header(error) => Some(error),
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCarrierReport {
    pub result: &'static str,
    pub stock_sha256: [u8; 32],
    pub code_bytes: usize,
    pub code_sha256: [u8; 32],
    pub carrier_bytes: usize,
    pub carrier_sha256: [u8; 32],
    pub unused_gap_bytes: usize,
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
    pub b1_blocks: usize,
    pub usb_bcd_device: u16,
}

/// Injects recovery-carrier code and dispatcher patches into exact official v4.49.
///
/// # Errors
///
/// Returns an error unless stock identity, code bounds, and the zero-filled carrier gap are exact.
pub fn build(stock: &[u8], code: &[u8]) -> Result<Vec<u8>, BuildError> {
    OFFICIAL_V449
        .validate(stock)
        .map_err(BuildError::StockIdentity)?;
    if code.is_empty() {
        return Err(BuildError::EmptyCode);
    }
    let code_end = CARRIER_ADDRESS
        .checked_add(code.len())
        .ok_or(BuildError::CodeTooLarge { end: usize::MAX })?;
    if code_end > CARRIER_LIMIT {
        return Err(BuildError::CodeTooLarge { end: code_end });
    }
    let gap = stock
        .get(CARRIER_ADDRESS..CARRIER_LIMIT)
        .ok_or(BuildError::ImageLayout)?;
    if gap.iter().any(|byte| *byte != 0) {
        return Err(BuildError::StockGapNotZero);
    }

    let mut image = stock.to_vec();
    image
        .get_mut(CARRIER_ADDRESS..code_end)
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(code);
    for (offset, branch) in DISPATCH_BRANCHES {
        image
            .get_mut(offset..offset + branch.len())
            .ok_or(BuildError::ImageLayout)?
            .copy_from_slice(&branch);
    }
    let dispatch_call = encode_thumb_bl(
        ThumbAddress::new(u32::try_from(DISPATCH_CALL).map_err(|_| BuildError::ImageLayout)?)
            .map_err(BuildError::Branch)?,
        ThumbAddress::new(u32::try_from(CARRIER_ADDRESS).map_err(|_| BuildError::ImageLayout)?)
            .map_err(BuildError::Branch)?,
    )
    .map_err(BuildError::Branch)?;
    image
        .get_mut(DISPATCH_CALL..DISPATCH_CALL + dispatch_call.len())
        .ok_or(BuildError::ImageLayout)?
        .copy_from_slice(&dispatch_call);
    *image
        .get_mut(V449_BCD_DEVICE_OFFSET)
        .ok_or(BuildError::ImageLayout)? = 0x51;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(BuildError::Image)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(BuildError::Image)?;
    Ok(image)
}

/// Performs the complete stock-derived recovery-carrier audit.
///
/// # Errors
///
/// Returns the first failed stock, layout, dispatcher, MMIO, header, ELF, or identity invariant.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the ordered carrier audit contiguous makes the stock-derived boundary reviewable"
)]
pub fn verify(
    stock: &[u8],
    carrier: &[u8],
    code: &[u8],
    elf_bytes: &[u8],
) -> Result<RecoveryCarrierReport, VerificationError> {
    OFFICIAL_V449
        .validate(stock)
        .map_err(VerificationError::StockIdentity)?;
    if code.len() != AUDITED_CODE_SIZE {
        return Err(VerificationError::CodeSize { actual: code.len() });
    }
    let code_end = CARRIER_ADDRESS
        .checked_add(code.len())
        .ok_or(VerificationError::SafetyMargin)?;
    if code_end >= CARRIER_LIMIT {
        return Err(VerificationError::SafetyMargin);
    }
    let stock_gap = stock
        .get(CARRIER_ADDRESS..CARRIER_LIMIT)
        .ok_or(VerificationError::StockGapNotZero)?;
    if stock_gap.iter().any(|byte| *byte != 0) {
        return Err(VerificationError::StockGapNotZero);
    }
    if carrier.len() != stock.len() {
        return Err(VerificationError::ContainerSize);
    }
    let expected = build(stock, code).map_err(VerificationError::Build)?;
    if carrier != expected {
        return Err(VerificationError::DerivedImage);
    }
    if carrier.get(CARRIER_ADDRESS..code_end) != Some(code) {
        return Err(VerificationError::EmbeddedCode);
    }
    let unused = carrier
        .get(code_end..CARRIER_LIMIT)
        .ok_or(VerificationError::UnusedGap)?;
    if unused.iter().any(|byte| *byte != 0) {
        return Err(VerificationError::UnusedGap);
    }
    if carrier.get(0x2300..0x2330) != stock.get(0x2300..0x2330) {
        return Err(VerificationError::InterruptWrappers);
    }
    for (offset, expected) in DISPATCH_BRANCHES {
        if carrier.get(offset..offset + expected.len()) != Some(expected.as_slice()) {
            return Err(VerificationError::DispatcherPatch { offset });
        }
    }
    let expected_call = encode_thumb_bl(
        ThumbAddress::new(0x18fba).map_err(|_| VerificationError::DispatcherCall)?,
        ThumbAddress::new(0x21ac).map_err(|_| VerificationError::DispatcherCall)?,
    )
    .map_err(|_| VerificationError::DispatcherCall)?;
    if carrier.get(DISPATCH_CALL..DISPATCH_CALL + 4) != Some(expected_call.as_slice())
        || thumb_target(carrier, DISPATCH_CALL)? != 0x21ac
        || thumb_target(stock, DISPATCH_CALL)? != 0x1895c
    {
        return Err(VerificationError::DispatcherCall);
    }
    if carrier.get(0x21ac..0x21be) != Some(CARRIER_DISPATCH.as_slice()) {
        return Err(VerificationError::CarrierDispatch);
    }
    if carrier.get(0x21be..0x21ce) != Some(READ_ONLY_PROBE.as_slice()) {
        return Err(VerificationError::ReadOnlyProbe);
    }
    if carrier.get(0x21ce..0x21d0) != Some([0x28, 0xe0].as_slice()) {
        return Err(VerificationError::ResetProbe);
    }
    for (offset, expected) in CRITICAL_LITERALS {
        let actual = read_u32(carrier, offset)?;
        if actual != expected {
            return Err(VerificationError::CriticalLiteral { offset, actual });
        }
    }
    if [read_u32(stock, 0x177e4)?, read_u32(stock, 0x177ec)?] != [0x58a9, 0xa958]
        || [read_u32(carrier, 0x22ac)?, read_u32(carrier, 0x22b0)?] != [0x58a9, 0xa958]
    {
        return Err(VerificationError::StorageUnlock);
    }
    if carrier.get(0x2242..0x2276) != Some(STORAGE_SEQUENCE.as_slice()) {
        return Err(VerificationError::StorageSequence);
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(carrier, offset).map_err(VerificationError::Header)?;
        if !header
            .crc_is_valid(carrier)
            .map_err(VerificationError::Header)?
        {
            return Err(VerificationError::HeaderCrc { offset });
        }
    }
    let device_version = carrier
        .get(V449_BCD_DEVICE_OFFSET)
        .copied()
        .ok_or(VerificationError::DeviceVersion { actual: 0 })?;
    if device_version != 0x51 {
        return Err(VerificationError::DeviceVersion {
            actual: device_version,
        });
    }
    verify_arm_executable_text(
        elf_bytes,
        ArmExecutableText {
            entry: 0x21ad,
            address: 0x21ac,
            size: 264,
        },
    )
    .map_err(VerificationError::Elf)?;
    if !RECOVERY_CARRIER_ARTIFACT.code_matches(code) {
        return Err(VerificationError::CodeIdentity);
    }
    let payload = RECOVERY_CARRIER
        .validate(carrier)
        .map_err(VerificationError::CarrierIdentity)?;
    if payload.len() != EXPECTED_PAYLOAD_SIZE {
        return Err(VerificationError::PayloadSize);
    }
    Ok(RecoveryCarrierReport {
        result: "PASS",
        stock_sha256: sha256(stock),
        code_bytes: code.len(),
        code_sha256: sha256(code),
        carrier_bytes: carrier.len(),
        carrier_sha256: sha256(carrier),
        unused_gap_bytes: CARRIER_LIMIT - CARRIER_ADDRESS - code.len(),
        payload_bytes: payload.len(),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
        b1_blocks: EXPECTED_BLOCK_COUNT,
        usb_bcd_device: 0x0451,
    })
}

fn thumb_target(image: &[u8], address: usize) -> Result<u32, VerificationError> {
    let instruction = read_array(image, address)?;
    let source = u32::try_from(address).map_err(|_| VerificationError::DispatcherCall)?;
    Ok(decode_thumb_bl(
        instruction,
        ThumbAddress::new(source).map_err(|_| VerificationError::DispatcherCall)?,
    )
    .map_err(|_| VerificationError::DispatcherCall)?
    .get())
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
        carrier: Vec<u8>,
        code: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read recovery-carrier fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build_dir = root.join("firmware/recovery_carrier/build");
        Some(Fixtures {
            stock: read_if_present(PathBuf::from("/tmp/slimblade-v449.bin"))?,
            carrier: read_if_present(
                build_dir.join("DO_NOT_FLASH-stock-recovery-carrier.container.bin"),
            )?,
            code: read_if_present(build_dir.join("DO_NOT_FLASH-stock-recovery-carrier.code.bin"))?,
            elf: read_if_present(build_dir.join("DO_NOT_FLASH-stock-recovery-carrier.elf"))?,
        })
    }

    #[test]
    fn audited_carrier_passes() {
        let Some(data) = fixtures() else { return };
        let report = verify(&data.stock, &data.carrier, &data.code, &data.elf)
            .expect("audited recovery carrier");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.b1_blocks, 3_748);
        assert_eq!(report.unused_gap_bytes, 76);
    }

    #[test]
    fn generator_reproduces_build() {
        let Some(data) = fixtures() else { return };
        assert_eq!(build(&data.stock, &data.code), Ok(data.carrier));
    }

    #[test]
    fn wrong_stock_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        *data.stock.last_mut().expect("nonempty stock") ^= 1;
        assert!(matches!(
            build(&data.stock, &data.code),
            Err(BuildError::StockIdentity(_))
        ));
    }

    #[test]
    fn oversized_injection_is_rejected() {
        let Some(data) = fixtures() else { return };
        let code = vec![0; CARRIER_LIMIT - CARRIER_ADDRESS + 1];
        assert!(matches!(
            build(&data.stock, &code),
            Err(BuildError::CodeTooLarge { .. })
        ));
    }

    #[test]
    fn changed_stock_fallback_pointer_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.carrier[0x2278] ^= 1;
        assert!(verify(&data.stock, &data.carrier, &data.code, &data.elf).is_err());
    }

    #[test]
    fn reversed_unlock_order_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        for index in 0..4 {
            data.carrier.swap(0x22ac + index, 0x22b0 + index);
        }
        assert!(verify(&data.stock, &data.carrier, &data.code, &data.elf).is_err());
    }
}
