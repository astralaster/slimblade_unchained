use core::{fmt, mem::size_of};

use slimblade_image::{
    ACTIVE_LOOP_HOOK_PROBE, ACTIVE_LOOP_HOOK_PROBE_ARTIFACT, APPLICATION_HEADER_OFFSET,
    CUSTOM_MAIN_HANDOFF_PROBE, CUSTOM_MAIN_HANDOFF_PROBE_ARTIFACT, CUSTOM_MAIN_SENSOR_STREAM_PROBE,
    CUSTOM_MAIN_SENSOR_STREAM_PROBE_ARTIFACT, CUSTOM_MAIN_SENSOR_STREAM_RUNTIME_ARTIFACT,
    CUSTOM_MAIN_SENSOR_STREAM_SUPPORT_ARTIFACT, CUSTOM_MAIN_STREAM_TRANSPORT_PROBE,
    CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_ARTIFACT, CUSTOM_MAIN_STREAM_TRANSPORT_RUNTIME_ARTIFACT,
    CUSTOM_MAIN_USB_RECOVERY_PROBE, CUSTOM_MAIN_USB_RECOVERY_PROBE_ARTIFACT,
    DISPATCHER_RETURN_HOOK_PROBE, DISPATCHER_RETURN_HOOK_PROBE_ARTIFACT, EXPERIMENT_DISPATCH_GUARD,
    EXPERIMENT_DISPATCH_GUARD_ARTIFACT, INPUT_DIAGNOSTICS, INPUT_DIAGNOSTICS_ARTIFACT,
    PAGED_INPUT_DIAGNOSTICS, PAGED_INPUT_DIAGNOSTICS_ARTIFACT, POST_INIT_HOOK_PROBE,
    POST_INIT_HOOK_PROBE_ARTIFACT, SENSOR_SHADOW_DIAGNOSTICS, SENSOR_SHADOW_DIAGNOSTICS_ARTIFACT,
    STACK_HEADER_OFFSET, STARTUP_TRAMPOLINE, STEADY_LOOP_HOOK_PROBE,
    STEADY_LOOP_HOOK_PROBE_ARTIFACT, UNSOLICITED_REPORT_PROBE, UNSOLICITED_REPORT_PROBE_ARTIFACT,
    V449_BCD_DEVICE_OFFSET, WIRED_LOOP_HOOK_PROBE, WIRED_LOOP_HOOK_PROBE_ARTIFACT, parse_header,
    refresh_header_crc, sha256,
};

use crate::{
    ArmAddress, BranchError, ThumbAddress, decode_arm_branch, decode_thumb_bl,
    elf::{ELF_MACHINE_ARM, ELF_TYPE_EXECUTABLE, Elf32},
    encode_arm_b, encode_thumb_bl,
};

const INJECTION_START: usize = 0x21ac;
const INJECTION_END: usize = 0x2300;
const RESET_BRANCH: usize = 0x2064;
const TRAMPOLINE: u32 = 0x22cc;
const MODE_BRANCH: usize = 0x19c00;
const LOCAL_BRANCH: usize = 0x19c6e;
const LOCAL_CALL: usize = 0x197cc;
const HOOK: u32 = 0x22c0;
const MAIN_LOOP: u32 = 0x19bf2;
const WIRED_SWITCH_DEFAULT: usize = 0x19b5e;
const WIRED_MAIN_LOOP: u32 = 0x19b4a;
const ACTIVE_LOOP_PATCH: usize = 0x1cfcc;
const STEADY_LOOP_PATCH: usize = 0x1d3c2;
const DISPATCHER_RETURN_PATCH: usize = 0x1c55a;
const CUSTOM_MAIN_HANDOFF_PATCH: usize = 0x19c08;
const CUSTOM_RUNTIME_START: usize = 0x1c460;
const CUSTOM_RUNTIME_LIMIT: usize = 0x1c5c0;
const CUSTOM_RUNTIME_LITERAL_START: usize = 0x1c58c;
const SENSOR_STREAM_SUPPORT_START: usize = 0x1c5c0;
const SENSOR_STREAM_SUPPORT_LIMIT: usize = 0x1c62c;
const EXPERIMENT_DISPATCH: u32 = 0x22a0;
const EXPERIMENT_CALL: usize = 0x22b2;
const SENSOR_SHADOW_PATCH: usize = 0x1a798;
const SENSOR_SHADOW_HOOK: u32 = 0x22aa;

const DISPATCH: [u8; 18] = [
    0x0d, 0x28, 0x04, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x0f, 0x28, 0x0b, 0xd0, 0x70, 0x47, 0x2c, 0x4b,
    0x18, 0x47,
];
const ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x03, 0x21, 0x01, 0x70, 0xa3, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const HOOK_BYTES: [u8; 12] = [
    0x02, 0x20, 0x20, 0x70, 0x00, 0x48, 0x00, 0x47, 0xf3, 0x9b, 0x01, 0x00,
];
const WIRED_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa5, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const WIRED_HOOK_BYTES: [u8; 12] = [
    0x00, 0x20, 0x38, 0x70, 0x00, 0x48, 0x00, 0x47, 0x4b, 0x9b, 0x01, 0x00,
];
const ACTIVE_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa6, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const ACTIVE_LOOP_HELPER: [u8; 28] = [
    0x04, 0x4f, 0x38, 0x68, 0x04, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x01, 0xd1, 0x00, 0x22, 0x0a, 0x70,
    0x70, 0x47, 0x00, 0x00, 0xb8, 0x02, 0x40, 0x00, 0x64, 0x02, 0x40, 0x00,
];
const STEADY_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa7, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const STEADY_LOOP_HELPER: [u8; 28] = [
    0x00, 0xb5, 0x04, 0x4b, 0x98, 0x47, 0x04, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x01, 0xd1, 0x00, 0x22,
    0x0a, 0x70, 0x00, 0xbd, 0x35, 0x5d, 0x01, 0x00, 0x64, 0x02, 0x40, 0x00,
];
const DISPATCHER_RETURN_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa8, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const DISPATCHER_RETURN_HELPER: [u8; 28] = [
    0x00, 0xb5, 0x04, 0x4b, 0x98, 0x47, 0x04, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x01, 0xd1, 0x00, 0x22,
    0x0a, 0x70, 0x00, 0xbd, 0x4d, 0x8f, 0x01, 0x00, 0x64, 0x02, 0x40, 0x00,
];
const EXPERIMENT_DISPATCH_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa9, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const UNSOLICITED_REPORT_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xab, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x27, 0x48, 0x00, 0x78, 0xe0, 0x70, 0x70, 0x47,
];
const EXPERIMENT_DISPATCH_HELPER: [u8; 32] = [
    0x10, 0xb5, 0x05, 0x4b, 0x98, 0x47, 0x05, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x03, 0xd1, 0x00, 0x22,
    0x0a, 0x70, 0x00, 0xf0, 0x05, 0xf8, 0x10, 0xbd, 0x4d, 0x8f, 0x01, 0x00, 0x64, 0x02, 0x40, 0x00,
];
const CUSTOM_MAIN_RETAINED_DISPATCH_HELPER: [u8; 32] = [
    0x10, 0xb5, 0x05, 0x4b, 0x98, 0x47, 0x05, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x03, 0xd1, 0x00, 0x22,
    0x0a, 0x70, 0x00, 0xf0, 0x09, 0xf8, 0x10, 0xbd, 0x4d, 0x8f, 0x01, 0x00, 0x64, 0x02, 0x40, 0x00,
];
const INPUT_DIAGNOSTICS_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa9, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x70, 0xe0, 0xc0, 0x46, 0xc0, 0x46, 0xc0, 0x46,
];
const INPUT_DIAGNOSTICS_HELPER: [u8; 44] = [
    0x10, 0xb5, 0x07, 0x4b, 0x98, 0x47, 0x07, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x01, 0xd1, 0x00, 0x22,
    0x0a, 0x70, 0x10, 0xbd, 0x04, 0x48, 0x0e, 0xc8, 0x20, 0x1d, 0x0e, 0xc0, 0x70, 0x47, 0x00, 0x00,
    0x4d, 0x8f, 0x01, 0x00, 0x64, 0x02, 0x40, 0x00, 0x60, 0x13, 0x40, 0x00,
];
const PAGED_INPUT_DIAGNOSTICS_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x05, 0x21, 0x01, 0x70, 0xa9, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0xe8, 0x78, 0xe0, 0x70, 0xc0, 0x00, 0x6d, 0xe0,
];
const PAGED_INPUT_DIAGNOSTICS_HELPER: [u8; 44] = [
    0x10, 0xb5, 0x07, 0x4b, 0x98, 0x47, 0x07, 0x49, 0x0a, 0x78, 0x05, 0x2a, 0x01, 0xd1, 0x00, 0x22,
    0x0a, 0x70, 0x10, 0xbd, 0x04, 0x49, 0x08, 0x18, 0x0e, 0xc8, 0x20, 0x1d, 0x0e, 0xc0, 0x70, 0x47,
    0x4d, 0x8f, 0x01, 0x00, 0x64, 0x02, 0x40, 0x00, 0x60, 0x01, 0x40, 0x00,
];
const SENSOR_SHADOW_ARM_AND_QUERY: [u8; 26] = [
    0x10, 0xb5, 0x00, 0xf0, 0x0a, 0xf8, 0x2a, 0x48, 0x00, 0x21, 0x01, 0x72, 0xaa, 0x20, 0xe0, 0x70,
    0x10, 0xbd, 0x03, 0x78, 0x01, 0x33, 0x03, 0x70, 0x73, 0xe0,
];
const SENSOR_SHADOW_HELPER: [u8; 44] = [
    0x09, 0x48, 0x0e, 0xc8, 0x20, 0x1d, 0x0e, 0xc0, 0x70, 0x47, 0x39, 0x68, 0x32, 0x88, 0x73, 0x88,
    0x1b, 0x04, 0x1a, 0x43, 0x08, 0x00, 0x10, 0x43, 0x02, 0xd0, 0x03, 0x48, 0x06, 0xc0, 0x87, 0xe7,
    0x34, 0x80, 0xb0, 0x1c, 0x70, 0x47, 0xc0, 0x46, 0x60, 0x13, 0x40, 0x00,
];
const SENSOR_SHADOW_DISPATCH: [u8; 18] = [
    0x0d, 0x28, 0x04, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x0f, 0x28, 0x73, 0xd0, 0x70, 0x47, 0x2c, 0x4b,
    0x18, 0x47,
];
const SENSOR_SHADOW_CRITICAL_WORDS: [(usize, u32); 13] = [
    (0x0c0, 0x0001_895d),
    (0x0c4, 0x0040_1360),
    (0x0c8, 0x0080_3000),
    (0x0cc, 0x0000_807c),
    (0x0d0, 0x7856_3412),
    (0x0d4, 0x0000_807d),
    (0x0d8, 0x19d2_bc9a),
    (0x0dc, 0x0001_78eb),
    (0x0e0, 0x0080_001c),
    (0x0e4, 0x0000_22e8),
    (0x0e8, 0x0080_6000),
    (0x0ec, 0x0000_58a9),
    (0x0f0, 0x0000_a958),
];
const RUST_EXPERIMENT_ENTRY: [u8; 6] = [0x80, 0xb5, 0x00, 0xaf, 0x80, 0xbd];
const UNSOLICITED_REPORT_ENTRY: [u8; 12] = [
    0x01, 0x48, 0x01, 0x21, 0xc1, 0x70, 0x70, 0x47, 0x71, 0x03, 0x40, 0x00,
];
const CUSTOM_MAIN_HANDOFF_ENTRY: [u8; 10] =
    [0x10, 0xb5, 0xff, 0xf7, 0x89, 0xff, 0xfe, 0xe7, 0x70, 0x47];
const CUSTOM_MAIN_USB_LOOP: [u8; 12] = [
    0x01, 0x4b, 0x98, 0x47, 0xfd, 0xe7, 0x00, 0x00, 0x4d, 0x8f, 0x01, 0x00,
];
const CUSTOM_MAIN_USB_HANDOFF: [u8; 8] = [0x10, 0xb5, 0xff, 0xf7, 0x89, 0xff, 0xeb, 0xe7];
const CUSTOM_MAIN_STREAM_VENEERS: [u8; 24] = [
    0x02, 0x4b, 0x18, 0x47, 0x02, 0x4b, 0x18, 0x47, 0x02, 0x4b, 0x18, 0x47, 0x4d, 0x8f, 0x01, 0x00,
    0xd1, 0xb4, 0x01, 0x00, 0x11, 0xc4, 0x01, 0x00,
];
const CUSTOM_MAIN_STREAM_HANDOFF: [u8; 12] = [
    0x10, 0xb5, 0xff, 0xf7, 0x89, 0xff, 0xff, 0xf7, 0xef, 0xff, 0xfe, 0xe7,
];
const CUSTOM_MAIN_SENSOR_VENEER: [u8; 8] = [0x00, 0x4b, 0x18, 0x47, 0x4d, 0xa7, 0x01, 0x00];
const PROTECTED_RUNTIME_WORDS: [u32; 4] = [0x0000_807c, 0x0080_3000, 0x0080_00c0, 0x0080_6000];
const CRITICAL_WORDS: [(usize, u32); 13] = [
    (0x0c0, 0x0001_895d),
    (0x0c4, 0x0040_0282),
    (0x0c8, 0x0080_3000),
    (0x0cc, 0x0000_807c),
    (0x0d0, 0x7856_3412),
    (0x0d4, 0x0000_807d),
    (0x0d8, 0x19d2_bc9a),
    (0x0dc, 0x0001_78eb),
    (0x0e0, 0x0080_001c),
    (0x0e4, 0x0000_22e8),
    (0x0e8, 0x0080_6000),
    (0x0ec, 0x0000_58a9),
    (0x0f0, 0x0000_a958),
];
const WIRED_CRITICAL_WORDS: [(usize, u32); 13] = [
    (0x0c0, 0x0001_895d),
    (0x0c4, 0x0040_0264),
    (0x0c8, 0x0080_3000),
    (0x0cc, 0x0000_807c),
    (0x0d0, 0x7856_3412),
    (0x0d4, 0x0000_807d),
    (0x0d8, 0x19d2_bc9a),
    (0x0dc, 0x0001_78eb),
    (0x0e0, 0x0080_001c),
    (0x0e4, 0x0000_22e8),
    (0x0e8, 0x0080_6000),
    (0x0ec, 0x0000_58a9),
    (0x0f0, 0x0000_a958),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BaseIdentity,
    InjectionSize { actual: usize },
    InjectionIdentity,
    RuntimeSize { actual: usize },
    RuntimeIdentity,
    ProtectedRuntimeWord { value: u32 },
    Layout,
    Branch(BranchError),
    DerivedImage,
    Bytes { offset: usize },
    Word { offset: usize, actual: u32 },
    Header,
    ContainerIdentity,
    Elf,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseIdentity => formatter.write_str("base is not exact v4.53"),
            Self::InjectionSize { actual } => write!(formatter, "injection is {actual} bytes"),
            Self::InjectionIdentity => formatter.write_str("injection identity changed"),
            Self::RuntimeSize { actual } => write!(formatter, "custom runtime is {actual} bytes"),
            Self::RuntimeIdentity => formatter.write_str("custom runtime identity changed"),
            Self::ProtectedRuntimeWord { value } => {
                write!(
                    formatter,
                    "custom runtime contains protected word {value:#010x}"
                )
            },
            Self::Layout => formatter.write_str("image layout is truncated"),
            Self::Branch(error) => write!(formatter, "branch: {error}"),
            Self::DerivedImage => formatter.write_str("image is not the exact derived candidate"),
            Self::Bytes { offset } => write!(formatter, "bytes changed at {offset:#x}"),
            Self::Word { offset, actual } => {
                write!(
                    formatter,
                    "word at injection +{offset:#x} is {actual:#010x}"
                )
            },
            Self::Header => formatter.write_str("container header audit failed"),
            Self::ContainerIdentity => formatter.write_str("container identity changed"),
            Self::Elf => formatter.write_str("ELF geometry changed"),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    pub injection_sha256: [u8; 32],
    pub container_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
}

/// Builds the dormant, marker-armed post-initialization hook candidate.
///
/// # Errors
///
/// Returns an error unless both inputs have their reviewed identities and every patched range
/// exists.
pub fn build(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !POST_INIT_HOOK_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }

    require_base(base, MODE_BRANCH, &[0xf7, 0xd1])?;
    require_base(base, 0x19c6d, &[0x0a, 0x00, 0x00])?;
    require_base(base, 0x197cb, &[0x0a, 0x00, 0x00, 0x00, 0x00])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;

    replace(&mut image, MODE_BRANCH, &[0x35, 0xd1])?;
    replace(&mut image, LOCAL_BRANCH - 1, &[0x00, 0xad, 0xe5])?;
    replace(&mut image, 0x197cb, &[0x00])?;
    replace(
        &mut image,
        LOCAL_CALL,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(LOCAL_CALL).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x59;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Audits the complete candidate, including its dormant stock branch chain and marker-first arm.
///
/// # Errors
///
/// Returns the first failed identity, byte, branch, header, or ELF invariant.
pub fn verify(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &ARM_AND_QUERY)?;
    require(injection, 0x114, &HOOK_BYTES)?;
    for (offset, expected) in CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if injection.get(0xf4..0x114) != Some([0_u8; 0x20].as_slice()) {
        return Err(Error::Bytes { offset: 0xf4 });
    }
    verify_branch_chain(image)?;
    if image.get(0x2300..0x2330) != base.get(0x2300..0x2330) {
        return Err(Error::Bytes { offset: 0x2300 });
    }
    if image.get(0x18f9a..0x18fbe) != base.get(0x18f9a..0x18fbe) {
        return Err(Error::Bytes { offset: 0x18f9a });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x0f4),
            (".probe", 0x22c0, 0x00c),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = POST_INIT_HOOK_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Builds the corrected dormant hook for the active wired switch loop.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed `0460` injection are supplied.
pub fn build_wired(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !WIRED_LOOP_HOOK_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, WIRED_SWITCH_DEFAULT, &[0x13])?;
    require_base(base, LOCAL_BRANCH - 1, &[0x0a, 0x00, 0x00])?;
    require_base(base, 0x197cb, &[0x0a, 0x00, 0x00, 0x00, 0x00])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(&mut image, WIRED_SWITCH_DEFAULT, &[0x8b])?;
    replace(&mut image, LOCAL_BRANCH - 1, &[0x00, 0xad, 0xe5])?;
    replace(&mut image, 0x197cb, &[0x00])?;
    replace(
        &mut image,
        LOCAL_CALL,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(LOCAL_CALL).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x60;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Audits the corrected active-wired-loop candidate.
///
/// # Errors
///
/// Returns the first failed identity, marker ordering, switch-table, branch, header, or ELF gate.
pub fn verify_wired(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_wired(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &WIRED_ARM_AND_QUERY)?;
    require(injection, 0x114, &WIRED_HOOK_BYTES)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if injection.get(0xf4..0x114) != Some([0_u8; 0x20].as_slice()) {
        return Err(Error::Bytes { offset: 0xf4 });
    }
    require(image, WIRED_SWITCH_DEFAULT, &[0x8b])?;
    require(image, LOCAL_BRANCH - 1, &[0x00, 0xad, 0xe5])?;
    require(image, 0x197cb, &[0x00])?;
    verify_direct_call_and_reset(image, WIRED_MAIN_LOOP)?;
    if image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
        || image.get(0x18f9a..0x18fbe) != base.get(0x18f9a..0x18fbe)
    {
        return Err(Error::Bytes { offset: 0x2300 });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x0f4),
            (".probe", 0x22c0, 0x00c),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = WIRED_LOOP_HOOK_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Builds the marker-armed hook at the active wired handler's internal loop boundary.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_active(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !ACTIVE_LOOP_HOOK_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, ACTIVE_LOOP_PATCH, &[0xd9, 0x4f, 0x38, 0x68])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        ACTIVE_LOOP_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(ACTIVE_LOOP_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x61;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Audits the active wired-handler loop hook, displaced-instruction replay, and marker-first arm.
///
/// # Errors
///
/// Returns the first failed identity, branch, replay, header, or ELF invariant.
pub fn verify_active(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_active(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &ACTIVE_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &ACTIVE_LOOP_HELPER)?;
    require(injection, 0x114, &[0xee, 0xe7])?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x108)? != 0x0040_02b8 || read_u32(injection, 0x10c)? != 0x0040_0264 {
        return Err(Error::Bytes { offset: 0x108 });
    }
    let target = decode_thumb_bl(
        read_array(image, ACTIVE_LOOP_PATCH)?,
        ThumbAddress::new(u32::try_from(ACTIVE_LOOP_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if target.get() != HOOK {
        return Err(Error::Bytes {
            offset: ACTIVE_LOOP_PATCH,
        });
    }
    if image.get(0x19b4a..0x19b80) != base.get(0x19b4a..0x19b80)
        || image.get(0x1cfd0..0x1cfd6) != base.get(0x1cfd0..0x1cfd6)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
        || image.get(0x18f9a..0x18fbe) != base.get(0x18f9a..0x18fbe)
    {
        return Err(Error::Bytes {
            offset: ACTIVE_LOOP_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x110),
            (".probe", 0x22c0, 0x002),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = ACTIVE_LOOP_HOOK_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Builds the marker-armed wrapper around the wired handler's steady-state service call.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_steady(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !STEADY_LOOP_HOOK_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, STEADY_LOOP_PATCH, &[0xf8, 0xf7, 0xb7, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        STEADY_LOOP_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(STEADY_LOOP_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x62;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Audits the steady-state wrapper, original stock call, marker-first arm, and return boundary.
///
/// # Errors
///
/// Returns the first failed identity, branch, replay, header, or ELF invariant.
pub fn verify_steady(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_steady(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &STEADY_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &STEADY_LOOP_HELPER)?;
    require(injection, 0x114, &[0xee, 0xe7])?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x108)? != 0x0001_5d35 || read_u32(injection, 0x10c)? != 0x0040_0264 {
        return Err(Error::Bytes { offset: 0x108 });
    }
    let target = decode_thumb_bl(
        read_array(image, STEADY_LOOP_PATCH)?,
        ThumbAddress::new(u32::try_from(STEADY_LOOP_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if target.get() != HOOK {
        return Err(Error::Bytes {
            offset: STEADY_LOOP_PATCH,
        });
    }
    if image.get(0x19b4a..0x19b80) != base.get(0x19b4a..0x19b80)
        || image.get(0x1cfcc..0x1cfd6) != base.get(0x1cfcc..0x1cfd6)
        || image.get(0x1d3c6..0x1d3cc) != base.get(0x1d3c6..0x1d3cc)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
        || image.get(0x18f9a..0x18fbe) != base.get(0x18f9a..0x18fbe)
    {
        return Err(Error::Bytes {
            offset: STEADY_LOOP_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x110),
            (".probe", 0x22c0, 0x002),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = STEADY_LOOP_HOOK_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Builds the marker-armed wrapper around the proven live vendor-dispatcher call.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_dispatcher_return(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !DISPATCHER_RETURN_HOOK_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, DISPATCHER_RETURN_PATCH, &[0xfc, 0xf7, 0xf7, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        DISPATCHER_RETURN_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x63;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Audits the synchronous dispatcher wrapper, original stock call, marker-first arm, and return.
///
/// # Errors
///
/// Returns the first failed identity, branch, stock-call, header, or ELF invariant.
pub fn verify_dispatcher_return(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_dispatcher_return(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &DISPATCHER_RETURN_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &DISPATCHER_RETURN_HELPER)?;
    require(injection, 0x114, &[0xee, 0xe7])?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x108)? != 0x0001_8f4d || read_u32(injection, 0x10c)? != 0x0040_0264 {
        return Err(Error::Bytes { offset: 0x108 });
    }
    let target = decode_thumb_bl(
        read_array(image, DISPATCHER_RETURN_PATCH)?,
        ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if target.get() != HOOK {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    if image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1c550..0x1c55a) != base.get(0x1c550..0x1c55a)
        || image.get(0x1c55e..0x1c58c) != base.get(0x1c55e..0x1c58c)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x110),
            (".probe", 0x22c0, 0x002),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = DISPATCHER_RETURN_HOOK_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Builds the reusable marker-first Rust experiment dispatcher.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_experiment_dispatch(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !EXPERIMENT_DISPATCH_GUARD_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, DISPATCHER_RETURN_PATCH, &[0xfc, 0xf7, 0xf7, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        DISPATCHER_RETURN_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(EXPERIMENT_DISPATCH).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x64;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the marker-first one-shot unsolicited endpoint-2 report probe.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_unsolicited_report_probe(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !UNSOLICITED_REPORT_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, DISPATCHER_RETURN_PATCH, &[0xfc, 0xf7, 0xf7, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        DISPATCHER_RETURN_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(EXPERIMENT_DISPATCH).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x71;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the automatic marker-first handoff that replaces the stock wired runtime.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_custom_main_handoff_probe(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !CUSTOM_MAIN_HANDOFF_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, CUSTOM_MAIN_HANDOFF_PATCH, &[0x02, 0xf0, 0x02, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        CUSTOM_MAIN_HANDOFF_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x72;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the automatic marker-first custom main that services stock USB recovery.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed injection are supplied.
pub fn build_custom_main_usb_recovery_probe(
    base: &[u8],
    injection: &[u8],
) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !CUSTOM_MAIN_USB_RECOVERY_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, CUSTOM_MAIN_HANDOFF_PATCH, &[0x02, 0xf0, 0x02, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        CUSTOM_MAIN_HANDOFF_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x73;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the marker-first custom main with a continuous endpoint-2 transport loop.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and both reviewed code regions are supplied.
pub fn build_custom_main_stream_transport_probe(
    base: &[u8],
    injection: &[u8],
    runtime: &[u8],
) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    if runtime.len() > CUSTOM_RUNTIME_LIMIT - CUSTOM_RUNTIME_START {
        return Err(Error::RuntimeSize {
            actual: runtime.len(),
        });
    }
    if !CUSTOM_MAIN_STREAM_TRANSPORT_RUNTIME_ARTIFACT.code_matches(runtime) {
        return Err(Error::RuntimeIdentity);
    }
    for value in PROTECTED_RUNTIME_WORDS {
        if runtime
            .windows(size_of::<u32>())
            .any(|window| window == value.to_le_bytes())
        {
            return Err(Error::ProtectedRuntimeWord { value });
        }
    }
    require_base(base, CUSTOM_MAIN_HANDOFF_PATCH, &[0x02, 0xf0, 0x02, 0xfc])?;
    require_base(base, CUSTOM_RUNTIME_START, &[0x12, 0x20, 0xfb, 0xf7])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(&mut image, CUSTOM_RUNTIME_START, runtime)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        CUSTOM_MAIN_HANDOFF_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x74;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the marker-first custom main with accumulated dual-sensor reports.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and three reviewed code regions are supplied.
pub fn build_custom_main_sensor_stream_probe(
    base: &[u8],
    injection: &[u8],
    runtime: &[u8],
    support: &[u8],
) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !CUSTOM_MAIN_SENSOR_STREAM_PROBE_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    if runtime.len() > CUSTOM_RUNTIME_LITERAL_START - CUSTOM_RUNTIME_START {
        return Err(Error::RuntimeSize {
            actual: runtime.len(),
        });
    }
    if !CUSTOM_MAIN_SENSOR_STREAM_RUNTIME_ARTIFACT.code_matches(runtime) {
        return Err(Error::RuntimeIdentity);
    }
    if support.len() != SENSOR_STREAM_SUPPORT_LIMIT - SENSOR_STREAM_SUPPORT_START {
        return Err(Error::RuntimeSize {
            actual: support.len(),
        });
    }
    if !CUSTOM_MAIN_SENSOR_STREAM_SUPPORT_ARTIFACT.code_matches(support) {
        return Err(Error::RuntimeIdentity);
    }
    for code in [runtime, support] {
        for value in PROTECTED_RUNTIME_WORDS {
            if code
                .windows(size_of::<u32>())
                .any(|window| window == value.to_le_bytes())
            {
                return Err(Error::ProtectedRuntimeWord { value });
            }
        }
    }
    require_base(base, CUSTOM_MAIN_HANDOFF_PATCH, &[0x02, 0xf0, 0x02, 0xfc])?;
    require_base(base, CUSTOM_RUNTIME_START, &[0x12, 0x20, 0xfb, 0xf7])?;
    require_base(base, SENSOR_SHADOW_PATCH, &[0x34, 0x80, 0x09, 0x48])?;
    require_base(base, SENSOR_STREAM_SUPPORT_START, &[0xf0, 0xb5, 0x00, 0x24])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(&mut image, CUSTOM_RUNTIME_START, runtime)?;
    replace(&mut image, SENSOR_STREAM_SUPPORT_START, support)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        CUSTOM_MAIN_HANDOFF_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        SENSOR_SHADOW_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(SENSOR_SHADOW_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(
                u32::try_from(SENSOR_STREAM_SUPPORT_START).map_err(|_| Error::Layout)?,
            )
            .map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x75;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the marker-first, read-only stock input snapshot candidate.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed diagnostic injection are supplied.
pub fn build_input_diagnostics(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !INPUT_DIAGNOSTICS_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, DISPATCHER_RETURN_PATCH, &[0xfc, 0xf7, 0xf7, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        DISPATCHER_RETURN_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(EXPERIMENT_DISPATCH).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x65;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the marker-first, selector-based live-state diagnostic candidate.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed paged injection are supplied.
pub fn build_paged_input_diagnostics(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !PAGED_INPUT_DIAGNOSTICS_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, DISPATCHER_RETURN_PATCH, &[0xfc, 0xf7, 0xf7, 0xfc])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        DISPATCHER_RETURN_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(EXPERIMENT_DISPATCH).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x66;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Builds the marker-first per-sensor shadow diagnostic candidate.
///
/// # Errors
///
/// Returns an error unless the exact v4.53 base and reviewed shadow injection are supplied.
pub fn build_sensor_shadow_diagnostics(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, Error> {
    STARTUP_TRAMPOLINE
        .validate(base)
        .map_err(|_| Error::BaseIdentity)?;
    if injection.len() != INJECTION_END - INJECTION_START {
        return Err(Error::InjectionSize {
            actual: injection.len(),
        });
    }
    if !SENSOR_SHADOW_DIAGNOSTICS_ARTIFACT.code_matches(injection) {
        return Err(Error::InjectionIdentity);
    }
    require_base(base, SENSOR_SHADOW_PATCH, &[0x34, 0x80, 0x09, 0x48])?;

    let mut image = base.to_vec();
    replace(&mut image, INJECTION_START, injection)?;
    replace(
        &mut image,
        RESET_BRANCH,
        &encode_arm_b(
            ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ArmAddress::new(TRAMPOLINE).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    replace(
        &mut image,
        SENSOR_SHADOW_PATCH,
        &encode_thumb_bl(
            ThumbAddress::new(u32::try_from(SENSOR_SHADOW_PATCH).map_err(|_| Error::Layout)?)
                .map_err(Error::Branch)?,
            ThumbAddress::new(SENSOR_SHADOW_HOOK).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?,
    )?;
    *image.get_mut(V449_BCD_DEVICE_OFFSET).ok_or(Error::Layout)? = 0x70;
    refresh_header_crc(&mut image, APPLICATION_HEADER_OFFSET).map_err(|_| Error::Header)?;
    refresh_header_crc(&mut image, STACK_HEADER_OFFSET).map_err(|_| Error::Header)?;
    Ok(image)
}

/// Audits the guard, clear-before-call order, Rust entry, stock dispatcher, and return path.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, header, or ELF invariant.
pub fn verify_experiment_dispatch(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_experiment_dispatch(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &EXPERIMENT_DISPATCH_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &EXPERIMENT_DISPATCH_HELPER)?;
    require(injection, 0x114, &RUST_EXPERIMENT_ENTRY)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x10c)? != 0x0001_8f4d || read_u32(injection, 0x110)? != 0x0040_0264 {
        return Err(Error::Bytes { offset: 0x10c });
    }
    let wrapper_target = decode_thumb_bl(
        read_array(image, DISPATCHER_RETURN_PATCH)?,
        ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if wrapper_target.get() != EXPERIMENT_DISPATCH {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    let rust_target = decode_thumb_bl(
        read_array(image, EXPERIMENT_CALL)?,
        ThumbAddress::new(u32::try_from(EXPERIMENT_CALL).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if rust_target.get() != HOOK {
        return Err(Error::Bytes {
            offset: EXPERIMENT_CALL,
        });
    }
    if image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1c550..0x1c55a) != base.get(0x1c550..0x1c55a)
        || image.get(0x1c55e..0x1c58c) != base.get(0x1c55e..0x1c58c)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x114),
            (".probe", 0x22c0, 0x006),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = EXPERIMENT_DISPATCH_GUARD
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits the marker-first one-shot endpoint-2 re-arm probe.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, stock-path, header, or ELF invariant.
pub fn verify_unsolicited_report_probe(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_unsolicited_report_probe(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &UNSOLICITED_REPORT_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &EXPERIMENT_DISPATCH_HELPER)?;
    require(injection, 0x114, &UNSOLICITED_REPORT_ENTRY)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x10c)? != 0x0001_8f4d
        || read_u32(injection, 0x110)? != 0x0040_0264
        || read_u32(injection, 0x11c)? != 0x0040_0371
    {
        return Err(Error::Bytes { offset: 0x10c });
    }
    let wrapper_target = decode_thumb_bl(
        read_array(image, DISPATCHER_RETURN_PATCH)?,
        ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if wrapper_target.get() != EXPERIMENT_DISPATCH {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    let probe_target = decode_thumb_bl(
        read_array(image, EXPERIMENT_CALL)?,
        ThumbAddress::new(u32::try_from(EXPERIMENT_CALL).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if probe_target.get() != HOOK {
        return Err(Error::Bytes {
            offset: EXPERIMENT_CALL,
        });
    }
    if image.get(0x11ef4..0x11f28) != base.get(0x11ef4..0x11f28)
        || image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1b4d0..0x1b534) != base.get(0x1b4d0..0x1b534)
        || image.get(0x1c550..0x1c55a) != base.get(0x1c550..0x1c55a)
        || image.get(0x1c55e..0x1c58c) != base.get(0x1c55e..0x1c58c)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x114),
            (".probe", 0x22c0, 0x00c),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = UNSOLICITED_REPORT_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits the post-init boundary, marker-before-custom ordering, and deliberate non-return.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, stock-path, header, or ELF invariant.
pub fn verify_custom_main_handoff_probe(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_custom_main_handoff_probe(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &EXPERIMENT_DISPATCH_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &CUSTOM_MAIN_RETAINED_DISPATCH_HELPER)?;
    require(injection, 0x114, &CUSTOM_MAIN_HANDOFF_ENTRY)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    let marker_target = decode_thumb_bl(
        read_array(injection, 0x116)?,
        ThumbAddress::new(HOOK + 2).map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if marker_target.get() != 0x21d8 {
        return Err(Error::Bytes { offset: 0x116 });
    }
    let handoff_target = decode_thumb_bl(
        read_array(image, CUSTOM_MAIN_HANDOFF_PATCH)?,
        ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if handoff_target.get() != HOOK {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }
    if image.get(0x19878..CUSTOM_MAIN_HANDOFF_PATCH) != base.get(0x19878..CUSTOM_MAIN_HANDOFF_PATCH)
        || image.get(0x19c0c..0x19c14) != base.get(0x19c0c..0x19c14)
        || image.get(0x1c410..0x1c5c0) != base.get(0x1c410..0x1c5c0)
        || image.get(0x1c5c0..0x1c878) != base.get(0x1c5c0..0x1c878)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x114),
            (".probe", 0x22c0, 0x00a),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = CUSTOM_MAIN_HANDOFF_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits marker-before-main ordering and the minimal stock USB-dispatch loop.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, stock-path, header, or ELF invariant.
pub fn verify_custom_main_usb_recovery_probe(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_custom_main_usb_recovery_probe(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &EXPERIMENT_DISPATCH_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &CUSTOM_MAIN_USB_LOOP)?;
    require(injection, 0x114, &CUSTOM_MAIN_USB_HANDOFF)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x0fc)? != 0x0001_8f4d {
        return Err(Error::Bytes { offset: 0x0fc });
    }
    let marker_target = decode_thumb_bl(
        read_array(injection, 0x116)?,
        ThumbAddress::new(HOOK + 2).map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if marker_target.get() != 0x21d8 {
        return Err(Error::Bytes { offset: 0x116 });
    }
    let handoff_target = decode_thumb_bl(
        read_array(image, CUSTOM_MAIN_HANDOFF_PATCH)?,
        ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if handoff_target.get() != HOOK {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }
    if image.get(0x19878..CUSTOM_MAIN_HANDOFF_PATCH) != base.get(0x19878..CUSTOM_MAIN_HANDOFF_PATCH)
        || image.get(0x19c0c..0x19c14) != base.get(0x19c0c..0x19c14)
        || image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1b4d0..0x1b534) != base.get(0x1b4d0..0x1b534)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x100),
            (".probe", 0x22c0, 0x008),
            (".trampoline", 0x22cc, 0x034),
        ],
    )?;
    let payload = CUSTOM_MAIN_USB_RECOVERY_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits the marker-first stock initializer and continuous Rust endpoint-2 loop.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, stock-path, or ELF invariant.
pub fn verify_custom_main_stream_transport_probe(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    runtime: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_custom_main_stream_transport_probe(base, injection, runtime)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &EXPERIMENT_DISPATCH_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &CUSTOM_MAIN_STREAM_VENEERS)?;
    require(injection, 0x114, &CUSTOM_MAIN_STREAM_HANDOFF)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }

    let marker_target = decode_thumb_bl(
        read_array(injection, 0x116)?,
        ThumbAddress::new(HOOK + 2).map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if marker_target.get() != 0x21d8 {
        return Err(Error::Bytes { offset: 0x116 });
    }
    let wired_initializer_target = decode_thumb_bl(
        read_array(injection, 0x11a)?,
        ThumbAddress::new(HOOK + 6).map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if wired_initializer_target.get() != 0x22a8 {
        return Err(Error::Bytes { offset: 0x11a });
    }
    let dispatcher_veneer = decode_thumb_bl(
        read_array(runtime, 0x10)?,
        ThumbAddress::new(0x1c470).map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if dispatcher_veneer.get() != 0x22a0 {
        return Err(Error::Bytes {
            offset: CUSTOM_RUNTIME_START + 0x10,
        });
    }
    let transmitter_veneer = decode_thumb_bl(
        read_array(runtime, 0x76)?,
        ThumbAddress::new(0x1c4d6).map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if transmitter_veneer.get() != 0x22a4 {
        return Err(Error::Bytes {
            offset: CUSTOM_RUNTIME_START + 0x76,
        });
    }

    let handoff_target = decode_thumb_bl(
        read_array(image, CUSTOM_MAIN_HANDOFF_PATCH)?,
        ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if handoff_target.get() != HOOK {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }
    let runtime_end = CUSTOM_RUNTIME_START
        .checked_add(runtime.len())
        .ok_or(Error::Layout)?;
    if image.get(0x19878..CUSTOM_MAIN_HANDOFF_PATCH) != base.get(0x19878..CUSTOM_MAIN_HANDOFF_PATCH)
        || image.get(0x19c0c..CUSTOM_RUNTIME_START) != base.get(0x19c0c..CUSTOM_RUNTIME_START)
        || image.get(runtime_end..CUSTOM_RUNTIME_LIMIT)
            != base.get(runtime_end..CUSTOM_RUNTIME_LIMIT)
        || image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x11ef4..0x11f28) != base.get(0x11ef4..0x11f28)
        || image.get(0x1b4d0..0x1b534) != base.get(0x1b4d0..0x1b534)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x10c),
            (".probe", 0x22c0, 0x00c),
            (".trampoline", 0x22cc, 0x034),
            (".custom_runtime", 0x1c460, 0x094),
        ],
    )?;
    let payload = CUSTOM_MAIN_STREAM_TRANSPORT_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits the marker-first dual-sensor stream and its retained USB recovery path.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, stock-path, or ELF invariant.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the independent injection, runtime, and support regions remain explicit"
)]
pub fn verify_custom_main_sensor_stream_probe(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    runtime: &[u8],
    support: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_custom_main_sensor_stream_probe(base, injection, runtime, support)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &EXPERIMENT_DISPATCH_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &CUSTOM_MAIN_STREAM_VENEERS)?;
    require(injection, 0x10c, &CUSTOM_MAIN_SENSOR_VENEER)?;
    require(injection, 0x114, &CUSTOM_MAIN_STREAM_HANDOFF)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }

    let calls = [
        (0x10, 0x1c470, 0x22a0),
        (0x1c, 0x1c47c, 0x22b8),
        (0xf4, 0x1c554, 0x1c5e0),
        (0xfa, 0x1c55a, 0x22a4),
    ];
    for (offset, call_address, target) in calls {
        let actual = decode_thumb_bl(
            read_array(runtime, offset)?,
            ThumbAddress::new(call_address).map_err(Error::Branch)?,
        )
        .map_err(Error::Branch)?;
        if actual.get() != target {
            return Err(Error::Bytes {
                offset: CUSTOM_RUNTIME_START + offset,
            });
        }
    }
    let sensor_hook_target = decode_thumb_bl(
        read_array(image, SENSOR_SHADOW_PATCH)?,
        ThumbAddress::new(u32::try_from(SENSOR_SHADOW_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if sensor_hook_target.get()
        != u32::try_from(SENSOR_STREAM_SUPPORT_START).map_err(|_| Error::Layout)?
    {
        return Err(Error::Bytes {
            offset: SENSOR_SHADOW_PATCH,
        });
    }
    let handoff_target = decode_thumb_bl(
        read_array(image, CUSTOM_MAIN_HANDOFF_PATCH)?,
        ThumbAddress::new(u32::try_from(CUSTOM_MAIN_HANDOFF_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if handoff_target.get() != HOOK {
        return Err(Error::Bytes {
            offset: CUSTOM_MAIN_HANDOFF_PATCH,
        });
    }

    let runtime_end = CUSTOM_RUNTIME_START
        .checked_add(runtime.len())
        .ok_or(Error::Layout)?;
    for (start, end) in [
        (0x19878, CUSTOM_MAIN_HANDOFF_PATCH),
        (0x19c0c, 0x1a74c),
        (0x1a74c, SENSOR_SHADOW_PATCH),
        (SENSOR_SHADOW_PATCH + 4, 0x1a7c8),
        (0x1a7c8, CUSTOM_RUNTIME_START),
        (runtime_end, CUSTOM_RUNTIME_LITERAL_START),
        (CUSTOM_RUNTIME_LITERAL_START, SENSOR_STREAM_SUPPORT_START),
        (SENSOR_STREAM_SUPPORT_LIMIT, 0x1c834),
        (0x18f4c, 0x19004),
        (0x11ef4, 0x11f28),
        (0x1b4d0, 0x1b534),
        (0x2300, 0x2330),
    ] {
        if image.get(start..end) != base.get(start..end) {
            return Err(Error::Bytes { offset: start });
        }
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[
            (".carrier", 0x21ac, 0x114),
            (".probe", 0x22c0, 0x00c),
            (".trampoline", 0x22cc, 0x034),
            (".custom_runtime", 0x1c460, 0x128),
            (".sensor_hook", 0x1c5c0, 0x014),
            (".sensor_support", 0x1c5e0, 0x04c),
        ],
    )?;
    let payload = CUSTOM_MAIN_SENSOR_STREAM_PROBE
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits the marker-first input snapshot, proven recovery bytes, and stock return path.
///
/// # Errors
///
/// Returns the first failed identity, instruction, address, branch, header, or ELF invariant.
pub fn verify_input_diagnostics(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_input_diagnostics(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &INPUT_DIAGNOSTICS_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &INPUT_DIAGNOSTICS_HELPER)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x114)? != 0x0001_8f4d
        || read_u32(injection, 0x118)? != 0x0040_0264
        || read_u32(injection, 0x11c)? != 0x0040_1360
    {
        return Err(Error::Bytes { offset: 0x114 });
    }
    let wrapper_target = decode_thumb_bl(
        read_array(image, DISPATCHER_RETURN_PATCH)?,
        ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if wrapper_target.get() != EXPERIMENT_DISPATCH {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    let (_, reset_target) = decode_arm_branch(
        read_array(image, RESET_BRANCH)?,
        ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if reset_target.get() != TRAMPOLINE {
        return Err(Error::Bytes {
            offset: RESET_BRANCH,
        });
    }
    if image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1c550..0x1c55a) != base.get(0x1c550..0x1c55a)
        || image.get(0x1c55e..0x1c58c) != base.get(0x1c55e..0x1c58c)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes { offset: 0x21d8 });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[(".carrier", 0x21ac, 0x120), (".trampoline", 0x22cc, 0x034)],
    )?;
    let payload = INPUT_DIAGNOSTICS
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits selector scaling, bounded RAM base, proven recovery bytes, and stock return path.
///
/// # Errors
///
/// Returns the first failed identity, instruction, address, branch, header, or ELF invariant.
pub fn verify_paged_input_diagnostics(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_paged_input_diagnostics(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &DISPATCH)?;
    require(injection, 0x12, &PAGED_INPUT_DIAGNOSTICS_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &PAGED_INPUT_DIAGNOSTICS_HELPER)?;
    for (offset, expected) in WIRED_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    if read_u32(injection, 0x114)? != 0x0001_8f4d
        || read_u32(injection, 0x118)? != 0x0040_0264
        || read_u32(injection, 0x11c)? != 0x0040_0160
    {
        return Err(Error::Bytes { offset: 0x114 });
    }
    let wrapper_target = decode_thumb_bl(
        read_array(image, DISPATCHER_RETURN_PATCH)?,
        ThumbAddress::new(u32::try_from(DISPATCHER_RETURN_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if wrapper_target.get() != EXPERIMENT_DISPATCH {
        return Err(Error::Bytes {
            offset: DISPATCHER_RETURN_PATCH,
        });
    }
    let (_, reset_target) = decode_arm_branch(
        read_array(image, RESET_BRANCH)?,
        ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if reset_target.get() != TRAMPOLINE {
        return Err(Error::Bytes {
            offset: RESET_BRANCH,
        });
    }
    if image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1c550..0x1c55a) != base.get(0x1c550..0x1c55a)
        || image.get(0x1c55e..0x1c58c) != base.get(0x1c55e..0x1c58c)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes { offset: 0x21d8 });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[(".carrier", 0x21ac, 0x120), (".trampoline", 0x22cc, 0x034)],
    )?;
    let payload = PAGED_INPUT_DIAGNOSTICS
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

/// Audits the pre-clear shadow call, displaced instructions, recovery bytes, and stock paths.
///
/// # Errors
///
/// Returns the first failed identity, instruction, address, branch, header, or ELF invariant.
pub fn verify_sensor_shadow_diagnostics(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<Report, Error> {
    if image != build_sensor_shadow_diagnostics(base, injection)? {
        return Err(Error::DerivedImage);
    }
    require(injection, 0, &SENSOR_SHADOW_DISPATCH)?;
    require(injection, 0x12, &SENSOR_SHADOW_ARM_AND_QUERY)?;
    require(injection, 0x0f4, &SENSOR_SHADOW_HELPER)?;
    for (offset, expected) in SENSOR_SHADOW_CRITICAL_WORDS {
        let actual = read_u32(injection, offset)?;
        if actual != expected {
            return Err(Error::Word { offset, actual });
        }
    }
    let shadow_target = decode_thumb_bl(
        read_array(image, SENSOR_SHADOW_PATCH)?,
        ThumbAddress::new(u32::try_from(SENSOR_SHADOW_PATCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if shadow_target.get() != SENSOR_SHADOW_HOOK {
        return Err(Error::Bytes {
            offset: SENSOR_SHADOW_PATCH,
        });
    }
    let (_, reset_target) = decode_arm_branch(
        read_array(image, RESET_BRANCH)?,
        ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if reset_target.get() != TRAMPOLINE {
        return Err(Error::Bytes {
            offset: RESET_BRANCH,
        });
    }
    if image.get(0x18f4c..0x19004) != base.get(0x18f4c..0x19004)
        || image.get(0x1a74c..SENSOR_SHADOW_PATCH) != base.get(0x1a74c..SENSOR_SHADOW_PATCH)
        || image.get(SENSOR_SHADOW_PATCH + 4..0x1a7c8) != base.get(SENSOR_SHADOW_PATCH + 4..0x1a7c8)
        || image.get(0x1c550..0x1c58c) != base.get(0x1c550..0x1c58c)
        || image.get(0x2300..0x2330) != base.get(0x2300..0x2330)
    {
        return Err(Error::Bytes {
            offset: SENSOR_SHADOW_PATCH,
        });
    }
    for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
        let header = parse_header(image, offset).map_err(|_| Error::Header)?;
        if !header.crc_is_valid(image).map_err(|_| Error::Header)? {
            return Err(Error::Header);
        }
    }
    verify_elf(
        elf_bytes,
        &[(".carrier", 0x21ac, 0x120), (".trampoline", 0x22cc, 0x034)],
    )?;
    let payload = SENSOR_SHADOW_DIAGNOSTICS
        .validate(image)
        .map_err(|_| Error::ContainerIdentity)?;
    Ok(Report {
        injection_sha256: sha256(injection),
        container_sha256: sha256(image),
        payload_sha256: sha256(payload),
        payload_crc: slimblade_protocol::updater_crc32(payload),
    })
}

fn verify_branch_chain(image: &[u8]) -> Result<(), Error> {
    require(image, MODE_BRANCH, &[0x35, 0xd1])?;
    require(image, LOCAL_BRANCH - 1, &[0x00, 0xad, 0xe5])?;
    require(image, 0x197cb, &[0x00])?;
    verify_direct_call_and_reset(image, MAIN_LOOP)
}

fn verify_direct_call_and_reset(image: &[u8], main_loop: u32) -> Result<(), Error> {
    let target = decode_thumb_bl(
        read_array(image, LOCAL_CALL)?,
        ThumbAddress::new(u32::try_from(LOCAL_CALL).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if target.get() != HOOK {
        return Err(Error::Bytes { offset: LOCAL_CALL });
    }
    if read_u32(image, 0x22c8)? != main_loop | 1 {
        return Err(Error::Bytes { offset: 0x22c8 });
    }
    let (_, reset_target) = decode_arm_branch(
        read_array(image, RESET_BRANCH)?,
        ArmAddress::new(u32::try_from(RESET_BRANCH).map_err(|_| Error::Layout)?)
            .map_err(Error::Branch)?,
    )
    .map_err(Error::Branch)?;
    if reset_target.get() != TRAMPOLINE {
        return Err(Error::Bytes {
            offset: RESET_BRANCH,
        });
    }
    Ok(())
}

fn verify_elf(bytes: &[u8], expected_geometry: &[(&str, u32, u32)]) -> Result<(), Error> {
    let elf = Elf32::parse(bytes).map_err(|_| Error::Elf)?;
    if elf.elf_type() != ELF_TYPE_EXECUTABLE
        || elf.machine() != ELF_MACHINE_ARM
        || elf.entry() != TRAMPOLINE
    {
        return Err(Error::Elf);
    }
    let mut geometry = Vec::new();
    for section in elf.sections() {
        let section = section.map_err(|_| Error::Elf)?;
        if section.is_relocation() || section.is_writable_allocated() {
            return Err(Error::Elf);
        }
        if section.is_allocated_executable() {
            geometry.push((section.name, section.address, section.size));
        }
    }
    if geometry != expected_geometry {
        return Err(Error::Elf);
    }
    Ok(())
}

fn replace(bytes: &mut [u8], offset: usize, replacement: &[u8]) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.saturating_add(replacement.len()))
        .ok_or(Error::Layout)?
        .copy_from_slice(replacement);
    Ok(())
}

fn require_base(bytes: &[u8], offset: usize, expected: &[u8]) -> Result<(), Error> {
    require(bytes, offset, expected).map_err(|_| Error::BaseIdentity)
}

fn require(bytes: &[u8], offset: usize, expected: &[u8]) -> Result<(), Error> {
    if bytes.get(offset..offset.saturating_add(expected.len())) == Some(expected) {
        Ok(())
    } else {
        Err(Error::Bytes { offset })
    }
}

fn read_array(bytes: &[u8], offset: usize) -> Result<[u8; 4], Error> {
    bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(Error::Layout)?
        .try_into()
        .map_err(|_| Error::Layout)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
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

    struct RuntimeFixtures {
        base: Vec<u8>,
        injection: Vec<u8>,
        runtime: Vec<u8>,
        container: Vec<u8>,
        elf: Vec<u8>,
    }

    struct SensorRuntimeFixtures {
        base: Vec<u8>,
        injection: Vec<u8>,
        runtime: Vec<u8>,
        support: Vec<u8>,
        container: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read post-init hook fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "post-init-hook/DO_NOT_FLASH-post-init-hook-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "post-init-hook/DO_NOT_FLASH-post-init-hook-probe.container.bin",
            ))?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-post-init-hook-probe"),
            )?,
        })
    }

    fn wired_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "wired-loop-hook/DO_NOT_FLASH-wired-loop-hook-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "wired-loop-hook/DO_NOT_FLASH-wired-loop-hook-probe.container.bin",
            ))?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-wired-loop-hook-probe"),
            )?,
        })
    }

    fn active_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "active-loop-hook/DO_NOT_FLASH-active-loop-hook-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "active-loop-hook/DO_NOT_FLASH-active-loop-hook-probe.container.bin",
            ))?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-active-loop-hook-probe"),
            )?,
        })
    }

    fn steady_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "steady-loop-hook/DO_NOT_FLASH-steady-loop-hook-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "steady-loop-hook/DO_NOT_FLASH-steady-loop-hook-probe.container.bin",
            ))?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-steady-loop-hook-probe"),
            )?,
        })
    }

    fn dispatcher_return_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "dispatcher-return-hook/DO_NOT_FLASH-dispatcher-return-hook-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "dispatcher-return-hook/DO_NOT_FLASH-dispatcher-return-hook-probe.container.bin",
            ))?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-dispatcher-return-hook-probe",
            ))?,
        })
    }

    fn experiment_dispatch_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.container.bin",
            ))?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-experiment-dispatch-guard",
            ))?,
        })
    }

    fn unsolicited_report_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.container.bin",
            ))?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-unsolicited-report-probe",
            ))?,
        })
    }

    fn custom_main_handoff_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.container.bin",
            ))?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-custom-main-handoff-probe",
            ))?,
        })
    }

    fn custom_main_usb_recovery_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.container.bin",
            ))?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-custom-main-usb-recovery-probe",
            ))?,
        })
    }

    fn custom_main_stream_transport_fixtures() -> Option<RuntimeFixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        let artifact = target.join("custom-main-stream-transport");
        Some(RuntimeFixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-stream-transport-probe.injection.bin"),
            )?,
            runtime: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-stream-transport-probe.runtime.bin"),
            )?,
            container: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-stream-transport-probe.container.bin"),
            )?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-custom-main-stream-transport-probe",
            ))?,
        })
    }

    fn custom_main_sensor_stream_fixtures() -> Option<SensorRuntimeFixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        let artifact = target.join("custom-main-sensor-stream");
        Some(SensorRuntimeFixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-sensor-stream-probe.injection.bin"),
            )?,
            runtime: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-sensor-stream-probe.runtime.bin"),
            )?,
            support: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-sensor-stream-probe.sensor.bin"),
            )?,
            container: read_if_present(
                artifact.join("DO_NOT_FLASH-custom-main-sensor-stream-probe.container.bin"),
            )?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-custom-main-sensor-stream-probe",
            ))?,
        })
    }

    fn input_diagnostics_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(
                target.join(
                    "input-diagnostics/DO_NOT_FLASH-input-diagnostics.injection.bin",
                ),
            )?,
            container: read_if_present(
                target.join(
                    "input-diagnostics/DO_NOT_FLASH-input-diagnostics.container.bin",
                ),
            )?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-input-diagnostics"),
            )?,
        })
    }

    fn paged_input_diagnostics_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "paged-input-diagnostics/DO_NOT_FLASH-paged-input-diagnostics.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "paged-input-diagnostics/DO_NOT_FLASH-paged-input-diagnostics.container.bin",
            ))?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-paged-input-diagnostics"),
            )?,
        })
    }

    fn sensor_shadow_diagnostics_fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "sensor-shadow-diagnostics/DO_NOT_FLASH-sensor-shadow-diagnostics.injection.bin",
            ))?,
            container: read_if_present(target.join(
                "sensor-shadow-diagnostics/DO_NOT_FLASH-sensor-shadow-diagnostics.container.bin",
            ))?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-sensor-shadow-diagnostics"),
            )?,
        })
    }

    #[test]
    fn exact_candidate_rebuilds_and_passes() {
        let Some(data) = fixtures() else { return };
        assert_eq!(
            build(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify(&data.base, &data.container, &data.injection, &data.elf)
            .expect("audit exact post-init hook probe");
        assert_eq!(report.payload_crc, 0x8065_29df);
    }

    #[test]
    fn input_diagnostics_rebuilds_and_passes() {
        let Some(data) = input_diagnostics_fixtures() else {
            return;
        };
        assert_eq!(
            build_input_diagnostics(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report =
            verify_input_diagnostics(&data.base, &data.container, &data.injection, &data.elf)
                .expect("audit exact input diagnostic");
        assert_eq!(report.payload_crc, 0xef6a_b24a);
    }

    #[test]
    fn input_diagnostics_preserves_proven_recovery_bytes() {
        let Some(data) = input_diagnostics_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let guard = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.injection.bin",
        ))
        .expect("read proven experiment guard");
        assert_eq!(&data.injection[0x2c..0x0f4], &guard[0x2c..0x0f4]);
        assert_eq!(&data.injection[0x120..0x154], &guard[0x120..0x154]);
    }

    #[test]
    fn input_diagnostics_rejects_snapshot_corruption() {
        let Some(mut data) = input_diagnostics_fixtures() else {
            return;
        };
        data.injection[0x108] ^= 1;
        assert_eq!(
            build_input_diagnostics(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );
    }

    #[test]
    fn paged_input_diagnostics_rebuilds_and_passes() {
        let Some(data) = paged_input_diagnostics_fixtures() else {
            return;
        };
        assert_eq!(
            build_paged_input_diagnostics(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report =
            verify_paged_input_diagnostics(&data.base, &data.container, &data.injection, &data.elf)
                .expect("audit exact paged input diagnostic");
        assert_eq!(report.payload_crc, 0x7ed6_3bf1);
    }

    #[test]
    fn paged_input_diagnostics_preserves_proven_recovery_bytes() {
        let Some(data) = paged_input_diagnostics_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let guard = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.injection.bin",
        ))
        .expect("read proven experiment guard");
        assert_eq!(&data.injection[0x2c..0x0f4], &guard[0x2c..0x0f4]);
        assert_eq!(&data.injection[0x120..0x154], &guard[0x120..0x154]);
    }

    #[test]
    fn paged_input_diagnostics_rejects_selector_scaling_corruption() {
        let Some(mut data) = paged_input_diagnostics_fixtures() else {
            return;
        };
        data.injection[0x26] ^= 1;
        assert_eq!(
            build_paged_input_diagnostics(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );
    }

    #[test]
    fn sensor_shadow_diagnostics_rebuilds_and_passes() {
        let Some(data) = sensor_shadow_diagnostics_fixtures() else {
            return;
        };
        assert_eq!(
            build_sensor_shadow_diagnostics(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_sensor_shadow_diagnostics(
            &data.base,
            &data.container,
            &data.injection,
            &data.elf,
        )
        .expect("audit exact sensor shadow diagnostic");
        assert_eq!(report.payload_crc, 0x96bd_3f6d);
    }

    #[test]
    fn sensor_shadow_diagnostics_preserves_proven_recovery_bytes() {
        let Some(data) = sensor_shadow_diagnostics_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let guard = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.injection.bin",
        ))
        .expect("read proven experiment guard");
        assert_eq!(&data.injection[0x2c..0x0c4], &guard[0x2c..0x0c4]);
        assert_eq!(&data.injection[0x0c8..0x0f4], &guard[0x0c8..0x0f4]);
        assert_eq!(&data.injection[0x120..0x154], &guard[0x120..0x154]);
    }

    #[test]
    fn sensor_shadow_diagnostics_rejects_hook_corruption() {
        let Some(mut data) = sensor_shadow_diagnostics_fixtures() else {
            return;
        };
        data.injection[0x0fe] ^= 1;
        assert_eq!(
            build_sensor_shadow_diagnostics(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );
    }

    #[test]
    fn arm_is_after_the_marker_call() {
        let Some(data) = fixtures() else { return };
        let marker_call = decode_thumb_bl(
            read_array(&data.injection, 0x14).expect("marker call"),
            ThumbAddress::new(0x21c0).expect("call address"),
        )
        .expect("decode marker call");
        assert_eq!(marker_call.get(), 0x21d8);
        assert_eq!(&data.injection[0x18..0x22], &ARM_AND_QUERY[6..16]);
    }

    #[test]
    fn changed_injection_and_branch_are_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[0x114] ^= 1;
        assert_eq!(
            build(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = fixtures() else { return };
        data.container[MODE_BRANCH] ^= 1;
        assert_eq!(
            verify(&data.base, &data.container, &data.injection, &data.elf),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn corrected_wired_candidate_rebuilds_and_passes() {
        let Some(data) = wired_fixtures() else { return };
        assert_eq!(
            build_wired(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_wired(&data.base, &data.container, &data.injection, &data.elf)
            .expect("audit exact wired-loop hook probe");
        assert_eq!(report.payload_crc, 0xd31d_c8f2);
    }

    #[test]
    fn corrected_probe_keeps_all_stock_switch_cases() {
        let Some(data) = wired_fixtures() else { return };
        assert_eq!(
            &data.base[0x19b59..0x19b5e],
            &[0x04, 0x07, 0x0a, 0x0d, 0x11]
        );
        assert_eq!(
            &data.container[0x19b59..0x19b5e],
            &[0x04, 0x07, 0x0a, 0x0d, 0x11]
        );
        assert_eq!(data.base[WIRED_SWITCH_DEFAULT], 0x13);
        assert_eq!(data.container[WIRED_SWITCH_DEFAULT], 0x8b);
    }

    #[test]
    fn active_loop_candidate_rebuilds_and_passes() {
        let Some(data) = active_fixtures() else {
            return;
        };
        assert_eq!(
            build_active(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_active(&data.base, &data.container, &data.injection, &data.elf)
            .expect("audit exact active-loop hook probe");
        assert_eq!(report.payload_crc, 0xdf50_3f76);
    }

    #[test]
    fn active_loop_candidate_locks_replay_and_patch() {
        let Some(mut data) = active_fixtures() else {
            return;
        };
        data.injection[0x0f4] ^= 1;
        assert_eq!(
            build_active(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = active_fixtures() else {
            return;
        };
        data.container[ACTIVE_LOOP_PATCH] ^= 1;
        assert_eq!(
            verify_active(&data.base, &data.container, &data.injection, &data.elf),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn steady_loop_candidate_rebuilds_and_passes() {
        let Some(data) = steady_fixtures() else {
            return;
        };
        assert_eq!(
            build_steady(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_steady(&data.base, &data.container, &data.injection, &data.elf)
            .expect("audit exact steady-loop hook probe");
        assert_eq!(report.payload_crc, 0x8a54_4004);
    }

    #[test]
    fn steady_loop_candidate_locks_wrapper_and_patch() {
        let Some(mut data) = steady_fixtures() else {
            return;
        };
        data.injection[0x0f4] ^= 1;
        assert_eq!(
            build_steady(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = steady_fixtures() else {
            return;
        };
        data.container[STEADY_LOOP_PATCH] ^= 1;
        assert_eq!(
            verify_steady(&data.base, &data.container, &data.injection, &data.elf),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn dispatcher_return_candidate_rebuilds_and_passes() {
        let Some(data) = dispatcher_return_fixtures() else {
            return;
        };
        assert_eq!(
            build_dispatcher_return(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report =
            verify_dispatcher_return(&data.base, &data.container, &data.injection, &data.elf)
                .expect("audit exact dispatcher-return hook probe");
        assert_eq!(report.payload_crc, 0x860c_2809);
    }

    #[test]
    fn dispatcher_return_candidate_locks_stock_call_and_patch() {
        let Some(mut data) = dispatcher_return_fixtures() else {
            return;
        };
        data.injection[0x108] ^= 1;
        assert_eq!(
            build_dispatcher_return(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = dispatcher_return_fixtures() else {
            return;
        };
        data.container[DISPATCHER_RETURN_PATCH] ^= 1;
        assert_eq!(
            verify_dispatcher_return(&data.base, &data.container, &data.injection, &data.elf,),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn experiment_dispatch_candidate_rebuilds_and_passes() {
        let Some(data) = experiment_dispatch_fixtures() else {
            return;
        };
        assert_eq!(
            build_experiment_dispatch(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report =
            verify_experiment_dispatch(&data.base, &data.container, &data.injection, &data.elf)
                .expect("audit exact experiment-dispatch guard");
        assert_eq!(report.payload_crc, 0x7057_4845);
    }

    #[test]
    fn experiment_dispatch_candidate_locks_guard_order_entry_and_patch() {
        let Some(mut data) = experiment_dispatch_fixtures() else {
            return;
        };
        data.injection[0x10c] ^= 1;
        assert_eq!(
            build_experiment_dispatch(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = experiment_dispatch_fixtures() else {
            return;
        };
        data.injection[0x114] ^= 1;
        assert_eq!(
            build_experiment_dispatch(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = experiment_dispatch_fixtures() else {
            return;
        };
        data.container[DISPATCHER_RETURN_PATCH] ^= 1;
        assert_eq!(
            verify_experiment_dispatch(&data.base, &data.container, &data.injection, &data.elf,),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn unsolicited_report_candidate_rebuilds_and_passes() {
        let Some(data) = unsolicited_report_fixtures() else {
            return;
        };
        assert_eq!(
            build_unsolicited_report_probe(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_unsolicited_report_probe(
            &data.base,
            &data.container,
            &data.injection,
            &data.elf,
        )
        .expect("audit exact unsolicited-report probe");
        assert_eq!(report.payload_crc, 0x4b61_d5a9);
    }

    #[test]
    fn unsolicited_report_candidate_locks_pending_byte_and_stock_senders() {
        let Some(mut data) = unsolicited_report_fixtures() else {
            return;
        };
        data.injection[0x114] ^= 1;
        assert_eq!(
            build_unsolicited_report_probe(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = unsolicited_report_fixtures() else {
            return;
        };
        data.container[0x11ef4] ^= 1;
        assert_eq!(
            verify_unsolicited_report_probe(
                &data.base,
                &data.container,
                &data.injection,
                &data.elf,
            ),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn unsolicited_report_candidate_preserves_proven_guard_and_trampoline() {
        let Some(data) = unsolicited_report_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proven = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.injection.bin",
        ))
        .expect("read proven experiment-dispatch guard");
        assert_eq!(&data.injection[..0x1e], &proven[..0x1e]);
        assert_eq!(&data.injection[0x1f..0x114], &proven[0x1f..0x114]);
        assert_eq!(&data.injection[0x120..], &proven[0x120..]);
    }

    #[test]
    fn custom_main_handoff_candidate_rebuilds_and_passes() {
        let Some(data) = custom_main_handoff_fixtures() else {
            return;
        };
        assert_eq!(
            build_custom_main_handoff_probe(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_custom_main_handoff_probe(
            &data.base,
            &data.container,
            &data.injection,
            &data.elf,
        )
        .expect("audit exact custom-main handoff probe");
        assert_eq!(report.payload_crc, 0x73c3_cfbe);
    }

    #[test]
    fn custom_main_handoff_preserves_live_marker_and_trampoline() {
        let Some(data) = custom_main_handoff_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proven = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.injection.bin",
        ))
        .expect("read live-tested unsolicited-report injection");
        assert_eq!(&data.injection[0x2c..0x0f4], &proven[0x2c..0x0f4]);
        assert_eq!(&data.injection[0x120..], &proven[0x120..]);
    }

    #[test]
    fn custom_main_handoff_rejects_entry_and_call_site_corruption() {
        let Some(mut data) = custom_main_handoff_fixtures() else {
            return;
        };
        data.injection[0x116] ^= 1;
        assert_eq!(
            build_custom_main_handoff_probe(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = custom_main_handoff_fixtures() else {
            return;
        };
        data.container[CUSTOM_MAIN_HANDOFF_PATCH] ^= 1;
        assert_eq!(
            verify_custom_main_handoff_probe(
                &data.base,
                &data.container,
                &data.injection,
                &data.elf,
            ),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn custom_main_usb_recovery_candidate_rebuilds_and_passes() {
        let Some(data) = custom_main_usb_recovery_fixtures() else {
            return;
        };
        assert_eq!(
            build_custom_main_usb_recovery_probe(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify_custom_main_usb_recovery_probe(
            &data.base,
            &data.container,
            &data.injection,
            &data.elf,
        )
        .expect("audit exact custom-main USB recovery probe");
        assert_eq!(report.payload_crc, 0x7b3c_a402);
    }

    #[test]
    fn custom_main_usb_recovery_preserves_marker_and_trampoline() {
        let Some(data) = custom_main_usb_recovery_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proven = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.injection.bin",
        ))
        .expect("read live-tested custom-main handoff injection");
        assert_eq!(&data.injection[..0x0f4], &proven[..0x0f4]);
        assert_eq!(&data.injection[0x120..], &proven[0x120..]);
    }

    #[test]
    fn custom_main_usb_recovery_rejects_dispatch_and_handoff_corruption() {
        let Some(mut data) = custom_main_usb_recovery_fixtures() else {
            return;
        };
        data.injection[0x0fc] ^= 1;
        assert_eq!(
            build_custom_main_usb_recovery_probe(&data.base, &data.injection),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = custom_main_usb_recovery_fixtures() else {
            return;
        };
        data.container[CUSTOM_MAIN_HANDOFF_PATCH] ^= 1;
        assert_eq!(
            verify_custom_main_usb_recovery_probe(
                &data.base,
                &data.container,
                &data.injection,
                &data.elf,
            ),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn custom_main_stream_transport_candidate_rebuilds_and_passes() {
        let Some(data) = custom_main_stream_transport_fixtures() else {
            return;
        };
        assert_eq!(
            build_custom_main_stream_transport_probe(&data.base, &data.injection, &data.runtime,),
            Ok(data.container.clone())
        );
        let report = verify_custom_main_stream_transport_probe(
            &data.base,
            &data.container,
            &data.injection,
            &data.runtime,
            &data.elf,
        )
        .expect("audit exact custom-main stream transport probe");
        assert_eq!(report.payload_crc, 0x105b_ca99);
    }

    #[test]
    fn custom_main_stream_transport_preserves_marker_and_trampoline() {
        let Some(data) = custom_main_stream_transport_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proven = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.injection.bin",
        ))
        .expect("read live-tested custom-main USB recovery injection");
        assert_eq!(&data.injection[..0x0f4], &proven[..0x0f4]);
        assert_eq!(&data.injection[0x120..], &proven[0x120..]);
    }

    #[test]
    fn custom_main_stream_transport_rejects_runtime_and_handoff_corruption() {
        let Some(mut data) = custom_main_stream_transport_fixtures() else {
            return;
        };
        data.runtime[0x10] ^= 1;
        assert_eq!(
            build_custom_main_stream_transport_probe(&data.base, &data.injection, &data.runtime,),
            Err(Error::RuntimeIdentity)
        );

        let Some(mut data) = custom_main_stream_transport_fixtures() else {
            return;
        };
        data.container[CUSTOM_MAIN_HANDOFF_PATCH] ^= 1;
        assert_eq!(
            verify_custom_main_stream_transport_probe(
                &data.base,
                &data.container,
                &data.injection,
                &data.runtime,
                &data.elf,
            ),
            Err(Error::DerivedImage)
        );
    }

    #[test]
    fn custom_main_sensor_stream_candidate_rebuilds_and_passes() {
        let Some(data) = custom_main_sensor_stream_fixtures() else {
            return;
        };
        assert_eq!(
            build_custom_main_sensor_stream_probe(
                &data.base,
                &data.injection,
                &data.runtime,
                &data.support,
            ),
            Ok(data.container.clone())
        );
        let report = verify_custom_main_sensor_stream_probe(
            &data.base,
            &data.container,
            &data.injection,
            &data.runtime,
            &data.support,
            &data.elf,
        )
        .expect("audit exact custom-main sensor stream probe");
        assert_eq!(report.payload_crc, 0xc430_b50f);
    }

    #[test]
    fn custom_main_sensor_stream_preserves_guard_and_wired_initializer_literals() {
        let Some(data) = custom_main_sensor_stream_fixtures() else {
            return;
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proven = std::fs::read(root.join(
            "firmware/bk3635-stock-harness/target/custom-main-stream-transport/DO_NOT_FLASH-custom-main-stream-transport-probe.injection.bin",
        ))
        .expect("read live-tested transport injection");
        assert_eq!(&data.injection[..0x10c], &proven[..0x10c]);
        assert_eq!(&data.injection[0x114..], &proven[0x114..]);
        assert_eq!(
            &data.container[CUSTOM_RUNTIME_LITERAL_START..SENSOR_STREAM_SUPPORT_START],
            &data.base[CUSTOM_RUNTIME_LITERAL_START..SENSOR_STREAM_SUPPORT_START]
        );
    }

    #[test]
    fn custom_main_sensor_stream_rejects_each_code_region_corruption() {
        let Some(mut data) = custom_main_sensor_stream_fixtures() else {
            return;
        };
        data.injection[0x10c] ^= 1;
        assert_eq!(
            build_custom_main_sensor_stream_probe(
                &data.base,
                &data.injection,
                &data.runtime,
                &data.support,
            ),
            Err(Error::InjectionIdentity)
        );

        let Some(mut data) = custom_main_sensor_stream_fixtures() else {
            return;
        };
        data.runtime[0x1c] ^= 1;
        assert_eq!(
            build_custom_main_sensor_stream_probe(
                &data.base,
                &data.injection,
                &data.runtime,
                &data.support,
            ),
            Err(Error::RuntimeIdentity)
        );

        let Some(mut data) = custom_main_sensor_stream_fixtures() else {
            return;
        };
        data.support[0] ^= 1;
        assert_eq!(
            build_custom_main_sensor_stream_probe(
                &data.base,
                &data.injection,
                &data.runtime,
                &data.support,
            ),
            Err(Error::RuntimeIdentity)
        );
    }
}
