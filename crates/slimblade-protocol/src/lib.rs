#![no_std]

use core::fmt;

pub const APPLICATION_PAYLOAD_OFFSET: u32 = 0x2000;
pub const NORMAL_REPORT_ID: u8 = 0x08;
pub const NORMAL_REPORT_LENGTH: usize = 17;
pub const SENSOR_STREAM_COMMAND: u8 = 0x20;
pub const SENSOR_STREAM_VERSION: u8 = 1;
pub const SENSOR_STREAM_ACCUMULATOR_SATURATED: u8 = 1 << 0;
pub const SENSOR_STREAM_SAMPLE_COUNT_SATURATED: u8 = 1 << 1;
pub const SENSOR_STREAM_KNOWN_FLAGS: u8 =
    SENSOR_STREAM_ACCUMULATOR_SATURATED | SENSOR_STREAM_SAMPLE_COUNT_SATURATED;
pub const USB_SETUP_PACKET_LENGTH: usize = 8;
pub const BOOT_REPORT_ID: u8 = 0x06;
pub const BOOT_REPORT_LENGTH: usize = 49;
pub const DOWNLOAD_BLOCK_LENGTH: usize = 32;

/// HID `SET_REPORT(Output, id=8)` for the `SlimBlade`'s vendor interface 1.
///
/// Fields are USB setup-packet byte order: host-to-device, class, interface;
/// request `SET_REPORT`; value `0x0208`; interface 1; 17-byte data stage.
pub const NORMAL_SET_REPORT_SETUP: [u8; USB_SETUP_PACKET_LENGTH] =
    [0x21, 0x09, 0x08, 0x02, 0x01, 0x00, 0x11, 0x00];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbIdentity {
    pub vendor_id: u16,
    pub product_id: u16,
}

pub const KENSINGTON_WIRED_IDENTITY: UsbIdentity = UsbIdentity {
    vendor_id: 0x047d,
    product_id: 0x80d7,
};
pub const BOOT_IDENTITIES: [UsbIdentity; 3] = [
    UsbIdentity {
        vendor_id: 0x25a7,
        product_id: 0xfabe,
    },
    UsbIdentity {
        vendor_id: 0x3554,
        product_id: 0xf600,
    },
    UsbIdentity {
        vendor_id: 0x3554,
        product_id: 0xf800,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalReport([u8; NORMAL_REPORT_LENGTH]);

impl NormalReport {
    /// Parses and validates a normal-mode report.
    ///
    /// # Errors
    ///
    /// Returns an error if the report has the wrong length, report ID, or checksum.
    #[allow(
        clippy::indexing_slicing,
        reason = "the exact report length is checked before the fixed report-ID byte is indexed"
    )]
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportParseError> {
        if bytes.len() != NORMAL_REPORT_LENGTH {
            return Err(ReportParseError::WrongLength {
                expected: NORMAL_REPORT_LENGTH,
                actual: bytes.len(),
            });
        }
        if bytes[0] != NORMAL_REPORT_ID {
            return Err(ReportParseError::WrongReportId {
                expected: NORMAL_REPORT_ID,
                actual: bytes[0],
            });
        }
        if !checksum_is_valid(bytes) {
            return Err(ReportParseError::InvalidChecksum);
        }
        let mut report = [0; NORMAL_REPORT_LENGTH];
        report.copy_from_slice(bytes);
        Ok(Self(report))
    }

    /// Constructs a normal-mode command report.
    ///
    /// The command is a byte at the type boundary, so an out-of-range integer
    /// cannot compile.
    ///
    /// ```compile_fail
    /// use slimblade_protocol::NormalReport;
    /// let _ = NormalReport::command(0x100);
    /// ```
    #[must_use]
    pub const fn command(command: u8) -> Self {
        let mut bytes = [0; NORMAL_REPORT_LENGTH];
        bytes[0] = NORMAL_REPORT_ID;
        bytes[1] = command;
        bytes[NORMAL_REPORT_LENGTH - 1] = checksum(&bytes);
        Self(bytes)
    }

    /// Constructs a normal-mode command with its one-byte parameter in byte 3.
    #[must_use]
    pub const fn command_with_parameter(command: u8, parameter: u8) -> Self {
        let mut bytes = [0; NORMAL_REPORT_LENGTH];
        bytes[0] = NORMAL_REPORT_ID;
        bytes[1] = command;
        bytes[3] = parameter;
        bytes[NORMAL_REPORT_LENGTH - 1] = checksum(&bytes);
        Self(bytes)
    }

    #[must_use]
    pub const fn reset_to_loader() -> Self {
        Self::command(0x0d)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NORMAL_REPORT_LENGTH] {
        &self.0
    }

    #[must_use]
    pub const fn command_byte(self) -> u8 {
        self.0[1]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensorStreamReport {
    pub flags: u8,
    pub sensor_a_x: i16,
    pub sensor_a_y: i16,
    pub sensor_b_x: i16,
    pub sensor_b_y: i16,
    pub buttons: u8,
    pub sample_count: u8,
    pub sequence: u16,
}

impl SensorStreamReport {
    /// Encodes a version-1 raw-sensor stream report with the normal checksum.
    #[must_use]
    pub const fn encode(self) -> NormalReport {
        let mut bytes = [0_u8; NORMAL_REPORT_LENGTH];
        bytes[0] = NORMAL_REPORT_ID;
        bytes[1] = SENSOR_STREAM_COMMAND;
        bytes[2] = SENSOR_STREAM_VERSION;
        bytes[3] = self.flags;
        let axis_bytes = self.sensor_a_x.to_le_bytes();
        bytes[4] = axis_bytes[0];
        bytes[5] = axis_bytes[1];
        let axis_bytes = self.sensor_a_y.to_le_bytes();
        bytes[6] = axis_bytes[0];
        bytes[7] = axis_bytes[1];
        let axis_bytes = self.sensor_b_x.to_le_bytes();
        bytes[8] = axis_bytes[0];
        bytes[9] = axis_bytes[1];
        let axis_bytes = self.sensor_b_y.to_le_bytes();
        bytes[10] = axis_bytes[0];
        bytes[11] = axis_bytes[1];
        bytes[12] = self.buttons;
        bytes[13] = self.sample_count;
        let [sequence_low, sequence_high] = self.sequence.to_le_bytes();
        bytes[14] = sequence_low;
        bytes[15] = sequence_high;
        bytes[16] = checksum(&bytes);
        NormalReport(bytes)
    }

    /// Decodes a checksum-validated normal report as the version-1 sensor stream ABI.
    ///
    /// # Errors
    ///
    /// Rejects another command, version, or any flag not defined by this version.
    pub const fn decode(report: NormalReport) -> Result<Self, SensorStreamReportError> {
        let bytes = report.0;
        if bytes[1] != SENSOR_STREAM_COMMAND {
            return Err(SensorStreamReportError::WrongCommand(bytes[1]));
        }
        if bytes[2] != SENSOR_STREAM_VERSION {
            return Err(SensorStreamReportError::WrongVersion(bytes[2]));
        }
        if bytes[3] & !SENSOR_STREAM_KNOWN_FLAGS != 0 {
            return Err(SensorStreamReportError::UnknownFlags(bytes[3]));
        }
        Ok(Self {
            flags: bytes[3],
            sensor_a_x: i16::from_le_bytes([bytes[4], bytes[5]]),
            sensor_a_y: i16::from_le_bytes([bytes[6], bytes[7]]),
            sensor_b_x: i16::from_le_bytes([bytes[8], bytes[9]]),
            sensor_b_y: i16::from_le_bytes([bytes[10], bytes[11]]),
            buttons: bytes[12],
            sample_count: bytes[13],
            sequence: u16::from_le_bytes([bytes[14], bytes[15]]),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorStreamReportError {
    WrongCommand(u8),
    WrongVersion(u8),
    UnknownFlags(u8),
}

impl fmt::Display for SensorStreamReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongCommand(actual) => {
                write!(formatter, "expected sensor command 0x20, got {actual:#04x}")
            },
            Self::WrongVersion(actual) => {
                write!(formatter, "expected sensor stream version 1, got {actual}")
            },
            Self::UnknownFlags(actual) => {
                write!(formatter, "sensor stream has unknown flags {actual:#04x}")
            },
        }
    }
}

impl core::error::Error for SensorStreamReportError {}

/// Accepts only a valid normal-mode report carrying the expected command byte.
#[must_use]
pub fn normal_command_response(bytes: &[u8], expected_command: u8) -> Option<NormalReport> {
    let report = NormalReport::parse(bytes).ok()?;
    (report.command_byte() == expected_command).then_some(report)
}

/// Accepts only the exact HID control transfer that requests the resident loader.
///
/// Keeping the setup and payload checks together prevents an unrelated class
/// request or malformed report from reaching the firmware reset path.
#[must_use]
pub fn is_loader_control_request(setup: &[u8], payload: &[u8]) -> bool {
    setup == NORMAL_SET_REPORT_SETUP
        && NormalReport::parse(payload).is_ok_and(|report| report.command_byte() == 0x0d)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootReport([u8; BOOT_REPORT_LENGTH]);

impl BootReport {
    /// Parses and validates a bootloader-mode report.
    ///
    /// # Errors
    ///
    /// Returns an error if the report has the wrong length or report ID.
    #[allow(
        clippy::indexing_slicing,
        reason = "the exact report length is checked before the fixed report-ID byte is indexed"
    )]
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportParseError> {
        if bytes.len() != BOOT_REPORT_LENGTH {
            return Err(ReportParseError::WrongLength {
                expected: BOOT_REPORT_LENGTH,
                actual: bytes.len(),
            });
        }
        if bytes[0] != BOOT_REPORT_ID {
            return Err(ReportParseError::WrongReportId {
                expected: BOOT_REPORT_ID,
                actual: bytes[0],
            });
        }
        let mut report = [0; BOOT_REPORT_LENGTH];
        report.copy_from_slice(bytes);
        Ok(Self(report))
    }

    #[must_use]
    pub const fn command(command: u8) -> Self {
        let mut bytes = [0; BOOT_REPORT_LENGTH];
        bytes[0] = BOOT_REPORT_ID;
        bytes[1] = command;
        bytes[BOOT_REPORT_LENGTH - 1] = checksum(&bytes);
        Self(bytes)
    }

    #[must_use]
    pub const fn reset() -> Self {
        Self::command(0x0d)
    }

    #[must_use]
    pub const fn query() -> Self {
        Self::command(0xb2)
    }

    #[must_use]
    pub const fn prepare(payload_length: u32, payload_crc: u32) -> Self {
        let mut bytes = [0; BOOT_REPORT_LENGTH];
        bytes[0] = BOOT_REPORT_ID;
        bytes[1] = 0xb0;
        let length = payload_length.to_be_bytes();
        bytes[5] = length[0];
        bytes[6] = length[1];
        bytes[7] = length[2];
        bytes[8] = length[3];
        let crc = payload_crc.to_be_bytes();
        bytes[9] = crc[0];
        bytes[10] = crc[1];
        bytes[11] = crc[2];
        bytes[12] = crc[3];
        Self(bytes)
    }

    /// Constructs a bootloader download packet for one payload block.
    ///
    /// # Errors
    ///
    /// Returns an error if `offset` is outside the payload or cannot be represented by the
    /// bootloader's 32-bit address field.
    #[allow(
        clippy::indexing_slicing,
        reason = "offset and block bounds are checked before copying into fixed packet fields"
    )]
    pub fn download(payload: &[u8], offset: usize) -> Result<Self, PacketError> {
        if offset >= payload.len() {
            return Err(PacketError::PayloadOffset {
                offset,
                payload_length: payload.len(),
            });
        }
        let Ok(address_offset) = u32::try_from(offset) else {
            return Err(PacketError::AddressOverflow);
        };
        let address = APPLICATION_PAYLOAD_OFFSET
            .checked_add(address_offset)
            .ok_or(PacketError::AddressOverflow)?;
        let remaining = payload.len() - offset;
        let data_length = remaining.min(DOWNLOAD_BLOCK_LENGTH);
        let Ok(data_length_u8) = u8::try_from(data_length) else {
            return Err(PacketError::AddressOverflow);
        };
        let final_block = data_length == remaining;

        let mut bytes = [0; BOOT_REPORT_LENGTH];
        bytes[0] = BOOT_REPORT_ID;
        bytes[1] = 0xb1;
        bytes[2] = if final_block { 0xc1 } else { 0xc0 };
        bytes[3] = data_length_u8;
        let address = address.to_be_bytes();
        bytes[5..9].copy_from_slice(&address);
        bytes[17..].fill(0xff);
        bytes[17..17 + data_length].copy_from_slice(&payload[offset..offset + data_length]);
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BOOT_REPORT_LENGTH] {
        &self.0
    }

    #[must_use]
    pub const fn command_byte(self) -> u8 {
        self.0[1]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportParseError {
    WrongLength { expected: usize, actual: usize },
    WrongReportId { expected: u8, actual: u8 },
    InvalidChecksum,
}

impl fmt::Display for ReportParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected}-byte report, got {actual}")
            },
            Self::WrongReportId { expected, actual } => {
                write!(f, "expected report ID {expected:#04x}, got {actual:#04x}")
            },
            Self::InvalidChecksum => f.write_str("report checksum is invalid"),
        }
    }
}

impl core::error::Error for ReportParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    PayloadOffset {
        offset: usize,
        payload_length: usize,
    },
    AddressOverflow,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadOffset {
                offset,
                payload_length,
            } => write!(
                f,
                "payload offset {offset} is outside {payload_length}-byte image"
            ),
            Self::AddressOverflow => f.write_str("payload address exceeds 32 bits"),
        }
    }
}

impl core::error::Error for PacketError {}

#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "the const loop condition proves every indexed byte is within the slice"
)]
pub const fn checksum(bytes: &[u8]) -> u8 {
    let mut sum = 0_u8;
    let mut index = 0;
    while index < bytes.len() {
        sum = sum.wrapping_add(bytes[index]);
        index += 1;
    }
    0x55_u8.wrapping_sub(sum)
}

#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "the const loop condition proves every indexed byte is within the slice"
)]
pub const fn checksum_is_valid(bytes: &[u8]) -> bool {
    let mut sum = 0_u8;
    let mut index = 0;
    while index < bytes.len() {
        sum = sum.wrapping_add(bytes[index]);
        index += 1;
    }
    sum == 0x55
}

/// BK3635 updater CRC: reflected CRC-32 with an all-ones initial value and no
/// final XOR.
#[must_use]
#[allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    reason = "the const loop proves indexing; u8-to-u32 is lossless and const From is not stable"
)]
pub const fn updater_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    let mut byte_index = 0;
    while byte_index < bytes.len() {
        crc ^= bytes[byte_index] as u32;
        let mut bit = 0_u32;
        while bit < 8_u32 {
            crc = if crc & 1 == 1 {
                (crc >> 1_u32) ^ 0xedb8_8320
            } else {
                crc >> 1_u32
            };
            bit += 1_u32;
        }
        byte_index += 1;
    }
    crc
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use fixed vectors and expect success as part of each assertion"
)]
mod tests {
    use super::*;

    #[test]
    fn known_boot_identities_match_recorded_values() {
        assert!(BOOT_IDENTITIES.contains(&UsbIdentity {
            vendor_id: 0x25a7,
            product_id: 0xfabe,
        }));
        assert!(BOOT_IDENTITIES.contains(&UsbIdentity {
            vendor_id: 0x3554,
            product_id: 0xf600,
        }));
        assert!(BOOT_IDENTITIES.contains(&UsbIdentity {
            vendor_id: 0x3554,
            product_id: 0xf800,
        }));
    }

    #[test]
    fn normal_report_parser_accepts_only_valid_checksummed_reports() {
        let report = NormalReport::command(0x0e);
        assert_eq!(NormalReport::parse(report.as_bytes()), Ok(report));

        let mut bad_checksum = *report.as_bytes();
        bad_checksum[16] ^= 1;
        assert_eq!(
            NormalReport::parse(&bad_checksum),
            Err(ReportParseError::InvalidChecksum)
        );
        assert!(matches!(
            NormalReport::parse(&report.as_bytes()[..16]),
            Err(ReportParseError::WrongLength { .. })
        ));
        let mut wrong_id = *report.as_bytes();
        wrong_id[0] = BOOT_REPORT_ID;
        assert!(matches!(
            NormalReport::parse(&wrong_id),
            Err(ReportParseError::WrongReportId { .. })
        ));
    }

    #[test]
    fn sensor_stream_report_round_trips_every_field() {
        let expected = SensorStreamReport {
            flags: SENSOR_STREAM_ACCUMULATOR_SATURATED,
            sensor_a_x: -1234,
            sensor_a_y: 2345,
            sensor_b_x: i16::MIN,
            sensor_b_y: i16::MAX,
            buttons: 0x15,
            sample_count: 7,
            sequence: 0xabcd,
        };
        let encoded = expected.encode();
        assert!(checksum_is_valid(encoded.as_bytes()));
        assert_eq!(SensorStreamReport::decode(encoded), Ok(expected));
    }

    #[test]
    fn sensor_stream_report_rejects_wrong_type_version_and_flags() {
        let base = SensorStreamReport {
            flags: 0,
            sensor_a_x: 0,
            sensor_a_y: 0,
            sensor_b_x: 0,
            sensor_b_y: 0,
            buttons: 0,
            sample_count: 0,
            sequence: 0,
        }
        .encode();

        let mut bytes = *base.as_bytes();
        bytes[1] ^= 1;
        bytes[16] = 0;
        bytes[16] = checksum(&bytes);
        let report = NormalReport::parse(&bytes).expect("wrong command retains a valid envelope");
        assert!(matches!(
            SensorStreamReport::decode(report),
            Err(SensorStreamReportError::WrongCommand(_))
        ));

        bytes = *base.as_bytes();
        bytes[2] = SENSOR_STREAM_VERSION + 1;
        bytes[16] = 0;
        bytes[16] = checksum(&bytes);
        let report = NormalReport::parse(&bytes).expect("wrong version retains a valid envelope");
        assert!(matches!(
            SensorStreamReport::decode(report),
            Err(SensorStreamReportError::WrongVersion(_))
        ));

        bytes = *base.as_bytes();
        bytes[3] = 0x80;
        bytes[16] = 0;
        bytes[16] = checksum(&bytes);
        let report = NormalReport::parse(&bytes).expect("unknown flags retain a valid envelope");
        assert!(matches!(
            SensorStreamReport::decode(report),
            Err(SensorStreamReportError::UnknownFlags(_))
        ));
    }

    #[test]
    fn read_probe_accepts_only_valid_checksummed_command_reply() {
        let report = NormalReport::command(0x0e);
        assert_eq!(
            normal_command_response(report.as_bytes(), 0x0e),
            Some(report)
        );
        assert_eq!(normal_command_response(report.as_bytes(), 0x0f), None);
    }

    #[test]
    fn read_probe_rejects_bad_checksum() {
        let report = NormalReport::command(0x0e);
        let mut corrupted = *report.as_bytes();
        corrupted[16] ^= 1;
        assert_eq!(normal_command_response(&corrupted, 0x0e), None);
    }

    #[test]
    fn boot_report_parser_enforces_length_and_report_id() {
        let report = BootReport::query();
        assert_eq!(BootReport::parse(report.as_bytes()), Ok(report));
        assert!(matches!(
            BootReport::parse(&report.as_bytes()[..48]),
            Err(ReportParseError::WrongLength { .. })
        ));
        let mut wrong_id = *report.as_bytes();
        wrong_id[0] = NORMAL_REPORT_ID;
        assert!(matches!(
            BootReport::parse(&wrong_id),
            Err(ReportParseError::WrongReportId { .. })
        ));
    }

    #[test]
    fn normal_reset_packet_matches_recorded_bytes() {
        assert_eq!(
            NormalReport::reset_to_loader().as_bytes(),
            &[0x08, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40,]
        );
    }

    #[test]
    fn loader_control_request_requires_exact_setup_and_payload() {
        let report = NormalReport::reset_to_loader();
        assert!(is_loader_control_request(
            &NORMAL_SET_REPORT_SETUP,
            report.as_bytes()
        ));

        for index in 0..NORMAL_SET_REPORT_SETUP.len() {
            let mut changed_setup = NORMAL_SET_REPORT_SETUP;
            changed_setup[index] ^= 1;
            assert!(!is_loader_control_request(
                &changed_setup,
                report.as_bytes()
            ));
        }

        let mut changed_payload = *report.as_bytes();
        changed_payload[1] = 0x0e;
        changed_payload[16] = checksum(&changed_payload);
        assert!(!is_loader_control_request(
            &NORMAL_SET_REPORT_SETUP,
            &changed_payload
        ));
        assert!(!is_loader_control_request(
            &NORMAL_SET_REPORT_SETUP,
            &report.as_bytes()[..16]
        ));
    }

    #[test]
    fn carrier_command_packets_match_recorded_bytes() {
        for (command, final_checksum) in [(0x0e, 0x3f), (0x0f, 0x3e), (0x10, 0x3d)] {
            let report = NormalReport::command(command);
            assert_eq!(report.as_bytes()[16], final_checksum);
            assert!(checksum_is_valid(report.as_bytes()));
        }
    }

    #[test]
    fn parameterized_command_places_parameter_and_refreshes_checksum() {
        let report = NormalReport::command_with_parameter(0x0f, 0x06);
        assert_eq!(
            report.as_bytes(),
            &[
                0x08, 0x0f, 0, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x38
            ]
        );
        assert!(checksum_is_valid(report.as_bytes()));
    }

    #[test]
    fn boot_reset_packet_matches_recorded_bytes() {
        let report = BootReport::reset();
        assert_eq!(&report.as_bytes()[..2], &[0x06, 0x0d]);
        assert_eq!(report.as_bytes()[48], 0x42);
        assert!(checksum_is_valid(report.as_bytes()));
    }

    #[test]
    fn boot_query_packet_matches_recorded_bytes() {
        let report = BootReport::query();
        assert_eq!(&report.as_bytes()[..2], &[0x06, 0xb2]);
        assert_eq!(report.as_bytes()[48], 0x9d);
        assert!(checksum_is_valid(report.as_bytes()));
    }

    #[test]
    fn updater_crc_matches_recorded_vectors() {
        assert_eq!(updater_crc32(b""), 0xffff_ffff);
        assert_eq!(updater_crc32(b"123456789"), 0x340b_c6d9);
        let mut payload = [0_u8; 256];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = if index == 255 {
                0xff
            } else {
                u8::try_from(index).expect("fixture index fits in one byte")
            };
        }
        assert_eq!(updater_crc32(&payload), 0xd6fa_738c);
    }

    #[test]
    fn prepare_packet_matches_recorded_bytes() {
        let report = BootReport::prepare(256, 0xd6fa_738c);
        assert_eq!(&report.as_bytes()[..2], &[0x06, 0xb0]);
        assert_eq!(&report.as_bytes()[5..9], &[0, 0, 1, 0]);
        assert_eq!(&report.as_bytes()[9..13], &[0xd6, 0xfa, 0x73, 0x8c]);
    }

    #[test]
    fn nonfinal_download_packet_matches_recorded_bytes() {
        let payload: [u8; 64] = core::array::from_fn(|index| {
            u8::try_from(index).expect("fixture index fits in one byte")
        });
        let report = BootReport::download(&payload, 0).expect("valid first block");
        assert_eq!(&report.as_bytes()[..4], &[0x06, 0xb1, 0xc0, 0x20]);
        assert_eq!(&report.as_bytes()[5..9], &[0, 0, 0x20, 0]);
        assert_eq!(&report.as_bytes()[17..], &payload[..32]);
    }

    #[test]
    fn short_final_download_packet_is_ff_padded() {
        let payload: [u8; 35] = core::array::from_fn(|index| {
            u8::try_from(index).expect("fixture index fits in one byte")
        });
        let report = BootReport::download(&payload, 32).expect("valid final block");
        assert_eq!(&report.as_bytes()[..4], &[0x06, 0xb1, 0xc1, 0x03]);
        assert_eq!(&report.as_bytes()[5..9], &[0, 0, 0x20, 0x20]);
        assert_eq!(&report.as_bytes()[17..20], &payload[32..]);
        assert_eq!(&report.as_bytes()[20..], &[0xff; 29]);
    }

    #[test]
    fn download_rejects_offset_outside_payload() {
        assert_eq!(
            BootReport::download(&[1, 2, 3], 3),
            Err(PacketError::PayloadOffset {
                offset: 3,
                payload_length: 3,
            })
        );
    }
}
