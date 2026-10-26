use slimblade_image::{
    ACTIVE_LOOP_HOOK_PROBE, CUSTOM_MAIN_HANDOFF_PROBE, CUSTOM_MAIN_SENSOR_STREAM_PROBE,
    CUSTOM_MAIN_STREAM_TRANSPORT_PROBE, CUSTOM_MAIN_USB_RECOVERY_PROBE,
    DISPATCHER_RETURN_HOOK_PROBE, EXPERIMENT_DISPATCH_GUARD, EXPERIMENT_ENTRY_PROBE,
    FirmwareIdentity, INPUT_DIAGNOSTICS, LATE_MARKER_PROBE, OFFICIAL_V449, PAGED_INPUT_DIAGNOSTICS,
    POST_INIT_HOOK_PROBE, RECOVERY_CARRIER, RECOVERY_GUARD, RECOVERY_STUB, RESET_TRAMPOLINE,
    RUST_RESPONSE_PROBE, SENSOR_SHADOW_DIAGNOSTICS, STARTUP_TRAMPOLINE, STEADY_LOOP_HOOK_PROBE,
    STOCK_HARNESS, UNSOLICITED_REPORT_PROBE, USB_RECOVERY_PROBE, V449_DESCRIPTOR_PROBE,
    WIRED_LOOP_HOOK_PROBE,
};
use slimblade_protocol::NormalReport;

pub const FULL_RECOVERY_CONFIRMATION: &str = "ERASE-MARKER-RESET";

#[must_use]
pub fn late_marker_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e && response.as_bytes().get(2) == Some(&0x01)
}

#[must_use]
pub fn rust_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0x58)
}

#[must_use]
pub fn post_init_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xa3)
}

#[must_use]
pub fn wired_loop_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xa5)
}

#[must_use]
pub fn active_loop_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xa6)
}

#[must_use]
pub fn steady_loop_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xa7)
}

#[must_use]
pub fn dispatcher_return_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xa8)
}

#[must_use]
pub fn experiment_dispatch_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xa9)
}

#[must_use]
pub fn sensor_shadow_arm_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xaa)
}

#[must_use]
pub fn unsolicited_report_probe_response_is_success(response: NormalReport) -> bool {
    response.command_byte() == 0x0e
        && response.as_bytes().get(2) == Some(&0x01)
        && response.as_bytes().get(3) == Some(&0xab)
}

#[must_use]
pub fn post_init_hook_state(response: NormalReport) -> Option<u8> {
    if response.command_byte() == 0x0f && response.as_bytes().get(2) == Some(&0x01) {
        response.as_bytes().get(3).copied()
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputSnapshot {
    pub prefix: [u8; 2],
    pub sequence: u8,
    pub buttons: u8,
    pub motion_x: i16,
    pub motion_y: i16,
    pub report_6: u8,
    pub report_7: u8,
    pub report_8: u8,
    pub report_9: u8,
}

#[must_use]
pub fn input_snapshot(response: NormalReport) -> Option<InputSnapshot> {
    let bytes = response.as_bytes();
    if response.command_byte() != 0x0f || bytes.get(2) != Some(&0x01) {
        return None;
    }
    Some(InputSnapshot {
        prefix: [*bytes.get(4)?, *bytes.get(5)?],
        sequence: *bytes.get(6)?,
        buttons: *bytes.get(7)?,
        motion_x: i16::from_le_bytes([*bytes.get(8)?, *bytes.get(9)?]),
        motion_y: i16::from_le_bytes([*bytes.get(10)?, *bytes.get(11)?]),
        report_6: *bytes.get(12)?,
        report_7: *bytes.get(13)?,
        report_8: *bytes.get(14)?,
        report_9: *bytes.get(15)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputStatePage {
    pub selector: u8,
    pub bytes: [u8; 12],
}

impl InputStatePage {
    #[must_use]
    pub fn address(self) -> u32 {
        0x0040_0160 + u32::from(self.selector) * 8
    }

    #[must_use]
    pub const fn halfwords(self) -> [u16; 6] {
        let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11] = self.bytes;
        [
            u16::from_le_bytes([b0, b1]),
            u16::from_le_bytes([b2, b3]),
            u16::from_le_bytes([b4, b5]),
            u16::from_le_bytes([b6, b7]),
            u16::from_le_bytes([b8, b9]),
            u16::from_le_bytes([b10, b11]),
        ]
    }
}

#[must_use]
pub fn input_state_page(response: NormalReport, selector: u8) -> Option<InputStatePage> {
    let response_bytes = response.as_bytes();
    if response.command_byte() != 0x0f
        || response_bytes.get(2) != Some(&0x01)
        || response_bytes.get(3) != Some(&selector)
    {
        return None;
    }
    let mut bytes = [0_u8; 12];
    bytes.copy_from_slice(response_bytes.get(4..16)?);
    Some(InputStatePage { selector, bytes })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensorShadow {
    pub sequence: u8,
    pub sensor_a_x: i16,
    pub sensor_a_y: i16,
    pub sensor_b_x: i16,
    pub sensor_b_y: i16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SensorTotals {
    pub sensor_a_x: i64,
    pub sensor_a_y: i64,
    pub sensor_b_x: i64,
    pub sensor_b_y: i64,
}

impl SensorTotals {
    fn checked_add(self, sample: SensorShadow) -> Option<Self> {
        Some(Self {
            sensor_a_x: self.sensor_a_x.checked_add(i64::from(sample.sensor_a_x))?,
            sensor_a_y: self.sensor_a_y.checked_add(i64::from(sample.sensor_a_y))?,
            sensor_b_x: self.sensor_b_x.checked_add(i64::from(sample.sensor_b_x))?,
            sensor_b_y: self.sensor_b_y.checked_add(i64::from(sample.sensor_b_y))?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorObservationKind {
    Initial,
    Changed,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensorObservation {
    pub kind: SensorObservationKind,
    pub sequence_gap: u8,
    pub polls: u64,
    pub changed_samples: u64,
    pub skipped_samples: u64,
    pub sample: SensorShadow,
    pub totals: SensorTotals,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorTrackerError {
    PollCounterOverflow,
    ChangedCounterOverflow,
    SkippedCounterOverflow,
    TotalOverflow,
    InconsistentRetainedSample,
}

impl core::fmt::Display for SensorTrackerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PollCounterOverflow => formatter.write_str("sensor poll counter overflow"),
            Self::ChangedCounterOverflow => {
                formatter.write_str("changed sensor tuple counter overflow")
            },
            Self::SkippedCounterOverflow => {
                formatter.write_str("skipped sensor sample counter overflow")
            },
            Self::TotalOverflow => formatter.write_str("sensor total overflow"),
            Self::InconsistentRetainedSample => {
                formatter.write_str("sensor values changed without a sequence change")
            },
        }
    }
}

impl core::error::Error for SensorTrackerError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SensorTracker {
    previous: Option<SensorShadow>,
    polls: u64,
    changed_samples: u64,
    skipped_samples: u64,
    totals: SensorTotals,
}

impl SensorTracker {
    #[must_use]
    pub const fn polls(&self) -> u64 {
        self.polls
    }

    #[must_use]
    pub const fn changed_samples(&self) -> u64 {
        self.changed_samples
    }

    #[must_use]
    pub const fn skipped_samples(&self) -> u64 {
        self.skipped_samples
    }

    #[must_use]
    pub const fn totals(&self) -> SensorTotals {
        self.totals
    }

    /// Classifies a USB observation and accumulates each new sequence once.
    ///
    /// The v4.70 sequence wraps modulo 256. This remains unambiguous while
    /// fewer than 256 nonzero firmware samples occur between USB reads.
    ///
    /// # Errors
    ///
    /// Returns an error instead of wrapping a counter or signed total.
    pub fn observe(
        &mut self,
        sample: SensorShadow,
    ) -> Result<SensorObservation, SensorTrackerError> {
        self.polls = self
            .polls
            .checked_add(1)
            .ok_or(SensorTrackerError::PollCounterOverflow)?;
        let (kind, sequence_gap) = match self.previous {
            None => (SensorObservationKind::Initial, 0),
            Some(previous) if previous.sequence == sample.sequence => {
                if previous != sample {
                    return Err(SensorTrackerError::InconsistentRetainedSample);
                }
                (SensorObservationKind::Retained, 0)
            },
            Some(previous) => {
                let sequence_gap = sample.sequence.wrapping_sub(previous.sequence);
                self.changed_samples = self
                    .changed_samples
                    .checked_add(1)
                    .ok_or(SensorTrackerError::ChangedCounterOverflow)?;
                self.skipped_samples = self
                    .skipped_samples
                    .checked_add(u64::from(sequence_gap.saturating_sub(1)))
                    .ok_or(SensorTrackerError::SkippedCounterOverflow)?;
                self.totals = self
                    .totals
                    .checked_add(sample)
                    .ok_or(SensorTrackerError::TotalOverflow)?;
                (SensorObservationKind::Changed, sequence_gap)
            },
        };
        self.previous = Some(sample);
        Ok(SensorObservation {
            kind,
            sequence_gap,
            polls: self.polls,
            changed_samples: self.changed_samples,
            skipped_samples: self.skipped_samples,
            sample,
            totals: self.totals,
        })
    }
}

#[must_use]
pub fn sensor_shadow(response: NormalReport) -> Option<SensorShadow> {
    let bytes = response.as_bytes();
    if response.command_byte() != 0x0f || bytes.get(2) != Some(&0x01) {
        return None;
    }
    Some(SensorShadow {
        sequence: *bytes.get(12)?,
        sensor_a_x: i16::from_le_bytes([*bytes.get(4)?, *bytes.get(5)?]),
        sensor_a_y: i16::from_le_bytes([*bytes.get(6)?, *bytes.get(7)?]),
        sensor_b_x: i16::from_le_bytes([*bytes.get(8)?, *bytes.get(9)?]),
        sensor_b_y: i16::from_le_bytes([*bytes.get(10)?, *bytes.get(11)?]),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashArtifact {
    OfficialV449,
    DescriptorProbe,
    RecoveryCarrier,
    ResetTrampoline,
    RecoveryStub,
    StartupTrampoline,
    RecoveryGuard,
    UsbRecoveryProbe,
    StockHarness,
    LateMarkerProbe,
    ExperimentEntryProbe,
    RustResponseProbe,
    PostInitHookProbe,
    WiredLoopHookProbe,
    ActiveLoopHookProbe,
    SteadyLoopHookProbe,
    DispatcherReturnHookProbe,
    ExperimentDispatchGuard,
    InputDiagnostics,
    PagedInputDiagnostics,
    SensorShadowDiagnostics,
    UnsolicitedReportProbe,
    CustomMainHandoffProbe,
    CustomMainUsbRecoveryProbe,
    CustomMainStreamTransportProbe,
    CustomMainSensorStreamProbe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostFlashExpectation {
    Application { bcd_device: &'static str },
    ResidentLoader,
    UsbSilence,
}

impl FlashArtifact {
    /// Returns why an artifact must be retained for analysis but never flashed again.
    #[must_use]
    pub const fn flash_refusal_reason(self) -> Option<&'static str> {
        match self {
            Self::CustomMainSensorStreamProbe => Some(
                "the 0475 sensor-stream image failed live recovery and is retained only for analysis",
            ),
            _ => None,
        }
    }

    #[must_use]
    pub const fn identity(self) -> FirmwareIdentity {
        match self {
            Self::OfficialV449 => OFFICIAL_V449,
            Self::DescriptorProbe => V449_DESCRIPTOR_PROBE,
            Self::RecoveryCarrier => RECOVERY_CARRIER,
            Self::ResetTrampoline => RESET_TRAMPOLINE,
            Self::RecoveryStub => RECOVERY_STUB,
            Self::StartupTrampoline => STARTUP_TRAMPOLINE,
            Self::RecoveryGuard => RECOVERY_GUARD,
            Self::UsbRecoveryProbe => USB_RECOVERY_PROBE,
            Self::StockHarness => STOCK_HARNESS,
            Self::LateMarkerProbe => LATE_MARKER_PROBE,
            Self::ExperimentEntryProbe => EXPERIMENT_ENTRY_PROBE,
            Self::RustResponseProbe => RUST_RESPONSE_PROBE,
            Self::PostInitHookProbe => POST_INIT_HOOK_PROBE,
            Self::WiredLoopHookProbe => WIRED_LOOP_HOOK_PROBE,
            Self::ActiveLoopHookProbe => ACTIVE_LOOP_HOOK_PROBE,
            Self::SteadyLoopHookProbe => STEADY_LOOP_HOOK_PROBE,
            Self::DispatcherReturnHookProbe => DISPATCHER_RETURN_HOOK_PROBE,
            Self::ExperimentDispatchGuard => EXPERIMENT_DISPATCH_GUARD,
            Self::InputDiagnostics => INPUT_DIAGNOSTICS,
            Self::PagedInputDiagnostics => PAGED_INPUT_DIAGNOSTICS,
            Self::SensorShadowDiagnostics => SENSOR_SHADOW_DIAGNOSTICS,
            Self::UnsolicitedReportProbe => UNSOLICITED_REPORT_PROBE,
            Self::CustomMainHandoffProbe => CUSTOM_MAIN_HANDOFF_PROBE,
            Self::CustomMainUsbRecoveryProbe => CUSTOM_MAIN_USB_RECOVERY_PROBE,
            Self::CustomMainStreamTransportProbe => CUSTOM_MAIN_STREAM_TRANSPORT_PROBE,
            Self::CustomMainSensorStreamProbe => CUSTOM_MAIN_SENSOR_STREAM_PROBE,
        }
    }

    #[must_use]
    pub fn confirmation_matches(self, confirmation: &str) -> bool {
        digest_matches_hex(self.identity().container_sha256, confirmation)
    }

    #[must_use]
    pub fn confirmation_sha256(self) -> String {
        digest_to_hex(self.identity().container_sha256)
    }

    #[must_use]
    pub const fn post_flash_expectation(self) -> PostFlashExpectation {
        match self {
            Self::OfficialV449 => PostFlashExpectation::Application { bcd_device: "0449" },
            Self::DescriptorProbe => PostFlashExpectation::Application { bcd_device: "0450" },
            Self::RecoveryCarrier => PostFlashExpectation::Application { bcd_device: "0451" },
            Self::ResetTrampoline => PostFlashExpectation::Application { bcd_device: "0452" },
            Self::StartupTrampoline => PostFlashExpectation::Application { bcd_device: "0453" },
            Self::RecoveryStub => PostFlashExpectation::ResidentLoader,
            Self::RecoveryGuard => PostFlashExpectation::UsbSilence,
            Self::UsbRecoveryProbe => PostFlashExpectation::Application { bcd_device: "0454" },
            Self::StockHarness => PostFlashExpectation::Application { bcd_device: "0455" },
            Self::LateMarkerProbe => PostFlashExpectation::Application { bcd_device: "0456" },
            Self::ExperimentEntryProbe => PostFlashExpectation::Application { bcd_device: "0457" },
            Self::RustResponseProbe => PostFlashExpectation::Application { bcd_device: "0458" },
            Self::PostInitHookProbe => PostFlashExpectation::Application { bcd_device: "0459" },
            Self::WiredLoopHookProbe => PostFlashExpectation::Application { bcd_device: "0460" },
            Self::ActiveLoopHookProbe => PostFlashExpectation::Application { bcd_device: "0461" },
            Self::SteadyLoopHookProbe => PostFlashExpectation::Application { bcd_device: "0462" },
            Self::DispatcherReturnHookProbe => {
                PostFlashExpectation::Application { bcd_device: "0463" }
            },
            Self::ExperimentDispatchGuard => {
                PostFlashExpectation::Application { bcd_device: "0464" }
            },
            Self::InputDiagnostics => PostFlashExpectation::Application { bcd_device: "0465" },
            Self::PagedInputDiagnostics => PostFlashExpectation::Application { bcd_device: "0466" },
            Self::SensorShadowDiagnostics => {
                PostFlashExpectation::Application { bcd_device: "0470" }
            },
            Self::UnsolicitedReportProbe => {
                PostFlashExpectation::Application { bcd_device: "0471" }
            },
            Self::CustomMainHandoffProbe => {
                PostFlashExpectation::Application { bcd_device: "0472" }
            },
            Self::CustomMainUsbRecoveryProbe => {
                PostFlashExpectation::Application { bcd_device: "0473" }
            },
            Self::CustomMainStreamTransportProbe => {
                PostFlashExpectation::Application { bcd_device: "0474" }
            },
            Self::CustomMainSensorStreamProbe => {
                PostFlashExpectation::Application { bcd_device: "0475" }
            },
        }
    }
}

#[must_use]
pub fn full_recovery_confirmation_matches(confirmation: &str) -> bool {
    confirmation == FULL_RECOVERY_CONFIRMATION
}

fn digest_matches_hex(digest: [u8; 32], confirmation: &str) -> bool {
    let bytes = confirmation.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    digest.into_iter().enumerate().all(|(index, byte)| {
        let offset = index * 2;
        bytes.get(offset).copied() == Some(hex_digit(byte >> 4_u8))
            && bytes.get(offset + 1).copied() == Some(hex_digit(byte & 0x0f))
    })
}

fn digest_to_hex(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(hex_digit(byte >> 4_u8)));
        output.push(char::from(hex_digit(byte & 0x0f)));
    }
    output
}

const fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_flash_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::RecoveryCarrier.confirmation_matches("wrong"));
    }

    #[test]
    fn reset_trampoline_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::ResetTrampoline.confirmation_matches("wrong"));
    }

    #[test]
    fn recovery_stub_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::RecoveryStub.confirmation_matches("wrong"));
    }

    #[test]
    fn startup_trampoline_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::StartupTrampoline.confirmation_matches("wrong"));
    }

    #[test]
    fn recovery_guard_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::RecoveryGuard.confirmation_matches("wrong"));
        assert!(FlashArtifact::RecoveryGuard.confirmation_matches(
            "7bb3055bc1575bcb9ca4eab9ba2a83a3dbaba131e92cca78fffb18397cc2d19a"
        ));
    }

    #[test]
    fn full_recovery_needs_exact_action_confirmation() {
        assert!(!full_recovery_confirmation_matches("wrong"));
        assert!(full_recovery_confirmation_matches("ERASE-MARKER-RESET"));
    }

    #[test]
    fn usb_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::UsbRecoveryProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::UsbRecoveryProbe.confirmation_matches(
            "3ce23e3b9af4a1e713bad622f56fc9055cb178ca1ec198c7556c1dee44169e5a"
        ));
    }

    #[test]
    fn stock_harness_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::StockHarness.confirmation_matches("wrong"));
        assert!(FlashArtifact::StockHarness.confirmation_matches(
            "cac3bab34545a2e20ad545af5b91c4a55db1c9cacfdcb0f45e4a348b65e3b356"
        ));
        assert_eq!(
            FlashArtifact::StockHarness.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0455" }
        );
    }

    #[test]
    fn late_marker_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::LateMarkerProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::LateMarkerProbe.confirmation_matches(
            "76669e150983725954fec510eb0c6717f84e08ef2a1a8ef3fb59cb49f7566905"
        ));
        assert_eq!(
            FlashArtifact::LateMarkerProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0456" }
        );
    }

    #[test]
    fn experiment_entry_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::ExperimentEntryProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::ExperimentEntryProbe.confirmation_matches(
            "bc3275a95a0ebd4f3c12863ed2607d5f9ce026903ef19f145e177834f1a988b3"
        ));
        assert_eq!(
            FlashArtifact::ExperimentEntryProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0457" }
        );
    }

    #[test]
    fn rust_response_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::RustResponseProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::RustResponseProbe.confirmation_matches(
            "93e939ffdf19a7d862108182528fac7d9b066e59fa853b21327bedd6260b14d4"
        ));
        assert_eq!(
            FlashArtifact::RustResponseProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0458" }
        );
    }

    #[test]
    fn post_init_hook_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::PostInitHookProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::PostInitHookProbe.confirmation_matches(
            "133f5241efecc23c7cc2fffcc0fdb34c37f5a3f840362938c27a2bc5353c1de1"
        ));
        assert_eq!(
            FlashArtifact::PostInitHookProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0459" }
        );
    }

    #[test]
    fn wired_loop_hook_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::WiredLoopHookProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::WiredLoopHookProbe.confirmation_matches(
            "61cf9ebc9b7739fbc586a6949a1dbca2f754f07b6e3e7ea16a4319c6d365bd87"
        ));
        assert_eq!(
            FlashArtifact::WiredLoopHookProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0460" }
        );
    }

    #[test]
    fn active_loop_hook_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::ActiveLoopHookProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::ActiveLoopHookProbe.confirmation_matches(
            "bf7aab32e3c32b4bf3853a7c79de21e5818961fbeb70239c95b40db7d898d077"
        ));
        assert_eq!(
            FlashArtifact::ActiveLoopHookProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0461" }
        );
    }

    #[test]
    fn steady_loop_hook_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::SteadyLoopHookProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::SteadyLoopHookProbe.confirmation_matches(
            "3defe9f5fda2ebaefb923fbe1c62fdd877345ccb75f6b1eec2604e731688d310"
        ));
        assert_eq!(
            FlashArtifact::SteadyLoopHookProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0462" }
        );
    }

    #[test]
    fn dispatcher_return_hook_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::DispatcherReturnHookProbe.confirmation_matches("wrong"));
        assert!(
            FlashArtifact::DispatcherReturnHookProbe.confirmation_matches(
                "e79d8a05f0ed65ae6f3059885e02899c1adbb10be3d320f30829d1e8623b2656"
            )
        );
        assert_eq!(
            FlashArtifact::DispatcherReturnHookProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0463" }
        );
    }

    #[test]
    fn experiment_dispatch_guard_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::ExperimentDispatchGuard.confirmation_matches("wrong"));
        assert!(FlashArtifact::ExperimentDispatchGuard.confirmation_matches(
            "dd720ba30fc05b9c401eb1f182f62bb217a57a03a3788ccc421806e06f30ac48"
        ));
        assert_eq!(
            FlashArtifact::ExperimentDispatchGuard.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0464" }
        );
    }

    #[test]
    fn unsolicited_report_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::UnsolicitedReportProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::UnsolicitedReportProbe.confirmation_matches(
            "342b8e7ed2891e9b495eaa6078bb738241a7dc49be67d61506d248ce4aafcf21"
        ));
        assert_eq!(
            FlashArtifact::UnsolicitedReportProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0471" }
        );
    }

    #[test]
    fn custom_main_handoff_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::CustomMainHandoffProbe.confirmation_matches("wrong"));
        assert!(FlashArtifact::CustomMainHandoffProbe.confirmation_matches(
            "401ab888a8512fa6ff74058fc78d329a3e4a34064614542ea3716d06be8dbf97"
        ));
        assert_eq!(
            FlashArtifact::CustomMainHandoffProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0472" }
        );
    }

    #[test]
    fn custom_main_usb_recovery_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::CustomMainUsbRecoveryProbe.confirmation_matches("wrong"));
        assert!(
            FlashArtifact::CustomMainUsbRecoveryProbe.confirmation_matches(
                "7c044eb8381b87ea3e383a114c066c569040b16c1becdfe079d4940a4392d7fa"
            )
        );
        assert_eq!(
            FlashArtifact::CustomMainUsbRecoveryProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0473" }
        );
    }

    #[test]
    fn custom_main_stream_transport_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::CustomMainStreamTransportProbe.confirmation_matches("wrong"));
        assert!(
            FlashArtifact::CustomMainStreamTransportProbe.confirmation_matches(
                "31c14d3a51a94ccc8f2d5337bae15b3755ee7665804d56416ac518d44decb489"
            )
        );
        assert_eq!(
            FlashArtifact::CustomMainStreamTransportProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0474" }
        );
    }

    #[test]
    fn custom_main_sensor_stream_probe_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::CustomMainSensorStreamProbe.confirmation_matches("wrong"));
        assert!(
            FlashArtifact::CustomMainSensorStreamProbe.confirmation_matches(
                "65c7dfd35d4f97751db74899c076c27741dd290d045fbd130aa854443b60edf8"
            )
        );
        assert_eq!(
            FlashArtifact::CustomMainSensorStreamProbe.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0475" }
        );
        assert!(
            FlashArtifact::CustomMainSensorStreamProbe
                .flash_refusal_reason()
                .is_some()
        );
        assert!(
            FlashArtifact::CustomMainStreamTransportProbe
                .flash_refusal_reason()
                .is_none()
        );
    }

    #[test]
    fn input_diagnostics_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::InputDiagnostics.confirmation_matches("wrong"));
        assert!(FlashArtifact::InputDiagnostics.confirmation_matches(
            "4a90ccf453b80cbbf4018dfec87d14051dfff3ea076445822c28dfbc3e4f55a3"
        ));
        assert_eq!(
            FlashArtifact::InputDiagnostics.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0465" }
        );
    }

    #[test]
    fn paged_input_diagnostics_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::PagedInputDiagnostics.confirmation_matches("wrong"));
        assert!(FlashArtifact::PagedInputDiagnostics.confirmation_matches(
            "c5fb2b865c6ba1993c673f989e5c811bfa661b31f8c6261d2ab04e95eab5692f"
        ));
        assert_eq!(
            FlashArtifact::PagedInputDiagnostics.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0466" }
        );
    }

    #[test]
    fn sensor_shadow_diagnostics_needs_exact_hash_confirmation() {
        assert!(!FlashArtifact::SensorShadowDiagnostics.confirmation_matches("wrong"));
        assert!(FlashArtifact::SensorShadowDiagnostics.confirmation_matches(
            "111f22eaf0db16bf2df2ba29187c9fbf151ca578385a5ad288c31b3f064657e4"
        ));
        assert_eq!(
            FlashArtifact::SensorShadowDiagnostics.post_flash_expectation(),
            PostFlashExpectation::Application { bcd_device: "0470" }
        );
    }

    #[test]
    #[allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "the fixed recorded response must parse for the assertion to be meaningful"
    )]
    fn input_snapshot_decodes_stock_report_fields() {
        let mut bytes = [
            0x08, 0x0f, 0x01, 0x00, 0xaa, 0xbb, 0x07, 0x15, 0x34, 0x12, 0xfe, 0xff, 0x61, 0x62,
            0x63, 0x64, 0x00,
        ];
        bytes[16] = slimblade_protocol::checksum(&bytes[..16]);
        let response = NormalReport::parse(&bytes).expect("recorded diagnostic response is valid");
        let snapshot = input_snapshot(response).expect("diagnostic response decodes");
        assert_eq!(snapshot.prefix, [0xaa, 0xbb]);
        assert_eq!(snapshot.sequence, 7);
        assert_eq!(snapshot.buttons, 0x15);
        assert_eq!(snapshot.motion_x, 0x1234);
        assert_eq!(snapshot.motion_y, -2);
        assert_eq!(
            [
                snapshot.report_6,
                snapshot.report_7,
                snapshot.report_8,
                snapshot.report_9,
            ],
            [0x61, 0x62, 0x63, 0x64]
        );
    }

    #[test]
    #[allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "the fixed recorded response must parse for the assertion to be meaningful"
    )]
    fn input_state_page_requires_matching_selector_and_copies_twelve_bytes() {
        let mut bytes = [
            0x08, 0x0f, 0x01, 0x06, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
            0x6a, 0x6b, 0x00,
        ];
        bytes[16] = slimblade_protocol::checksum(&bytes[..16]);
        let response = NormalReport::parse(&bytes).expect("recorded diagnostic response is valid");
        assert_eq!(
            input_state_page(response, 6),
            Some(InputStatePage {
                selector: 6,
                bytes: *b"`abcdefghijk",
            })
        );
        assert_eq!(input_state_page(response, 2), None);
    }

    #[test]
    #[allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "the fixed recorded response must parse for the assertion to be meaningful"
    )]
    fn sensor_shadow_decodes_four_signed_halfwords() {
        let mut bytes = [
            0x08, 0x0f, 0x01, 0x00, 0xfe, 0xff, 0x03, 0x00, 0xfc, 0xff, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        bytes[16] = slimblade_protocol::checksum(&bytes[..16]);
        let response = NormalReport::parse(&bytes).expect("recorded sensor response is valid");
        assert_eq!(
            sensor_shadow(response),
            Some(SensorShadow {
                sequence: 0,
                sensor_a_x: -2,
                sensor_a_y: 3,
                sensor_b_x: -4,
                sensor_b_y: 5,
            })
        );
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the tracker operations are expected to remain within fixed test bounds"
    )]
    fn sensor_tracker_counts_each_sequence_once_and_accepts_identical_deltas() {
        let mut tracker = SensorTracker::default();
        let initial = SensorShadow {
            sequence: 254,
            sensor_a_x: 1,
            sensor_a_y: -2,
            sensor_b_x: 3,
            sensor_b_y: -4,
        };
        let repeated_delta = SensorShadow {
            sequence: 255,
            ..initial
        };
        let wrapped_delta = SensorShadow {
            sequence: 0,
            ..initial
        };

        let first = tracker.observe(initial).expect("initial observation");
        let retained = tracker.observe(initial).expect("retained observation");
        let changed = tracker
            .observe(repeated_delta)
            .expect("changed observation");
        let wrapped = tracker.observe(wrapped_delta).expect("wrapped observation");

        assert_eq!(first.kind, SensorObservationKind::Initial);
        assert_eq!(retained.kind, SensorObservationKind::Retained);
        assert_eq!(changed.kind, SensorObservationKind::Changed);
        assert_eq!(changed.sequence_gap, 1);
        assert_eq!(wrapped.kind, SensorObservationKind::Changed);
        assert_eq!(wrapped.sequence_gap, 1);
        assert_eq!(tracker.polls(), 4);
        assert_eq!(tracker.changed_samples(), 2);
        assert_eq!(tracker.skipped_samples(), 0);
        assert_eq!(
            tracker.totals(),
            SensorTotals {
                sensor_a_x: 2,
                sensor_a_y: -4,
                sensor_b_x: 6,
                sensor_b_y: -8,
            }
        );
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the tracker operations are expected to remain within fixed test bounds"
    )]
    fn sensor_tracker_reports_skipped_sequences_and_rejects_torn_reads() {
        let mut tracker = SensorTracker::default();
        let initial = SensorShadow {
            sequence: 10,
            sensor_a_x: 1,
            sensor_a_y: 2,
            sensor_b_x: 3,
            sensor_b_y: 4,
        };
        tracker.observe(initial).expect("initial observation");
        let skipped = tracker
            .observe(SensorShadow {
                sequence: 13,
                sensor_a_x: -1,
                ..initial
            })
            .expect("observation after skipped sequences");
        assert_eq!(skipped.sequence_gap, 3);
        assert_eq!(skipped.skipped_samples, 2);
        assert_eq!(
            tracker.observe(SensorShadow {
                sensor_a_y: -2,
                ..skipped.sample
            }),
            Err(SensorTrackerError::InconsistentRetainedSample)
        );
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed recorded response must parse for the assertion to be meaningful"
    )]
    fn late_marker_response_requires_command_and_success_status() {
        let response = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x3e,
        ])
        .expect("recorded carrier response is valid");
        assert!(late_marker_response_is_success(response));
        assert!(!late_marker_response_is_success(NormalReport::command(
            0x0e
        )));
        assert!(!late_marker_response_is_success(NormalReport::command(
            0x0f
        )));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed recorded response must parse for the assertion to be meaningful"
    )]
    fn rust_response_requires_signature_and_success_status() {
        let response = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xe6,
        ])
        .expect("fixed Rust response is valid");
        assert!(rust_response_is_success(response));
        assert!(!rust_response_is_success(NormalReport::command(0x0e)));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed candidate responses must parse for the assertions to be meaningful"
    )]
    fn post_init_responses_require_exact_signatures() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x9b,
        ])
        .expect("fixed arm response is valid");
        let state = NormalReport::parse(&[
            0x08, 0x0f, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x3b,
        ])
        .expect("fixed state response is valid");
        assert!(post_init_arm_response_is_success(arm));
        assert_eq!(post_init_hook_state(state), Some(2));
        assert!(!post_init_arm_response_is_success(state));
        assert_eq!(post_init_hook_state(arm), None);
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed corrected response must parse for the assertion to be meaningful"
    )]
    fn wired_loop_response_requires_exact_signature() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x99,
        ])
        .expect("fixed corrected response is valid");
        assert!(wired_loop_arm_response_is_success(arm));
        assert!(!post_init_arm_response_is_success(arm));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed active-loop response must parse for the assertion to be meaningful"
    )]
    fn active_loop_response_requires_exact_signature() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x98,
        ])
        .expect("fixed active-loop response is valid");
        assert!(active_loop_arm_response_is_success(arm));
        assert!(!wired_loop_arm_response_is_success(arm));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed steady-loop response must parse for the assertion to be meaningful"
    )]
    fn steady_loop_response_requires_exact_signature() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x97,
        ])
        .expect("fixed steady-loop response is valid");
        assert!(steady_loop_arm_response_is_success(arm));
        assert!(!active_loop_arm_response_is_success(arm));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed dispatcher-return response must parse for the assertion to be meaningful"
    )]
    fn dispatcher_return_response_requires_exact_signature() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x96,
        ])
        .expect("fixed dispatcher-return response is valid");
        assert!(dispatcher_return_arm_response_is_success(arm));
        assert!(!steady_loop_arm_response_is_success(arm));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed experiment-dispatch response must parse for the assertion to be meaningful"
    )]
    fn experiment_dispatch_response_requires_exact_signature() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x95,
        ])
        .expect("fixed experiment-dispatch response is valid");
        assert!(experiment_dispatch_arm_response_is_success(arm));
        assert!(!dispatcher_return_arm_response_is_success(arm));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed sensor response must parse for the assertion to be meaningful"
    )]
    fn sensor_shadow_response_requires_exact_signature() {
        let arm = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x94,
        ])
        .expect("fixed sensor arm response is valid");
        assert!(sensor_shadow_arm_response_is_success(arm));
        assert!(!experiment_dispatch_arm_response_is_success(arm));
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "the fixed unsolicited-report response must parse for the assertion to be meaningful"
    )]
    fn unsolicited_report_response_requires_exact_signature() {
        let response = NormalReport::parse(&[
            0x08, 0x0e, 0x01, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x93,
        ])
        .expect("fixed unsolicited-report response is valid");
        assert!(unsolicited_report_probe_response_is_success(response));
        assert!(!sensor_shadow_arm_response_is_success(response));
    }
}
