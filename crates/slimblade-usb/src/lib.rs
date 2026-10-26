#![no_std]

use slimblade_protocol::{
    NORMAL_REPORT_LENGTH, NORMAL_SET_REPORT_SETUP, USB_SETUP_PACKET_LENGTH,
    is_loader_control_request,
};

pub mod descriptors;
pub mod endpoint;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    /// Parses one USB setup packet without assuming host endianness.
    ///
    /// # Errors
    ///
    /// Returns `WrongLength` unless exactly eight bytes were supplied.
    pub fn parse(bytes: &[u8]) -> Result<Self, SetupPacketError> {
        let Ok(
            [
                request_type,
                request,
                value_low,
                value_high,
                index_low,
                index_high,
                length_low,
                length_high,
            ],
        ) = <[u8; USB_SETUP_PACKET_LENGTH]>::try_from(bytes)
        else {
            return Err(SetupPacketError::WrongLength {
                actual: bytes.len(),
            });
        };

        Ok(Self {
            request_type,
            request,
            value: u16::from_le_bytes([value_low, value_high]),
            index: u16::from_le_bytes([index_low, index_high]),
            length: u16::from_le_bytes([length_low, length_high]),
        })
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; USB_SETUP_PACKET_LENGTH] {
        let [value_low, value_high] = self.value.to_le_bytes();
        let [index_low, index_high] = self.index.to_le_bytes();
        let [length_low, length_high] = self.length.to_le_bytes();
        [
            self.request_type,
            self.request,
            value_low,
            value_high,
            index_low,
            index_high,
            length_low,
            length_high,
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupPacketError {
    WrongLength { actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorKind {
    Device,
    Configuration,
    String,
    Hid,
    Report,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recipient {
    Device,
    Interface,
    Endpoint,
}

/// Supported setup requests for the minimal wired USB application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRequest {
    GetDescriptor {
        kind: DescriptorKind,
        descriptor_index: u8,
        /// Language ID for strings, interface number for HID/report descriptors.
        index: u16,
        requested_length: u16,
    },
    GetStatus {
        recipient: Recipient,
        index: u16,
    },
    SetAddress(u8),
    GetConfiguration,
    SetConfiguration(u8),
    GetInterface(u8),
    SetInterface(u8),
    GetIdle {
        interface: u8,
        report_id: u8,
    },
    SetIdle {
        interface: u8,
        report_id: u8,
        duration: u8,
    },
    GetProtocol(u8),
    SetProtocol {
        interface: u8,
        protocol: u8,
    },
    RecoveryOutputReport,
}

/// Classifies only the standard and HID requests needed by the minimal wired
/// application. Unsupported or malformed requests must be stalled by the
/// endpoint-zero driver.
#[must_use]
pub fn classify_control_request(setup: SetupPacket) -> Option<ControlRequest> {
    match (setup.request_type, setup.request) {
        (0x80 | 0x81, 0x06) => classify_descriptor_request(setup),
        (0x80, 0x00) if setup.value == 0 && setup.index == 0 && setup.length == 2 => {
            Some(ControlRequest::GetStatus {
                recipient: Recipient::Device,
                index: 0,
            })
        },
        (0x81, 0x00) if setup.value == 0 && setup.length == 2 => supported_interface(setup.index)
            .map(|interface| ControlRequest::GetStatus {
                recipient: Recipient::Interface,
                index: u16::from(interface),
            }),
        (0x82, 0x00) if setup.value == 0 && setup.length == 2 => Some(ControlRequest::GetStatus {
            recipient: Recipient::Endpoint,
            index: setup.index,
        }),
        (0x00, 0x05) if setup.index == 0 && setup.length == 0 && setup.value <= 0x7f => {
            u8::try_from(setup.value)
                .ok()
                .map(ControlRequest::SetAddress)
        },
        (0x80, 0x08) if setup.value == 0 && setup.index == 0 && setup.length == 1 => {
            Some(ControlRequest::GetConfiguration)
        },
        (0x00, 0x09) if setup.index == 0 && setup.length == 0 && setup.value <= 1 => {
            u8::try_from(setup.value)
                .ok()
                .map(ControlRequest::SetConfiguration)
        },
        (0x81, 0x0a) if setup.value == 0 && setup.length == 1 => {
            supported_interface(setup.index).map(ControlRequest::GetInterface)
        },
        (0x01, 0x0b) if setup.value == 0 && setup.length == 0 => {
            supported_interface(setup.index).map(ControlRequest::SetInterface)
        },
        (0xa1, 0x02) if setup.length == 1 => {
            let [report_id, reserved] = setup.value.to_le_bytes();
            (reserved == 0).then(|| {
                supported_interface(setup.index).map(|interface| ControlRequest::GetIdle {
                    interface,
                    report_id,
                })
            })?
        },
        (0x21, 0x0a) if setup.length == 0 => {
            let [report_id, duration] = setup.value.to_le_bytes();
            supported_interface(setup.index).map(|interface| ControlRequest::SetIdle {
                interface,
                report_id,
                duration,
            })
        },
        (0xa1, 0x03) if setup.value == 0 && setup.length == 1 => {
            supported_interface(setup.index).map(ControlRequest::GetProtocol)
        },
        (0x21, 0x0b) if setup.length == 0 && setup.value <= 1 => {
            let protocol = u8::try_from(setup.value).ok()?;
            supported_interface(setup.index).map(|interface| ControlRequest::SetProtocol {
                interface,
                protocol,
            })
        },
        (0x21, 0x09) if setup.to_bytes() == NORMAL_SET_REPORT_SETUP => {
            Some(ControlRequest::RecoveryOutputReport)
        },
        _ => None,
    }
}

const fn classify_descriptor_request(setup: SetupPacket) -> Option<ControlRequest> {
    let [descriptor_index, descriptor_type] = setup.value.to_le_bytes();
    let kind = match (
        setup.request_type,
        descriptor_type,
        descriptor_index,
        setup.index,
    ) {
        (0x80, 0x01, 0, 0) => DescriptorKind::Device,
        (0x80, 0x02, 0, 0) => DescriptorKind::Configuration,
        (0x80, 0x03, _, _) => DescriptorKind::String,
        (0x81, 0x21, 0, 0 | 1) => DescriptorKind::Hid,
        (0x81, 0x22, 0, 0 | 1) => DescriptorKind::Report,
        _ => return None,
    };
    Some(ControlRequest::GetDescriptor {
        kind,
        descriptor_index,
        index: setup.index,
        requested_length: setup.length,
    })
}

const fn supported_interface(index: u16) -> Option<u8> {
    match index {
        0 => Some(0),
        1 => Some(1),
        _ => None,
    }
}

/// The endpoint-zero phase currently expected by the recovery command path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecoveryStage {
    /// Waiting for a new setup packet.
    #[default]
    Setup,
    /// Waiting for the 17-byte HID output report.
    OutData,
    /// Waiting for the status packet to finish before entering the loader.
    StatusIn,
}

/// Action for the USB controller after receiving a setup packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupAction {
    ReceiveOut { length: usize },
    Stall,
}

/// Action for the USB controller after receiving an OUT data packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutAction {
    AcknowledgeStatus,
    Stall,
}

/// Firmware action after the control transfer's status stage completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionAction {
    None,
    EnterLoader,
}

/// Pure state machine for the normal-mode command that enters the resident loader.
///
/// This type deliberately has no MMIO access. The BK3635-specific endpoint-zero
/// driver must translate these actions into controller CSR writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryControl {
    stage: RecoveryStage,
}

impl RecoveryControl {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stage: RecoveryStage::Setup,
        }
    }

    #[must_use]
    pub const fn stage(self) -> RecoveryStage {
        self.stage
    }

    /// Handles a new setup packet. Any new setup packet cancels an incomplete
    /// recovery request before the packet itself is classified.
    pub fn handle_setup(&mut self, setup: &[u8]) -> SetupAction {
        self.stage = RecoveryStage::Setup;
        if setup == NORMAL_SET_REPORT_SETUP {
            self.stage = RecoveryStage::OutData;
            SetupAction::ReceiveOut {
                length: NORMAL_REPORT_LENGTH,
            }
        } else {
            SetupAction::Stall
        }
    }

    /// Validates the OUT data stage and arms loader entry only after a valid
    /// reset report has been acknowledged to the host.
    pub fn handle_out_data(&mut self, payload: &[u8]) -> OutAction {
        if self.stage == RecoveryStage::OutData
            && is_loader_control_request(&NORMAL_SET_REPORT_SETUP, payload)
        {
            self.stage = RecoveryStage::StatusIn;
            OutAction::AcknowledgeStatus
        } else {
            self.stage = RecoveryStage::Setup;
            OutAction::Stall
        }
    }

    /// Finishes the status stage. `EnterLoader` is returned at most once.
    pub fn complete_status(&mut self) -> CompletionAction {
        if self.stage == RecoveryStage::StatusIn {
            self.stage = RecoveryStage::Setup;
            CompletionAction::EnterLoader
        } else {
            CompletionAction::None
        }
    }

    /// Cancels every partially received command on a USB bus reset.
    pub const fn bus_reset(&mut self) {
        self.stage = RecoveryStage::Setup;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompletionAction, ControlRequest, DescriptorKind, OutAction, Recipient, RecoveryControl,
        RecoveryStage, SetupAction, SetupPacket, SetupPacketError, classify_control_request,
    };
    use slimblade_protocol::{NORMAL_REPORT_LENGTH, NORMAL_SET_REPORT_SETUP, NormalReport};

    #[test]
    fn setup_packet_round_trips_little_endian_fields() {
        let bytes = [0x81, 0x06, 0x00, 0x22, 0x01, 0x00, 0xaa, 0x00];
        let packet = SetupPacket::parse(&bytes);

        assert_eq!(
            packet,
            Ok(SetupPacket {
                request_type: 0x81,
                request: 0x06,
                value: 0x2200,
                index: 1,
                length: 170,
            })
        );
        assert_eq!(packet.map(SetupPacket::to_bytes), Ok(bytes));
    }

    #[test]
    fn setup_packet_requires_exact_length() {
        assert_eq!(
            SetupPacket::parse(&[0; 7]),
            Err(SetupPacketError::WrongLength { actual: 7 })
        );
        assert_eq!(
            SetupPacket::parse(&[0; 9]),
            Err(SetupPacketError::WrongLength { actual: 9 })
        );
    }

    #[test]
    fn stock_descriptor_requests_are_classified() {
        let device = SetupPacket::parse(&[0x80, 0x06, 0x00, 0x01, 0, 0, 64, 0]);
        let mouse_report = SetupPacket::parse(&[0x81, 0x06, 0, 0x22, 0, 0, 87, 0]);
        let vendor_report = SetupPacket::parse(&[0x81, 0x06, 0, 0x22, 1, 0, 170, 0]);

        assert_eq!(
            device.ok().and_then(classify_control_request),
            Some(ControlRequest::GetDescriptor {
                kind: DescriptorKind::Device,
                descriptor_index: 0,
                index: 0,
                requested_length: 64,
            })
        );
        assert_eq!(
            mouse_report.ok().and_then(classify_control_request),
            Some(ControlRequest::GetDescriptor {
                kind: DescriptorKind::Report,
                descriptor_index: 0,
                index: 0,
                requested_length: 87,
            })
        );
        assert_eq!(
            vendor_report.ok().and_then(classify_control_request),
            Some(ControlRequest::GetDescriptor {
                kind: DescriptorKind::Report,
                descriptor_index: 0,
                index: 1,
                requested_length: 170,
            })
        );
    }

    #[test]
    fn address_configuration_and_interface_requests_are_strict() {
        let set_address = SetupPacket::parse(&[0x00, 0x05, 42, 0, 0, 0, 0, 0]);
        let set_configuration = SetupPacket::parse(&[0x00, 0x09, 1, 0, 0, 0, 0, 0]);
        let get_interface = SetupPacket::parse(&[0x81, 0x0a, 0, 0, 1, 0, 1, 0]);
        let bad_address = SetupPacket::parse(&[0x00, 0x05, 128, 0, 0, 0, 0, 0]);

        assert_eq!(
            set_address.ok().and_then(classify_control_request),
            Some(ControlRequest::SetAddress(42))
        );
        assert_eq!(
            set_configuration.ok().and_then(classify_control_request),
            Some(ControlRequest::SetConfiguration(1))
        );
        assert_eq!(
            get_interface.ok().and_then(classify_control_request),
            Some(ControlRequest::GetInterface(1))
        );
        assert_eq!(bad_address.ok().and_then(classify_control_request), None);
    }

    #[test]
    fn status_and_hid_requests_are_classified() {
        let device_status = SetupPacket::parse(&[0x80, 0, 0, 0, 0, 0, 2, 0]);
        let set_idle = SetupPacket::parse(&[0x21, 0x0a, 8, 20, 1, 0, 0, 0]);
        let get_protocol = SetupPacket::parse(&[0xa1, 0x03, 0, 0, 0, 0, 1, 0]);

        assert_eq!(
            device_status.ok().and_then(classify_control_request),
            Some(ControlRequest::GetStatus {
                recipient: Recipient::Device,
                index: 0,
            })
        );
        assert_eq!(
            set_idle.ok().and_then(classify_control_request),
            Some(ControlRequest::SetIdle {
                interface: 1,
                report_id: 8,
                duration: 20,
            })
        );
        assert_eq!(
            get_protocol.ok().and_then(classify_control_request),
            Some(ControlRequest::GetProtocol(0))
        );
    }

    #[test]
    fn only_exact_recovery_setup_is_classified() {
        let exact = SetupPacket::parse(&NORMAL_SET_REPORT_SETUP);
        let wrong_interface = SetupPacket::parse(&[0x21, 0x09, 0x08, 0x02, 0, 0, 0x11, 0]);

        assert_eq!(
            exact.ok().and_then(classify_control_request),
            Some(ControlRequest::RecoveryOutputReport)
        );
        assert_eq!(
            wrong_interface.ok().and_then(classify_control_request),
            None
        );
    }

    #[test]
    fn exact_loader_transfer_enters_loader_after_status_completion() {
        let mut control = RecoveryControl::new();

        assert_eq!(
            control.handle_setup(&NORMAL_SET_REPORT_SETUP),
            SetupAction::ReceiveOut {
                length: NORMAL_REPORT_LENGTH
            }
        );
        assert_eq!(control.stage(), RecoveryStage::OutData);
        assert_eq!(
            control.handle_out_data(NormalReport::reset_to_loader().as_bytes()),
            OutAction::AcknowledgeStatus
        );
        assert_eq!(control.stage(), RecoveryStage::StatusIn);
        assert_eq!(control.complete_status(), CompletionAction::EnterLoader);
        assert_eq!(control.stage(), RecoveryStage::Setup);
        assert_eq!(control.complete_status(), CompletionAction::None);
    }

    #[test]
    fn wrong_setup_packet_never_arms_recovery() {
        let mut control = RecoveryControl::new();
        let setup = [0_u8; 8];

        assert_eq!(control.handle_setup(&setup), SetupAction::Stall);
        assert_eq!(control.stage(), RecoveryStage::Setup);
        assert_eq!(
            control.handle_out_data(NormalReport::reset_to_loader().as_bytes()),
            OutAction::Stall
        );
        assert_eq!(control.complete_status(), CompletionAction::None);
    }

    #[test]
    fn other_valid_command_is_rejected() {
        let mut control = RecoveryControl::new();
        assert_eq!(
            control.handle_setup(&NORMAL_SET_REPORT_SETUP),
            SetupAction::ReceiveOut {
                length: NORMAL_REPORT_LENGTH
            }
        );

        assert_eq!(
            control.handle_out_data(NormalReport::command(0x0e).as_bytes()),
            OutAction::Stall
        );
        assert_eq!(control.complete_status(), CompletionAction::None);
    }

    #[test]
    fn truncated_report_is_rejected() {
        let mut control = RecoveryControl::new();
        let _ = control.handle_setup(&NORMAL_SET_REPORT_SETUP);

        assert_eq!(control.handle_out_data(&[0x08, 0x0d]), OutAction::Stall);
        assert_eq!(control.complete_status(), CompletionAction::None);
    }

    #[test]
    fn new_setup_packet_cancels_an_armed_loader_entry() {
        let mut control = RecoveryControl::new();
        let _ = control.handle_setup(&NORMAL_SET_REPORT_SETUP);
        assert_eq!(
            control.handle_out_data(NormalReport::reset_to_loader().as_bytes()),
            OutAction::AcknowledgeStatus
        );

        assert_eq!(control.handle_setup(&[0_u8; 8]), SetupAction::Stall);
        assert_eq!(control.complete_status(), CompletionAction::None);
    }

    #[test]
    fn bus_reset_cancels_every_partial_stage() {
        let mut receiving = RecoveryControl::new();
        let _ = receiving.handle_setup(&NORMAL_SET_REPORT_SETUP);
        receiving.bus_reset();
        assert_eq!(receiving.stage(), RecoveryStage::Setup);

        let mut armed = RecoveryControl::new();
        let _ = armed.handle_setup(&NORMAL_SET_REPORT_SETUP);
        let _ = armed.handle_out_data(NormalReport::reset_to_loader().as_bytes());
        armed.bus_reset();
        assert_eq!(armed.complete_status(), CompletionAction::None);
    }
}
