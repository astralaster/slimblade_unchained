use crate::{
    ControlRequest, DescriptorKind, SetupPacket, classify_control_request,
    descriptors::DescriptorSet,
};
use slimblade_protocol::NORMAL_SET_REPORT_SETUP;

use super::{CompletionAction, OutAction, RecoveryControl, SetupAction};

pub const MAX_PACKET_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InPacket {
    source: InSource,
    offset: usize,
    length: u8,
    pub final_packet: bool,
}

impl InPacket {
    #[must_use]
    pub const fn length(self) -> u8 {
        self.length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointResponse {
    None,
    SendData(InPacket),
    ReceiveOut { length: usize },
    SendStatus,
    Stall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAction {
    None,
    SetAddress(u8),
    SetConfiguration(u8),
    EnterLoader,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InSource {
    Descriptor {
        kind: DescriptorKind,
        descriptor_index: u8,
        index: u16,
    },
    Inline {
        bytes: [u8; 2],
        length: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InTransfer {
    source: InSource,
    offset: usize,
    total: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingCompletion {
    None,
    Address(u8),
    Configuration(u8),
    MouseIdle(u8),
    VendorIdle(u8),
    MouseProtocol(u8),
    VendorProtocol(u8),
    Loader,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Stage {
    #[default]
    Setup,
    DataIn(InTransfer),
    StatusOut,
    RecoveryOut,
    StatusIn(PendingCompletion),
}

/// Pure endpoint-zero transfer engine for the minimal wired application.
///
/// Register access and CSR ordering remain outside this type. Every method is
/// deterministic and host-testable.
#[derive(Debug)]
pub struct ControlEndpoint {
    descriptors: DescriptorSet,
    recovery: RecoveryControl,
    stage: Stage,
    configuration: u8,
    mouse_idle: u8,
    vendor_idle: u8,
    mouse_protocol: u8,
    vendor_protocol: u8,
}

impl ControlEndpoint {
    #[must_use]
    pub const fn new(release_bcd: u16) -> Self {
        Self {
            descriptors: DescriptorSet::new(release_bcd),
            recovery: RecoveryControl::new(),
            stage: Stage::Setup,
            configuration: 0,
            mouse_idle: 0,
            vendor_idle: 0,
            mouse_protocol: 1,
            vendor_protocol: 1,
        }
    }

    #[must_use]
    pub const fn expects_out_data(&self) -> bool {
        matches!(self.stage, Stage::RecoveryOut)
    }

    #[must_use]
    pub const fn has_pending_in_data(&self) -> bool {
        matches!(self.stage, Stage::DataIn(_))
    }

    #[must_use]
    pub const fn awaits_status_completion(&self) -> bool {
        matches!(self.stage, Stage::StatusOut | Stage::StatusIn(_))
    }

    pub fn handle_setup(&mut self, bytes: &[u8]) -> EndpointResponse {
        self.cancel_transfer();
        let Ok(setup) = SetupPacket::parse(bytes) else {
            return EndpointResponse::Stall;
        };
        let Some(request) = classify_control_request(setup) else {
            return EndpointResponse::Stall;
        };

        match request {
            ControlRequest::GetDescriptor {
                kind,
                descriptor_index,
                index,
                requested_length,
            } => self.begin_descriptor(kind, descriptor_index, index, requested_length),
            ControlRequest::GetStatus { .. } => self.begin_inline([0, 0], 2, setup.length),
            ControlRequest::SetAddress(address) => {
                self.begin_status(PendingCompletion::Address(address))
            },
            ControlRequest::GetConfiguration => {
                self.begin_inline([self.configuration, 0], 1, setup.length)
            },
            ControlRequest::SetConfiguration(configuration) => {
                self.begin_status(PendingCompletion::Configuration(configuration))
            },
            ControlRequest::GetInterface(_) => self.begin_inline([0, 0], 1, setup.length),
            ControlRequest::SetInterface(_) => self.begin_status(PendingCompletion::None),
            ControlRequest::GetIdle { interface, .. } => {
                self.begin_inline([self.idle(interface), 0], 1, setup.length)
            },
            ControlRequest::SetIdle {
                interface,
                duration,
                ..
            } => self.begin_status(match interface {
                0 => PendingCompletion::MouseIdle(duration),
                _ => PendingCompletion::VendorIdle(duration),
            }),
            ControlRequest::GetProtocol(interface) => {
                self.begin_inline([self.protocol(interface), 0], 1, setup.length)
            },
            ControlRequest::SetProtocol {
                interface,
                protocol,
            } => self.begin_status(match interface {
                0 => PendingCompletion::MouseProtocol(protocol),
                _ => PendingCompletion::VendorProtocol(protocol),
            }),
            ControlRequest::RecoveryOutputReport => {
                if self.recovery.handle_setup(&NORMAL_SET_REPORT_SETUP)
                    == (SetupAction::ReceiveOut { length: 17 })
                {
                    self.stage = Stage::RecoveryOut;
                    EndpointResponse::ReceiveOut { length: 17 }
                } else {
                    EndpointResponse::Stall
                }
            },
        }
    }

    pub fn handle_out_data(&mut self, payload: &[u8]) -> EndpointResponse {
        if self.stage == Stage::RecoveryOut
            && self.recovery.handle_out_data(payload) == OutAction::AcknowledgeStatus
        {
            self.stage = Stage::StatusIn(PendingCompletion::Loader);
            EndpointResponse::SendStatus
        } else {
            self.cancel_transfer();
            EndpointResponse::Stall
        }
    }

    pub fn next_in_packet(&mut self) -> EndpointResponse {
        let Stage::DataIn(transfer) = self.stage else {
            return EndpointResponse::None;
        };
        self.packet_for(transfer)
    }

    /// Reads one byte from a packet previously returned by this endpoint.
    #[must_use]
    pub fn packet_byte(&self, packet: InPacket, index: u8) -> Option<u8> {
        if index >= packet.length {
            return None;
        }
        let absolute = packet.offset.checked_add(usize::from(index))?;
        match packet.source {
            InSource::Descriptor {
                kind,
                descriptor_index,
                index,
            } => self
                .descriptors
                .get(kind, descriptor_index, index)?
                .get(absolute)
                .copied(),
            InSource::Inline { bytes, length } => {
                if absolute >= usize::from(length) {
                    None
                } else {
                    bytes.get(absolute).copied()
                }
            },
        }
    }

    pub fn complete_status(&mut self) -> DeviceAction {
        let stage = self.stage;
        self.stage = Stage::Setup;
        match stage {
            Stage::StatusIn(PendingCompletion::Address(address)) => {
                DeviceAction::SetAddress(address)
            },
            Stage::StatusIn(PendingCompletion::Configuration(configuration)) => {
                self.configuration = configuration;
                DeviceAction::SetConfiguration(configuration)
            },
            Stage::StatusIn(PendingCompletion::MouseIdle(duration)) => {
                self.mouse_idle = duration;
                DeviceAction::None
            },
            Stage::StatusIn(PendingCompletion::VendorIdle(duration)) => {
                self.vendor_idle = duration;
                DeviceAction::None
            },
            Stage::StatusIn(PendingCompletion::MouseProtocol(protocol)) => {
                self.mouse_protocol = protocol;
                DeviceAction::None
            },
            Stage::StatusIn(PendingCompletion::VendorProtocol(protocol)) => {
                self.vendor_protocol = protocol;
                DeviceAction::None
            },
            Stage::StatusIn(PendingCompletion::Loader) => {
                if self.recovery.complete_status() == CompletionAction::EnterLoader {
                    DeviceAction::EnterLoader
                } else {
                    DeviceAction::None
                }
            },
            Stage::Setup
            | Stage::DataIn(_)
            | Stage::StatusOut
            | Stage::RecoveryOut
            | Stage::StatusIn(PendingCompletion::None) => DeviceAction::None,
        }
    }

    pub const fn bus_reset(&mut self) {
        self.recovery.bus_reset();
        self.stage = Stage::Setup;
        self.configuration = 0;
        self.mouse_idle = 0;
        self.vendor_idle = 0;
        self.mouse_protocol = 1;
        self.vendor_protocol = 1;
    }

    /// Cancels the active transfer without changing configured device state.
    pub const fn abort_transfer(&mut self) {
        self.cancel_transfer();
    }

    fn begin_descriptor(
        &mut self,
        kind: DescriptorKind,
        descriptor_index: u8,
        index: u16,
        requested_length: u16,
    ) -> EndpointResponse {
        let Some(bytes) = self.descriptors.get(kind, descriptor_index, index) else {
            return EndpointResponse::Stall;
        };
        let source = InSource::Descriptor {
            kind,
            descriptor_index,
            index,
        };
        let total = bytes.len().min(usize::from(requested_length));
        self.packet_for(InTransfer {
            source,
            offset: 0,
            total,
        })
    }

    fn begin_inline(
        &mut self,
        bytes: [u8; 2],
        length: u8,
        requested_length: u16,
    ) -> EndpointResponse {
        let total = usize::from(length).min(usize::from(requested_length));
        self.packet_for(InTransfer {
            source: InSource::Inline { bytes, length },
            offset: 0,
            total,
        })
    }

    const fn begin_status(&mut self, completion: PendingCompletion) -> EndpointResponse {
        self.stage = Stage::StatusIn(completion);
        EndpointResponse::SendStatus
    }

    fn packet_for(&mut self, transfer: InTransfer) -> EndpointResponse {
        let source_length = match transfer.source {
            InSource::Descriptor {
                kind,
                descriptor_index,
                index,
            } => {
                let Some(source) = self.descriptors.get(kind, descriptor_index, index) else {
                    self.cancel_transfer();
                    return EndpointResponse::Stall;
                };
                source.len()
            },
            InSource::Inline { length, .. } => usize::from(length),
        };
        if transfer.offset > transfer.total || transfer.total > source_length {
            self.cancel_transfer();
            return EndpointResponse::Stall;
        }
        let remaining = transfer.total - transfer.offset;
        let packet_length = remaining.min(MAX_PACKET_LENGTH);
        let end = transfer.offset + packet_length;
        let Ok(length) = u8::try_from(packet_length) else {
            self.cancel_transfer();
            return EndpointResponse::Stall;
        };
        let final_packet = end == transfer.total;
        self.stage = if final_packet {
            Stage::StatusOut
        } else {
            Stage::DataIn(InTransfer {
                offset: end,
                ..transfer
            })
        };
        EndpointResponse::SendData(InPacket {
            source: transfer.source,
            offset: transfer.offset,
            length,
            final_packet,
        })
    }

    const fn idle(&self, interface: u8) -> u8 {
        match interface {
            0 => self.mouse_idle,
            _ => self.vendor_idle,
        }
    }

    const fn protocol(&self, interface: u8) -> u8 {
        match interface {
            0 => self.mouse_protocol,
            _ => self.vendor_protocol,
        }
    }

    const fn cancel_transfer(&mut self) {
        self.recovery.bus_reset();
        self.stage = Stage::Setup;
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests compare checked packet ranges and panic only when a required response variant is absent"
)]
mod tests {
    extern crate alloc;

    use super::{ControlEndpoint, DeviceAction, EndpointResponse};
    use crate::descriptors::VENDOR_REPORT_DESCRIPTOR;
    use alloc::vec::Vec;
    use slimblade_protocol::{NORMAL_SET_REPORT_SETUP, NormalReport};

    fn packet_bytes(endpoint: &ControlEndpoint, packet: super::InPacket) -> Vec<u8> {
        (0..packet.length())
            .filter_map(|index| endpoint.packet_byte(packet, index))
            .collect()
    }

    #[test]
    fn vendor_descriptor_is_packetized_as_64_64_42() {
        let mut endpoint = ControlEndpoint::new(0x0454);
        let setup = [0x81, 0x06, 0x00, 0x22, 0x01, 0x00, 0xaa, 0x00];

        let EndpointResponse::SendData(first) = endpoint.handle_setup(&setup) else {
            panic!("expected first descriptor packet");
        };
        assert_eq!(first.length(), 64);
        assert!(!first.final_packet);
        assert_eq!(
            packet_bytes(&endpoint, first),
            VENDOR_REPORT_DESCRIPTOR[..64]
        );

        let EndpointResponse::SendData(second) = endpoint.next_in_packet() else {
            panic!("expected second descriptor packet");
        };
        assert_eq!(second.length(), 64);
        assert!(!second.final_packet);
        assert_eq!(
            packet_bytes(&endpoint, second),
            VENDOR_REPORT_DESCRIPTOR[64..128]
        );

        let EndpointResponse::SendData(third) = endpoint.next_in_packet() else {
            panic!("expected final descriptor packet");
        };
        assert_eq!(third.length(), 42);
        assert!(third.final_packet);
        assert_eq!(
            packet_bytes(&endpoint, third),
            VENDOR_REPORT_DESCRIPTOR[128..]
        );
        assert!(endpoint.awaits_status_completion());
        assert_eq!(endpoint.complete_status(), DeviceAction::None);
    }

    #[test]
    fn address_is_deferred_until_status_completion() {
        let mut endpoint = ControlEndpoint::new(0x0454);
        let set_address = [0x00, 0x05, 42, 0, 0, 0, 0, 0];

        assert_eq!(
            endpoint.handle_setup(&set_address),
            EndpointResponse::SendStatus
        );
        assert_eq!(endpoint.complete_status(), DeviceAction::SetAddress(42));
        assert_eq!(endpoint.complete_status(), DeviceAction::None);
    }

    #[test]
    fn configuration_state_changes_only_after_status_completion() {
        let mut endpoint = ControlEndpoint::new(0x0454);
        let set_configuration = [0x00, 0x09, 1, 0, 0, 0, 0, 0];
        let get_configuration = [0x80, 0x08, 0, 0, 0, 0, 1, 0];

        assert_eq!(
            endpoint.handle_setup(&set_configuration),
            EndpointResponse::SendStatus
        );
        assert_eq!(
            endpoint.complete_status(),
            DeviceAction::SetConfiguration(1)
        );
        let EndpointResponse::SendData(packet) = endpoint.handle_setup(&get_configuration) else {
            panic!("expected configuration byte");
        };
        assert_eq!(packet_bytes(&endpoint, packet), [1]);
    }

    #[test]
    fn loader_action_is_deferred_until_status_completion() {
        let mut endpoint = ControlEndpoint::new(0x0454);

        assert_eq!(
            endpoint.handle_setup(&NORMAL_SET_REPORT_SETUP),
            EndpointResponse::ReceiveOut { length: 17 }
        );
        assert_eq!(
            endpoint.handle_out_data(NormalReport::reset_to_loader().as_bytes()),
            EndpointResponse::SendStatus
        );
        assert!(endpoint.awaits_status_completion());
        assert_eq!(endpoint.complete_status(), DeviceAction::EnterLoader);
        assert_eq!(endpoint.complete_status(), DeviceAction::None);
    }

    #[test]
    fn bus_reset_cancels_loader_action_and_device_state() {
        let mut endpoint = ControlEndpoint::new(0x0454);
        let _ = endpoint.handle_setup(&NORMAL_SET_REPORT_SETUP);
        let _ = endpoint.handle_out_data(NormalReport::reset_to_loader().as_bytes());

        endpoint.bus_reset();
        assert_eq!(endpoint.complete_status(), DeviceAction::None);
    }

    #[test]
    fn malformed_or_unsupported_setup_stalls() {
        let mut endpoint = ControlEndpoint::new(0x0454);

        assert_eq!(endpoint.handle_setup(&[0; 7]), EndpointResponse::Stall);
        assert_eq!(endpoint.handle_setup(&[0; 8]), EndpointResponse::Stall);
        assert_eq!(
            endpoint.handle_setup(&[0x81, 0x06, 0, 0x22, 2, 0, 64, 0]),
            EndpointResponse::Stall
        );
    }
}
