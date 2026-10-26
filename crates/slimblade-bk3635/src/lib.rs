#![no_std]

use core::{arch::asm, ptr};
use slimblade_usb::endpoint::{ControlEndpoint, DeviceAction, EndpointResponse, MAX_PACKET_LENGTH};

pub const SYSTEM_BASE: usize = 0x0080_0000;
pub const USB_BASE: usize = 0x0080_4000;

const USB_PLATFORM_BASE: usize = 0x0080_6500;
const PLATFORM_CONTROL_ZERO_SET: u32 = 0x0000_4040;
const PLATFORM_CONTROL_ZERO_CLEAR: u32 = 0x4040_0000;
const PLATFORM_CONTROL_ONE_SET: u32 = 1 << 22;
const USB_CLOCK_DISABLE: u32 = 0x01;
const USB_CLOCK_SECONDARY_DISABLE: u32 = 0x80;
const USB_MODULE_ENABLE: u32 = 1 << 11;
const GLOBAL_IRQ_FIQ_ENABLE: u32 = 0x03;
const STOCK_DELAY_ITERATIONS: u16 = 499;
const RESET_INTERRUPT: u8 = 0x04;
const ENDPOINT_ZERO_INTERRUPT: u8 = 0x01;
const CSR_RX_PACKET_READY: u8 = 0x01;
const CSR_TX_PACKET_READY: u8 = 0x02;
const CSR_SENT_STALL: u8 = 0x04;
const CSR_DATA_END: u8 = 0x08;
const CSR_SETUP_END: u8 = 0x10;
const CSR_SEND_STALL: u8 = 0x20;
const CSR_SERVICE_RX_PACKET_READY: u8 = 0x40;
const CSR_SERVICE_SETUP_END: u8 = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemRegister {
    UsbPlatformControlZero,
    UsbPlatformControlOne,
    UsbClockControl,
    ModuleEnable,
    GlobalInterruptEnable,
}

impl SystemRegister {
    #[must_use]
    pub const fn address(self) -> usize {
        match self {
            Self::UsbPlatformControlZero => USB_PLATFORM_BASE + 0x20,
            Self::UsbPlatformControlOne => USB_PLATFORM_BASE + 0x24,
            Self::UsbClockControl => SYSTEM_BASE + 0x20,
            Self::ModuleEnable => SYSTEM_BASE + 0x40,
            Self::GlobalInterruptEnable => SYSTEM_BASE + 0x44,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbRegister {
    FunctionAddress,
    Power,
    InterruptTxLow,
    InterruptTxHigh,
    InterruptRxLow,
    InterruptRxHigh,
    InterruptUsb,
    InterruptTxEnableLow,
    InterruptTxEnableHigh,
    InterruptRxEnableLow,
    InterruptRxEnableHigh,
    InterruptUsbEnable,
    Index,
    DeviceControl,
    ControlStatusZero,
    ControlStatusZeroHigh,
    CountZero,
    FifoZero,
    OtgConfiguration,
    DmaEndpoint,
    VoltageThreshold,
    GeneralControl,
    AhbInterrupt,
    DeviceConfiguration,
}

impl UsbRegister {
    #[must_use]
    pub const fn address(self) -> usize {
        match self {
            Self::FunctionAddress => USB_BASE,
            Self::Power => USB_BASE + 0x01,
            Self::InterruptTxLow => USB_BASE + 0x02,
            Self::InterruptTxHigh => USB_BASE + 0x03,
            Self::InterruptRxLow => USB_BASE + 0x04,
            Self::InterruptRxHigh => USB_BASE + 0x05,
            Self::InterruptUsb => USB_BASE + 0x06,
            Self::InterruptTxEnableLow => USB_BASE + 0x07,
            Self::InterruptTxEnableHigh => USB_BASE + 0x08,
            Self::InterruptRxEnableLow => USB_BASE + 0x09,
            Self::InterruptRxEnableHigh => USB_BASE + 0x0a,
            Self::InterruptUsbEnable => USB_BASE + 0x0b,
            Self::Index => USB_BASE + 0x0e,
            Self::DeviceControl => USB_BASE + 0x0f,
            Self::ControlStatusZero => USB_BASE + 0x11,
            Self::ControlStatusZeroHigh => USB_BASE + 0x12,
            Self::CountZero => USB_BASE + 0x16,
            Self::FifoZero => USB_BASE + 0x20,
            Self::OtgConfiguration => USB_BASE + 0x80,
            Self::DmaEndpoint => USB_BASE + 0x84,
            Self::VoltageThreshold => USB_BASE + 0x88,
            Self::GeneralControl => USB_BASE + 0x8c,
            Self::AhbInterrupt => USB_BASE + 0x94,
            Self::DeviceConfiguration => USB_BASE + 0x9c,
        }
    }
}

/// Narrow register interface used by the wired USB driver.
///
/// No storage-controller address is representable through this trait.
pub trait RegisterIo {
    fn read_system(&mut self, register: SystemRegister) -> u32;
    fn write_system(&mut self, register: SystemRegister, value: u32);
    fn read_usb(&mut self, register: UsbRegister) -> u8;
    fn write_usb(&mut self, register: UsbRegister, value: u8);
    fn delay_cycles(&mut self, cycles: u16);
}

/// Direct volatile register access for the BK3635.
///
/// The constructor is unsafe; all subsequent accesses remain constrained to
/// the typed system/USB registers above.
#[derive(Debug)]
pub struct Mmio {
    _private: (),
}

#[allow(
    unsafe_code,
    reason = "the reviewed constructor establishes the BK3635 MMIO safety invariant"
)]
impl Mmio {
    /// Creates the unique live hardware register backend.
    ///
    /// # Safety
    ///
    /// The caller must run on a BK3635, guarantee that the listed addresses are
    /// valid, and ensure no other code accesses these registers concurrently.
    #[must_use]
    pub const unsafe fn claim() -> Self {
        Self { _private: () }
    }
}

#[allow(
    unsafe_code,
    reason = "volatile access is isolated to the reviewed typed MMIO backend"
)]
impl RegisterIo for Mmio {
    fn read_system(&mut self, register: SystemRegister) -> u32 {
        let address = ptr::with_exposed_provenance::<u32>(register.address());
        // SAFETY: `Mmio::claim` requires valid BK3635 addresses and exclusive access.
        unsafe { ptr::read_volatile(address) }
    }

    fn write_system(&mut self, register: SystemRegister, value: u32) {
        let address = ptr::with_exposed_provenance_mut::<u32>(register.address());
        // SAFETY: `Mmio::claim` requires valid BK3635 addresses and exclusive access.
        unsafe { ptr::write_volatile(address, value) };
    }

    fn read_usb(&mut self, register: UsbRegister) -> u8 {
        let address = ptr::with_exposed_provenance::<u8>(register.address());
        // SAFETY: `Mmio::claim` requires valid BK3635 addresses and exclusive access.
        unsafe { ptr::read_volatile(address) }
    }

    fn write_usb(&mut self, register: UsbRegister, value: u8) {
        let address = ptr::with_exposed_provenance_mut::<u8>(register.address());
        // SAFETY: `Mmio::claim` requires valid BK3635 addresses and exclusive access.
        unsafe { ptr::write_volatile(address, value) };
    }

    fn delay_cycles(&mut self, mut cycles: u16) {
        while cycles != 0 {
            // SAFETY: empty volatile assembly has no hardware effect; it prevents removal of
            // the timing loop on targets where `spin_loop` is only a compiler hint.
            unsafe { asm!("", options(nomem, nostack, preserves_flags)) };
            cycles = cycles.wrapping_sub(1);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptSnapshot {
    pub usb: u8,
    pub tx: u16,
    pub rx: u16,
}

impl InterruptSnapshot {
    #[must_use]
    pub const fn bus_reset(self) -> bool {
        self.usb & RESET_INTERRUPT != 0
    }

    #[must_use]
    pub const fn endpoint_zero(self) -> bool {
        self.tx.to_le_bytes()[0] & ENDPOINT_ZERO_INTERRUPT != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointZeroSnapshot {
    pub control_status: u8,
    pub byte_count: u8,
}

/// BK3635 USB device-mode controller using a polling interrupt snapshot.
#[derive(Debug)]
pub struct UsbController<R> {
    registers: R,
}

impl<R: RegisterIo> UsbController<R> {
    #[must_use]
    pub const fn new(registers: R) -> Self {
        Self { registers }
    }

    /// Replays Kensington's v4.48/v4.49 BK3635 USB-device initialization.
    ///
    /// The CPU remains in the marker guard's interrupt-masked state, so the
    /// controller is serviced by polling despite the stock module-enable writes.
    pub fn initialize_polling(&mut self) {
        let platform_zero = self
            .registers
            .read_system(SystemRegister::UsbPlatformControlZero);
        self.registers.write_system(
            SystemRegister::UsbPlatformControlZero,
            platform_zero | PLATFORM_CONTROL_ZERO_SET,
        );
        let platform_one = self
            .registers
            .read_system(SystemRegister::UsbPlatformControlOne);
        self.registers.write_system(
            SystemRegister::UsbPlatformControlOne,
            platform_one | PLATFORM_CONTROL_ONE_SET,
        );
        let platform_zero = self
            .registers
            .read_system(SystemRegister::UsbPlatformControlZero);
        self.registers.write_system(
            SystemRegister::UsbPlatformControlZero,
            platform_zero & !PLATFORM_CONTROL_ZERO_CLEAR,
        );

        let clock = self.registers.read_system(SystemRegister::UsbClockControl);
        self.registers
            .write_system(SystemRegister::UsbClockControl, clock & !USB_CLOCK_DISABLE);
        let clock = self.registers.read_system(SystemRegister::UsbClockControl);
        self.registers.write_system(
            SystemRegister::UsbClockControl,
            clock & !USB_CLOCK_SECONDARY_DISABLE,
        );

        self.registers
            .write_usb(UsbRegister::InterruptRxEnableLow, 0);
        self.registers
            .write_usb(UsbRegister::InterruptRxEnableHigh, 0);
        self.registers
            .write_usb(UsbRegister::InterruptTxEnableLow, 0);
        self.registers
            .write_usb(UsbRegister::InterruptTxEnableHigh, 0);
        self.registers.write_usb(UsbRegister::InterruptUsbEnable, 0);

        let threshold = self.registers.read_usb(UsbRegister::VoltageThreshold);
        self.registers
            .write_usb(UsbRegister::VoltageThreshold, threshold & !0x80);
        self.registers
            .write_usb(UsbRegister::InterruptRxEnableLow, 0x07);
        self.registers
            .write_usb(UsbRegister::InterruptRxEnableHigh, 0);
        self.registers
            .write_usb(UsbRegister::InterruptTxEnableLow, 0x07);
        self.registers
            .write_usb(UsbRegister::InterruptTxEnableHigh, 0);
        self.registers
            .write_usb(UsbRegister::InterruptUsbEnable, 0x3f);
        self.registers.write_usb(UsbRegister::OtgConfiguration, 0);
        self.registers.write_usb(UsbRegister::DmaEndpoint, 0);
        self.registers
            .write_usb(UsbRegister::DeviceConfiguration, 0xf4);
        let otg = self.registers.read_usb(UsbRegister::OtgConfiguration);
        self.registers
            .write_usb(UsbRegister::OtgConfiguration, otg | 0x01);

        self.registers.delay_cycles(STOCK_DELAY_ITERATIONS);
        let interrupt = self.registers.read_usb(UsbRegister::AhbInterrupt);
        self.registers.delay_cycles(STOCK_DELAY_ITERATIONS);
        self.registers
            .write_usb(UsbRegister::AhbInterrupt, interrupt);
        self.registers.delay_cycles(STOCK_DELAY_ITERATIONS);

        self.registers.write_usb(UsbRegister::GeneralControl, 0x77);
        self.registers.write_usb(UsbRegister::FunctionAddress, 0);
        self.registers.write_usb(UsbRegister::DeviceControl, 1);

        let modules = self.registers.read_system(SystemRegister::ModuleEnable);
        self.registers
            .write_system(SystemRegister::ModuleEnable, modules | USB_MODULE_ENABLE);
        let global = self
            .registers
            .read_system(SystemRegister::GlobalInterruptEnable);
        self.registers.write_system(
            SystemRegister::GlobalInterruptEnable,
            global | GLOBAL_IRQ_FIQ_ENABLE,
        );

        let otg = self.registers.read_usb(UsbRegister::OtgConfiguration);
        self.registers
            .write_usb(UsbRegister::OtgConfiguration, otg | 0x08);
        let power = self.registers.read_usb(UsbRegister::Power);
        self.registers.write_usb(UsbRegister::Power, power | 0x01);
    }

    /// Reads the same interrupt registers as the stock USB service routine.
    /// These status registers may clear on read, so every field is captured once.
    pub fn poll_interrupts(&mut self) -> InterruptSnapshot {
        let usb = self.registers.read_usb(UsbRegister::InterruptUsb) & !0xc0;
        let tx_low = self.registers.read_usb(UsbRegister::InterruptTxLow);
        let tx_high = self.registers.read_usb(UsbRegister::InterruptTxHigh);
        let rx_low = self.registers.read_usb(UsbRegister::InterruptRxLow);
        let rx_high = self.registers.read_usb(UsbRegister::InterruptRxHigh);
        InterruptSnapshot {
            usb,
            tx: u16::from_le_bytes([tx_low, tx_high]),
            rx: u16::from_le_bytes([rx_low, rx_high]),
        }
    }

    pub fn endpoint_zero_snapshot(&mut self) -> EndpointZeroSnapshot {
        self.registers.write_usb(UsbRegister::Index, 0);
        EndpointZeroSnapshot {
            control_status: self.registers.read_usb(UsbRegister::ControlStatusZero),
            byte_count: self.registers.read_usb(UsbRegister::CountZero),
        }
    }

    pub fn write_endpoint_zero_control(&mut self, value: u8) {
        self.registers
            .write_usb(UsbRegister::ControlStatusZero, value);
    }

    pub fn write_endpoint_zero_control_high(&mut self, value: u8) {
        self.registers
            .write_usb(UsbRegister::ControlStatusZeroHigh, value);
    }

    pub fn set_function_address(&mut self, address: u8) {
        self.registers
            .write_usb(UsbRegister::FunctionAddress, address);
    }

    pub fn read_fifo_byte(&mut self) -> u8 {
        self.registers.read_usb(UsbRegister::FifoZero)
    }

    pub fn write_fifo_byte(&mut self, value: u8) {
        self.registers.write_usb(UsbRegister::FifoZero, value);
    }

    #[must_use]
    pub fn into_registers(self) -> R {
        self.registers
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    None,
    BusReset,
    Configuration(u8),
    EnterLoader,
}

/// Polling endpoint-zero driver for the minimal wired USB application.
#[derive(Debug)]
pub struct PollingUsbDevice<R> {
    controller: UsbController<R>,
    endpoint_zero: ControlEndpoint,
}

impl<R: RegisterIo> PollingUsbDevice<R> {
    #[must_use]
    pub const fn new(registers: R, release_bcd: u16) -> Self {
        Self {
            controller: UsbController::new(registers),
            endpoint_zero: ControlEndpoint::new(release_bcd),
        }
    }

    pub fn initialize(&mut self) {
        self.controller.initialize_polling();
    }

    /// Polls the clear-on-read interrupt registers once and services endpoint 0.
    pub fn poll(&mut self) -> PollOutcome {
        let interrupts = self.controller.poll_interrupts();
        let outcome = if interrupts.bus_reset() {
            self.endpoint_zero.bus_reset();
            self.controller.set_function_address(0);
            PollOutcome::BusReset
        } else {
            PollOutcome::None
        };
        if !interrupts.endpoint_zero() {
            return outcome;
        }

        let snapshot = self.controller.endpoint_zero_snapshot();
        match self.service_endpoint_zero(snapshot) {
            Some(PollOutcome::None) | None => outcome,
            Some(event) => event,
        }
    }

    #[must_use]
    pub fn into_registers(self) -> R {
        self.controller.into_registers()
    }

    fn service_endpoint_zero(&mut self, snapshot: EndpointZeroSnapshot) -> Option<PollOutcome> {
        if snapshot.control_status & CSR_SENT_STALL != 0 {
            self.controller.write_endpoint_zero_control(0);
            self.endpoint_zero.abort_transfer();
            return None;
        }
        if snapshot.control_status & CSR_SETUP_END != 0 {
            self.controller
                .write_endpoint_zero_control(CSR_SERVICE_SETUP_END);
            self.endpoint_zero.abort_transfer();
        }

        if snapshot.control_status & CSR_RX_PACKET_READY != 0 {
            if snapshot.byte_count == 0 && self.endpoint_zero.awaits_status_completion() {
                self.controller.write_endpoint_zero_control(0);
                return Some(self.complete_status());
            }
            let length = usize::from(snapshot.byte_count);
            if length > MAX_PACKET_LENGTH {
                for _ in 0..length {
                    let _discarded = self.controller.read_fifo_byte();
                }
                self.controller
                    .write_endpoint_zero_control(CSR_SERVICE_RX_PACKET_READY | CSR_SEND_STALL);
                self.endpoint_zero.abort_transfer();
                return None;
            }
            let response = if self.endpoint_zero.expects_out_data() && length == 17 {
                let packet: [u8; 17] = core::array::from_fn(|_| self.controller.read_fifo_byte());
                self.endpoint_zero.handle_out_data(&packet)
            } else if !self.endpoint_zero.expects_out_data() && length == 8 {
                let packet: [u8; 8] = core::array::from_fn(|_| self.controller.read_fifo_byte());
                self.endpoint_zero.handle_setup(&packet)
            } else {
                for _ in 0..length {
                    let _discarded = self.controller.read_fifo_byte();
                }
                EndpointResponse::Stall
            };
            self.apply_response(response, true);
            return None;
        }

        if snapshot.control_status & CSR_TX_PACKET_READY == 0 {
            if self.endpoint_zero.has_pending_in_data() {
                let response = self.endpoint_zero.next_in_packet();
                self.apply_response(response, false);
            } else if snapshot.byte_count == 0 && self.endpoint_zero.awaits_status_completion() {
                self.controller.write_endpoint_zero_control(0);
                return Some(self.complete_status());
            }
        }
        None
    }

    fn apply_response(&mut self, response: EndpointResponse, acknowledge_rx: bool) {
        match response {
            EndpointResponse::None => {},
            EndpointResponse::SendData(packet) => {
                if acknowledge_rx {
                    self.controller
                        .write_endpoint_zero_control(CSR_SERVICE_RX_PACKET_READY);
                }
                let mut index = 0_u8;
                while index < packet.length() {
                    let Some(byte) = self.endpoint_zero.packet_byte(packet, index) else {
                        self.controller.write_endpoint_zero_control(CSR_SEND_STALL);
                        self.endpoint_zero.abort_transfer();
                        return;
                    };
                    self.controller.write_fifo_byte(byte);
                    index = index.wrapping_add(1);
                }
                let mut control = CSR_TX_PACKET_READY;
                if packet.final_packet {
                    control |= CSR_DATA_END;
                }
                self.controller.write_endpoint_zero_control(control);
            },
            EndpointResponse::ReceiveOut { .. } => {
                if acknowledge_rx {
                    self.controller.write_endpoint_zero_control_high(1);
                    self.controller
                        .write_endpoint_zero_control(CSR_SERVICE_RX_PACKET_READY);
                }
            },
            EndpointResponse::SendStatus => {
                if acknowledge_rx {
                    // Stock helper 0x170e8 writes CSR0-high=1, then sends the
                    // endpoint-zero IN status packet as TXPKTRDY|DATAEND.
                    self.controller.write_endpoint_zero_control_high(1);
                    self.controller
                        .write_endpoint_zero_control(CSR_TX_PACKET_READY | CSR_DATA_END);
                } else {
                    self.controller.write_endpoint_zero_control(CSR_DATA_END);
                }
            },
            EndpointResponse::Stall => {
                let acknowledge = if acknowledge_rx {
                    CSR_SERVICE_RX_PACKET_READY
                } else {
                    0
                };
                self.controller
                    .write_endpoint_zero_control(acknowledge | CSR_SEND_STALL);
            },
        }
    }

    fn complete_status(&mut self) -> PollOutcome {
        match self.endpoint_zero.complete_status() {
            DeviceAction::None => PollOutcome::None,
            DeviceAction::SetAddress(address) => {
                self.controller.set_function_address(address);
                PollOutcome::None
            },
            DeviceAction::SetConfiguration(configuration) => {
                PollOutcome::Configuration(configuration)
            },
            DeviceAction::EnterLoader => PollOutcome::EnterLoader,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "the private test register bank maps a closed five-variant enum to a five-element array"
)]
mod tests {
    extern crate alloc;

    use super::{
        CSR_DATA_END, CSR_RX_PACKET_READY, CSR_SERVICE_RX_PACKET_READY, CSR_TX_PACKET_READY,
        InterruptSnapshot, PollOutcome, PollingUsbDevice, RegisterIo, SYSTEM_BASE, SystemRegister,
        USB_BASE, UsbController, UsbRegister,
    };
    use alloc::{collections::VecDeque, vec, vec::Vec};
    use slimblade_protocol::{NORMAL_SET_REPORT_SETUP, NormalReport};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        ReadSystem(SystemRegister),
        WriteSystem(SystemRegister, u32),
        ReadUsb(UsbRegister),
        WriteUsb(UsbRegister, u8),
        Delay(u16),
    }

    #[derive(Debug)]
    struct FakeRegisters {
        operations: Vec<Operation>,
        system_values: [u32; 5],
        otg_configuration: u8,
        power: u8,
        interrupt_usb: u8,
        control_status: u8,
        byte_count: u8,
        fifo: VecDeque<u8>,
    }

    impl Default for FakeRegisters {
        fn default() -> Self {
            Self {
                operations: Vec::new(),
                system_values: [u32::MAX, 0, 0xff, 0x100, 0x10],
                otg_configuration: 0,
                power: 0,
                interrupt_usb: 0xc4,
                control_status: 0,
                byte_count: 0,
                fifo: VecDeque::new(),
            }
        }
    }

    impl RegisterIo for FakeRegisters {
        fn read_system(&mut self, register: SystemRegister) -> u32 {
            self.operations.push(Operation::ReadSystem(register));
            self.system_values[system_value_index(register)]
        }

        fn write_system(&mut self, register: SystemRegister, value: u32) {
            self.operations
                .push(Operation::WriteSystem(register, value));
            self.system_values[system_value_index(register)] = value;
        }

        fn read_usb(&mut self, register: UsbRegister) -> u8 {
            self.operations.push(Operation::ReadUsb(register));
            match register {
                UsbRegister::VoltageThreshold => 0xaa,
                UsbRegister::OtgConfiguration => self.otg_configuration,
                UsbRegister::Power => self.power,
                UsbRegister::AhbInterrupt => 0x55,
                UsbRegister::InterruptUsb => self.interrupt_usb,
                UsbRegister::InterruptTxLow => 0x01,
                UsbRegister::InterruptTxHigh => 0x02,
                UsbRegister::InterruptRxLow => 0x03,
                UsbRegister::InterruptRxHigh => 0x04,
                UsbRegister::ControlStatusZero => self.control_status,
                UsbRegister::CountZero => self.byte_count,
                UsbRegister::FifoZero => self.fifo.pop_front().unwrap_or(0),
                _ => 0,
            }
        }

        fn write_usb(&mut self, register: UsbRegister, value: u8) {
            self.operations.push(Operation::WriteUsb(register, value));
            match register {
                UsbRegister::OtgConfiguration => self.otg_configuration = value,
                UsbRegister::Power => self.power = value,
                _ => {},
            }
        }

        fn delay_cycles(&mut self, cycles: u16) {
            self.operations.push(Operation::Delay(cycles));
        }
    }

    const fn system_value_index(register: SystemRegister) -> usize {
        match register {
            SystemRegister::UsbPlatformControlZero => 0,
            SystemRegister::UsbPlatformControlOne => 1,
            SystemRegister::UsbClockControl => 2,
            SystemRegister::ModuleEnable => 3,
            SystemRegister::GlobalInterruptEnable => 4,
        }
    }

    fn deliver_out(device: &mut PollingUsbDevice<FakeRegisters>, packet: &[u8]) -> PollOutcome {
        let byte_count = u8::try_from(packet.len()).unwrap_or_default();
        assert_eq!(usize::from(byte_count), packet.len());
        device.controller.registers.control_status = CSR_RX_PACKET_READY;
        device.controller.registers.byte_count = byte_count;
        device.controller.registers.fifo = packet.iter().copied().collect();
        device.poll()
    }

    fn finish_status(device: &mut PollingUsbDevice<FakeRegisters>) -> PollOutcome {
        device.controller.registers.control_status = 0;
        device.controller.registers.byte_count = 0;
        device.poll()
    }

    #[test]
    fn typed_addresses_cover_only_stock_usb_platform_and_controller_registers() {
        assert_eq!(
            SystemRegister::UsbPlatformControlZero.address(),
            0x0080_6520
        );
        assert_eq!(SystemRegister::UsbPlatformControlOne.address(), 0x0080_6524);
        assert_eq!(
            SystemRegister::UsbClockControl.address(),
            SYSTEM_BASE + 0x20
        );
        assert_eq!(SystemRegister::ModuleEnable.address(), SYSTEM_BASE + 0x40);
        assert_eq!(
            SystemRegister::GlobalInterruptEnable.address(),
            SYSTEM_BASE + 0x44
        );
        for register in [
            UsbRegister::FunctionAddress,
            UsbRegister::Power,
            UsbRegister::InterruptTxLow,
            UsbRegister::InterruptTxHigh,
            UsbRegister::InterruptRxLow,
            UsbRegister::InterruptRxHigh,
            UsbRegister::InterruptUsb,
            UsbRegister::InterruptTxEnableLow,
            UsbRegister::InterruptTxEnableHigh,
            UsbRegister::InterruptRxEnableLow,
            UsbRegister::InterruptRxEnableHigh,
            UsbRegister::InterruptUsbEnable,
            UsbRegister::Index,
            UsbRegister::DeviceControl,
            UsbRegister::ControlStatusZero,
            UsbRegister::ControlStatusZeroHigh,
            UsbRegister::CountZero,
            UsbRegister::FifoZero,
            UsbRegister::OtgConfiguration,
            UsbRegister::DmaEndpoint,
            UsbRegister::VoltageThreshold,
            UsbRegister::GeneralControl,
            UsbRegister::AhbInterrupt,
            UsbRegister::DeviceConfiguration,
        ] {
            assert!((USB_BASE..USB_BASE + 0xa0).contains(&register.address()));
        }
    }

    #[test]
    fn polling_initialization_matches_the_kensington_register_sequence() {
        let mut controller = UsbController::new(FakeRegisters::default());
        controller.initialize_polling();
        let registers = controller.into_registers();

        assert_eq!(
            registers.operations,
            vec![
                Operation::ReadSystem(SystemRegister::UsbPlatformControlZero),
                Operation::WriteSystem(SystemRegister::UsbPlatformControlZero, u32::MAX),
                Operation::ReadSystem(SystemRegister::UsbPlatformControlOne),
                Operation::WriteSystem(SystemRegister::UsbPlatformControlOne, 0x0040_0000),
                Operation::ReadSystem(SystemRegister::UsbPlatformControlZero),
                Operation::WriteSystem(SystemRegister::UsbPlatformControlZero, 0xbfbf_ffff,),
                Operation::ReadSystem(SystemRegister::UsbClockControl),
                Operation::WriteSystem(SystemRegister::UsbClockControl, 0xfe),
                Operation::ReadSystem(SystemRegister::UsbClockControl),
                Operation::WriteSystem(SystemRegister::UsbClockControl, 0x7e),
                Operation::WriteUsb(UsbRegister::InterruptRxEnableLow, 0),
                Operation::WriteUsb(UsbRegister::InterruptRxEnableHigh, 0),
                Operation::WriteUsb(UsbRegister::InterruptTxEnableLow, 0),
                Operation::WriteUsb(UsbRegister::InterruptTxEnableHigh, 0),
                Operation::WriteUsb(UsbRegister::InterruptUsbEnable, 0),
                Operation::ReadUsb(UsbRegister::VoltageThreshold),
                Operation::WriteUsb(UsbRegister::VoltageThreshold, 0x2a),
                Operation::WriteUsb(UsbRegister::InterruptRxEnableLow, 0x07),
                Operation::WriteUsb(UsbRegister::InterruptRxEnableHigh, 0),
                Operation::WriteUsb(UsbRegister::InterruptTxEnableLow, 0x07),
                Operation::WriteUsb(UsbRegister::InterruptTxEnableHigh, 0),
                Operation::WriteUsb(UsbRegister::InterruptUsbEnable, 0x3f),
                Operation::WriteUsb(UsbRegister::OtgConfiguration, 0),
                Operation::WriteUsb(UsbRegister::DmaEndpoint, 0),
                Operation::WriteUsb(UsbRegister::DeviceConfiguration, 0xf4),
                Operation::ReadUsb(UsbRegister::OtgConfiguration),
                Operation::WriteUsb(UsbRegister::OtgConfiguration, 0x01),
                Operation::Delay(499),
                Operation::ReadUsb(UsbRegister::AhbInterrupt),
                Operation::Delay(499),
                Operation::WriteUsb(UsbRegister::AhbInterrupt, 0x55),
                Operation::Delay(499),
                Operation::WriteUsb(UsbRegister::GeneralControl, 0x77),
                Operation::WriteUsb(UsbRegister::FunctionAddress, 0),
                Operation::WriteUsb(UsbRegister::DeviceControl, 1),
                Operation::ReadSystem(SystemRegister::ModuleEnable),
                Operation::WriteSystem(SystemRegister::ModuleEnable, 0x900),
                Operation::ReadSystem(SystemRegister::GlobalInterruptEnable),
                Operation::WriteSystem(SystemRegister::GlobalInterruptEnable, 0x13),
                Operation::ReadUsb(UsbRegister::OtgConfiguration),
                Operation::WriteUsb(UsbRegister::OtgConfiguration, 0x09),
                Operation::ReadUsb(UsbRegister::Power),
                Operation::WriteUsb(UsbRegister::Power, 1),
            ]
        );
    }

    #[test]
    fn polling_captures_and_decodes_interrupts_once() {
        let mut controller = UsbController::new(FakeRegisters::default());
        let snapshot = controller.poll_interrupts();

        assert_eq!(
            snapshot,
            InterruptSnapshot {
                usb: 0x04,
                tx: 0x0201,
                rx: 0x0403,
            }
        );
        assert!(snapshot.bus_reset());
        assert!(snapshot.endpoint_zero());
    }

    #[test]
    fn endpoint_zero_translates_device_descriptor_into_stock_csr_order() {
        let registers = FakeRegisters {
            interrupt_usb: 0,
            control_status: CSR_RX_PACKET_READY,
            byte_count: 8,
            fifo: [0x80, 0x06, 0, 0x01, 0, 0, 64, 0].into_iter().collect(),
            ..FakeRegisters::default()
        };
        let mut device = PollingUsbDevice::new(registers, 0x0454);

        assert_eq!(device.poll(), PollOutcome::None);
        let registers = device.into_registers();
        let mut expected_tail = vec![
            Operation::WriteUsb(UsbRegister::Index, 0),
            Operation::ReadUsb(UsbRegister::ControlStatusZero),
            Operation::ReadUsb(UsbRegister::CountZero),
        ];
        for _ in 0_u8..8 {
            expected_tail.push(Operation::ReadUsb(UsbRegister::FifoZero));
        }
        expected_tail.push(Operation::WriteUsb(
            UsbRegister::ControlStatusZero,
            CSR_SERVICE_RX_PACKET_READY,
        ));
        for byte in [
            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x7d, 0x04, 0xd7, 0x80, 0x54, 0x04,
            0x01, 0x02, 0x00, 0x01,
        ] {
            expected_tail.push(Operation::WriteUsb(UsbRegister::FifoZero, byte));
        }
        expected_tail.push(Operation::WriteUsb(
            UsbRegister::ControlStatusZero,
            CSR_TX_PACKET_READY | CSR_DATA_END,
        ));

        assert!(registers.operations.ends_with(&expected_tail));
        assert!(registers.fifo.is_empty());
    }

    #[test]
    fn loader_outcome_occurs_only_after_status_completion_interrupt() {
        let registers = FakeRegisters {
            interrupt_usb: 0,
            control_status: CSR_RX_PACKET_READY,
            byte_count: 8,
            fifo: NORMAL_SET_REPORT_SETUP.into_iter().collect(),
            ..FakeRegisters::default()
        };
        let mut device = PollingUsbDevice::new(registers, 0x0454);

        assert_eq!(device.poll(), PollOutcome::None);
        assert!(device.controller.registers.operations.ends_with(&[
            Operation::WriteUsb(UsbRegister::ControlStatusZeroHigh, 1),
            Operation::WriteUsb(UsbRegister::ControlStatusZero, CSR_SERVICE_RX_PACKET_READY,),
        ]));

        assert_eq!(
            deliver_out(&mut device, NormalReport::reset_to_loader().as_bytes()),
            PollOutcome::None
        );
        assert!(device.endpoint_zero.awaits_status_completion());
        assert!(device.controller.registers.operations.ends_with(&[
            Operation::WriteUsb(UsbRegister::ControlStatusZeroHigh, 1),
            Operation::WriteUsb(
                UsbRegister::ControlStatusZero,
                CSR_TX_PACKET_READY | CSR_DATA_END,
            ),
        ]));

        assert_eq!(finish_status(&mut device), PollOutcome::EnterLoader);
        assert_eq!(device.poll(), PollOutcome::None);
    }

    #[test]
    fn synthetic_enumeration_reaches_configured_recovery_path() {
        let mut device = PollingUsbDevice::new(
            FakeRegisters {
                interrupt_usb: 0,
                ..FakeRegisters::default()
            },
            0x0454,
        );

        assert_eq!(
            deliver_out(&mut device, &[0x80, 0x06, 0, 0x01, 0, 0, 64, 0],),
            PollOutcome::None
        );
        assert_eq!(
            deliver_out(&mut device, &[]),
            PollOutcome::None,
            "host status OUT completes the device descriptor"
        );

        assert_eq!(
            deliver_out(&mut device, &[0x00, 0x05, 7, 0, 0, 0, 0, 0]),
            PollOutcome::None
        );
        assert_eq!(finish_status(&mut device), PollOutcome::None);
        assert!(
            device
                .controller
                .registers
                .operations
                .contains(&Operation::WriteUsb(UsbRegister::FunctionAddress, 7))
        );

        assert_eq!(
            deliver_out(&mut device, &[0x80, 0x06, 0, 0x02, 0, 0, 0x3b, 0],),
            PollOutcome::None
        );
        assert_eq!(deliver_out(&mut device, &[]), PollOutcome::None);

        assert_eq!(
            deliver_out(&mut device, &[0x00, 0x09, 1, 0, 0, 0, 0, 0]),
            PollOutcome::None
        );
        assert_eq!(finish_status(&mut device), PollOutcome::Configuration(1));

        assert_eq!(
            deliver_out(&mut device, &NORMAL_SET_REPORT_SETUP),
            PollOutcome::None
        );
        assert_eq!(
            deliver_out(&mut device, NormalReport::reset_to_loader().as_bytes()),
            PollOutcome::None
        );
        assert_eq!(finish_status(&mut device), PollOutcome::EnterLoader);
    }
}
