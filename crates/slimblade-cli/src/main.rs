use core::time::Duration;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Instant;

use slimblade_cli::{
    FlashArtifact, InputSnapshot, InputStatePage, PostFlashExpectation, SensorObservationKind,
    SensorShadow, SensorTracker, active_loop_arm_response_is_success,
    dispatcher_return_arm_response_is_success, experiment_dispatch_arm_response_is_success,
    input_snapshot, input_state_page, late_marker_response_is_success,
    post_init_arm_response_is_success, post_init_hook_state, rust_response_is_success,
    sensor_shadow, sensor_shadow_arm_response_is_success, steady_loop_arm_response_is_success,
    unsolicited_report_probe_response_is_success, wired_loop_arm_response_is_success,
};
use slimblade_linux::UsbDevice;
use slimblade_linux::flash::{transfer_payload, wait_for_queried_loader};
use slimblade_linux::hidraw::Hidraw;
use slimblade_linux::sysfs::{
    HIDRAW_SYSFS_ROOT, observe_usb_silence, usb_device_from_directory, usb_parent_for_hidraw,
    wait_for_identity_at_path, wait_for_reenumeration,
};
use slimblade_linux::usbfs;
use slimblade_protocol::{
    BOOT_IDENTITIES, KENSINGTON_WIRED_IDENTITY, NormalReport, SensorStreamReport,
};

const DEFAULT_APPLICATION_DEVICE: &str = "/dev/slimblade-vendor";
const DEFAULT_LOADER_DEVICE: &str = "/dev/slimblade-loader";
const DEFAULT_RESCUE_DEVICE: &str = "/sys/bus/usb/devices/1-4";

#[derive(Debug)]
enum Command {
    Identify,
    EnterLoader {
        confirmed: bool,
    },
    SetLateMarker {
        confirmed: bool,
    },
    StartExperiment {
        confirmed: bool,
    },
    RunRustResponse {
        confirmed: bool,
    },
    RunPostInitHook {
        confirmed: bool,
    },
    RunUnsolicitedReportProbe {
        confirmed: bool,
    },
    ReadInput {
        confirmed: bool,
    },
    CaptureInput {
        confirmed: bool,
    },
    CaptureState {
        confirmed: bool,
    },
    CaptureSensors {
        confirmed: bool,
    },
    PollSensors {
        confirmed: bool,
    },
    StreamSensors {
        confirmed: bool,
        duration: Option<Duration>,
    },
    ProbeStreamTransport,
    UsbfsEnterLoader {
        confirmed: bool,
    },
    StreamSensorReports {
        duration: Option<Duration>,
    },
    QueryLoader,
    Flash {
        artifact: FlashArtifact,
        firmware: PathBuf,
        confirmation: String,
    },
}

#[derive(Debug)]
struct Arguments {
    device: PathBuf,
    timeout: Duration,
    command: Command,
}

const fn usage() -> &'static str {
    "usage:\n  slimblade [--device PATH] identify\n  slimblade [--device PATH] [--timeout-seconds N] enter-loader --confirm\n  slimblade [--device USB_SYSFS_PATH] [--timeout-seconds N] usbfs-enter-loader --confirm\n  slimblade [--device PATH] [--timeout-seconds N] set-late-marker --confirm\n  slimblade [--device PATH] [--timeout-seconds N] start-experiment --confirm\n  slimblade [--device PATH] [--timeout-seconds N] run-rust-response --confirm\n  slimblade [--device PATH] [--timeout-seconds N] run-post-init-hook --confirm\n  slimblade [--device PATH] [--timeout-seconds N] run-unsolicited-report-probe --confirm\n  slimblade [--device PATH] [--timeout-seconds N] read-input --confirm\n  slimblade [--device PATH] [--timeout-seconds N] capture-input --confirm\n  slimblade [--device PATH] [--timeout-seconds N] capture-state --confirm\n  slimblade [--device PATH] [--timeout-seconds N] capture-sensors --confirm\n  slimblade [--device PATH] [--timeout-seconds N] poll-sensors --confirm\n  slimblade [--device PATH] [--timeout-seconds N] [--duration-seconds N] stream-sensors --confirm\n  slimblade [--device PATH] [--timeout-seconds N] probe-stream-transport\n  slimblade [--device PATH] [--timeout-seconds N] [--duration-seconds N] stream-sensor-reports\n  slimblade [--device PATH] [--timeout-seconds N] query-loader\n  slimblade [--device PATH] [--timeout-seconds N] FLASH_COMMAND --firmware PATH --confirm-sha256 HASH\n\nFLASH_COMMAND: restore-official-v449, flash-descriptor-probe, flash-recovery-carrier, flash-reset-trampoline, flash-recovery-stub, flash-startup-trampoline, flash-rust-guard, flash-usb-recovery-probe, flash-stock-harness, flash-late-marker-probe, flash-experiment-entry-probe, flash-rust-response-probe, flash-post-init-hook-probe, flash-wired-loop-hook-probe, flash-active-loop-hook-probe, flash-steady-loop-hook-probe, flash-dispatcher-return-hook-probe, flash-experiment-dispatch-guard, flash-unsolicited-report-probe, flash-custom-main-handoff-probe, flash-custom-main-usb-recovery-probe, flash-custom-main-stream-transport-probe, flash-custom-main-sensor-stream-probe, flash-input-diagnostics, flash-paged-input-diagnostics, or flash-sensor-shadow-diagnostics"
}

fn flash_artifact_for_command(command: &str) -> Option<FlashArtifact> {
    match command {
        "restore-official-v449" => Some(FlashArtifact::OfficialV449),
        "flash-descriptor-probe" => Some(FlashArtifact::DescriptorProbe),
        "flash-recovery-carrier" => Some(FlashArtifact::RecoveryCarrier),
        "flash-reset-trampoline" => Some(FlashArtifact::ResetTrampoline),
        "flash-recovery-stub" => Some(FlashArtifact::RecoveryStub),
        "flash-startup-trampoline" => Some(FlashArtifact::StartupTrampoline),
        "flash-rust-guard" => Some(FlashArtifact::RecoveryGuard),
        "flash-usb-recovery-probe" => Some(FlashArtifact::UsbRecoveryProbe),
        "flash-stock-harness" => Some(FlashArtifact::StockHarness),
        "flash-late-marker-probe" => Some(FlashArtifact::LateMarkerProbe),
        "flash-experiment-entry-probe" => Some(FlashArtifact::ExperimentEntryProbe),
        "flash-rust-response-probe" => Some(FlashArtifact::RustResponseProbe),
        "flash-post-init-hook-probe" => Some(FlashArtifact::PostInitHookProbe),
        "flash-wired-loop-hook-probe" => Some(FlashArtifact::WiredLoopHookProbe),
        "flash-active-loop-hook-probe" => Some(FlashArtifact::ActiveLoopHookProbe),
        "flash-steady-loop-hook-probe" => Some(FlashArtifact::SteadyLoopHookProbe),
        "flash-dispatcher-return-hook-probe" => Some(FlashArtifact::DispatcherReturnHookProbe),
        "flash-experiment-dispatch-guard" => Some(FlashArtifact::ExperimentDispatchGuard),
        "flash-unsolicited-report-probe" => Some(FlashArtifact::UnsolicitedReportProbe),
        "flash-custom-main-handoff-probe" => Some(FlashArtifact::CustomMainHandoffProbe),
        "flash-custom-main-usb-recovery-probe" => Some(FlashArtifact::CustomMainUsbRecoveryProbe),
        "flash-custom-main-stream-transport-probe" => {
            Some(FlashArtifact::CustomMainStreamTransportProbe)
        },
        "flash-custom-main-sensor-stream-probe" => Some(FlashArtifact::CustomMainSensorStreamProbe),
        "flash-input-diagnostics" => Some(FlashArtifact::InputDiagnostics),
        "flash-paged-input-diagnostics" => Some(FlashArtifact::PagedInputDiagnostics),
        "flash-sensor-shadow-diagnostics" => Some(FlashArtifact::SensorShadowDiagnostics),
        _ => None,
    }
}

fn take_value(arguments: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index = index
        .checked_add(1)
        .ok_or_else(|| "argument index overflow".to_owned())?;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn take_duration(
    arguments: &[String],
    index: &mut usize,
    option: &str,
) -> Result<Duration, String> {
    let value = take_value(arguments, index, option)?;
    value
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|error| format!("invalid {option} value {value:?}: {error}"))
}

const fn default_device(command: &Command) -> &'static str {
    match command {
        Command::QueryLoader | Command::Flash { .. } => DEFAULT_LOADER_DEVICE,
        Command::UsbfsEnterLoader { .. } => DEFAULT_RESCUE_DEVICE,
        _ => DEFAULT_APPLICATION_DEVICE,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the flat command mapping keeps every safety-sensitive flash spelling reviewable"
)]
fn parse_arguments() -> Result<Arguments, String> {
    let raw: Vec<String> = env::args().skip(1).collect();
    let mut device = None;
    let mut timeout = Duration::from_secs(3);
    let mut stream_duration = None;
    let mut command_name = None;
    let mut confirmed = false;
    let mut firmware = None;
    let mut confirmation = None;
    let mut index = 0_usize;
    while index < raw.len() {
        let argument = raw
            .get(index)
            .ok_or_else(|| "argument index out of bounds".to_owned())?;
        match argument.as_str() {
            "--device" => device = Some(PathBuf::from(take_value(&raw, &mut index, argument)?)),
            "--timeout-seconds" => timeout = take_duration(&raw, &mut index, argument)?,
            "--duration-seconds" => {
                stream_duration = Some(take_duration(&raw, &mut index, argument)?);
            },
            "--confirm" => confirmed = true,
            "--firmware" => {
                firmware = Some(PathBuf::from(take_value(&raw, &mut index, argument)?));
            },
            "--confirm-sha256" => {
                confirmation = Some(take_value(&raw, &mut index, argument)?);
            },
            value if value.starts_with('-') => return Err(format!("unknown option {value:?}")),
            value if command_name.is_none() => command_name = Some(value.to_owned()),
            value => return Err(format!("unexpected argument {value:?}")),
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| "argument index overflow".to_owned())?;
    }
    let command_name = command_name.ok_or_else(|| "missing command".to_owned())?;
    let command = match command_name.as_str() {
        "identify" => Command::Identify,
        "enter-loader" => Command::EnterLoader { confirmed },
        "usbfs-enter-loader" => Command::UsbfsEnterLoader { confirmed },
        "set-late-marker" => Command::SetLateMarker { confirmed },
        "start-experiment" => Command::StartExperiment { confirmed },
        "run-rust-response" => Command::RunRustResponse { confirmed },
        "run-post-init-hook" => Command::RunPostInitHook { confirmed },
        "run-unsolicited-report-probe" => Command::RunUnsolicitedReportProbe { confirmed },
        "read-input" => Command::ReadInput { confirmed },
        "capture-input" => Command::CaptureInput { confirmed },
        "capture-state" => Command::CaptureState { confirmed },
        "capture-sensors" => Command::CaptureSensors { confirmed },
        "poll-sensors" => Command::PollSensors { confirmed },
        "stream-sensors" => Command::StreamSensors {
            confirmed,
            duration: stream_duration,
        },
        "probe-stream-transport" => Command::ProbeStreamTransport,
        "stream-sensor-reports" => Command::StreamSensorReports {
            duration: stream_duration,
        },
        "query-loader" => Command::QueryLoader,
        "restore-official-v449"
        | "flash-descriptor-probe"
        | "flash-recovery-carrier"
        | "flash-reset-trampoline"
        | "flash-recovery-stub"
        | "flash-startup-trampoline"
        | "flash-rust-guard"
        | "flash-usb-recovery-probe"
        | "flash-stock-harness"
        | "flash-late-marker-probe"
        | "flash-experiment-entry-probe"
        | "flash-rust-response-probe"
        | "flash-post-init-hook-probe"
        | "flash-wired-loop-hook-probe"
        | "flash-active-loop-hook-probe"
        | "flash-steady-loop-hook-probe"
        | "flash-dispatcher-return-hook-probe"
        | "flash-experiment-dispatch-guard"
        | "flash-unsolicited-report-probe"
        | "flash-custom-main-handoff-probe"
        | "flash-custom-main-usb-recovery-probe"
        | "flash-custom-main-stream-transport-probe"
        | "flash-custom-main-sensor-stream-probe"
        | "flash-input-diagnostics"
        | "flash-paged-input-diagnostics"
        | "flash-sensor-shadow-diagnostics" => Command::Flash {
            artifact: flash_artifact_for_command(command_name.as_str())
                .ok_or_else(|| "unreachable flash command mapping".to_owned())?,
            firmware: firmware.ok_or_else(|| "flash command requires --firmware".to_owned())?,
            confirmation: confirmation
                .ok_or_else(|| "flash command requires --confirm-sha256".to_owned())?,
        },
        value => return Err(format!("unknown command {value:?}")),
    };
    if stream_duration.is_some()
        && !matches!(
            &command,
            Command::StreamSensors { .. } | Command::StreamSensorReports { .. }
        )
    {
        return Err(
            "--duration-seconds is only valid with stream-sensors or stream-sensor-reports"
                .to_owned(),
        );
    }
    let default_device = default_device(&command);
    Ok(Arguments {
        device: device.unwrap_or_else(|| PathBuf::from(default_device)),
        timeout,
        command,
    })
}

fn identify(device: &Path) -> Result<(), String> {
    let hidraw = Hidraw::open_read_only(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (bus, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    let descriptor = hidraw
        .report_descriptor()
        .map_err(|error| format!("could not read HID report descriptor: {error}"))?;
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    println!("device={}", device.display());
    println!("bus={bus}");
    println!(
        "identity={:04x}:{:04x}",
        identity.vendor_id, identity.product_id
    );
    println!("bcd_device={}", parent.bcd_device.as_deref().unwrap_or(""));
    println!("sysfs={}", parent.sysfs);
    println!("report_descriptor_bytes={}", descriptor.len());
    Ok(())
}

fn enter_loader(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing loader reset without --confirm".to_owned());
    }
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    let mut hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != KENSINGTON_WIRED_IDENTITY || parent.identity != identity {
        return Err(format!(
            "refusing reset for unexpected identity {:04x}:{:04x}",
            identity.vendor_id, identity.product_id
        ));
    }
    hidraw
        .write_report(NormalReport::reset_to_loader().as_bytes())
        .map_err(|error| format!("reset-to-loader report failed: {error}"))?;
    drop(hidraw);
    let loader = wait_for_identity_at_path(&parent.sysfs, &BOOT_IDENTITIES, timeout)
        .map_err(|error| format!("USB enumeration failed: {error}"))?
        .ok_or_else(|| "resident loader did not appear at the same USB path".to_owned())?;
    println!(
        "loader={:04x}:{:04x} sysfs={} devnum={}",
        loader.identity.vendor_id,
        loader.identity.product_id,
        loader.sysfs,
        loader.devnum.as_deref().unwrap_or("")
    );
    Ok(())
}

fn usbfs_enter_loader(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing usbfs loader reset without --confirm".to_owned());
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "rescue timeout overflow".to_owned())?;
    let mut attempts = 0_u64;
    let mut last_error = None;
    let mut physical_path = None;
    while Instant::now() < deadline {
        match usb_device_from_directory(device) {
            Ok(Some(current)) if BOOT_IDENTITIES.contains(&current.identity) => {
                println!(
                    "loader={:04x}:{:04x} sysfs={} attempts={attempts}",
                    current.identity.vendor_id, current.identity.product_id, current.sysfs
                );
                return Ok(());
            },
            Ok(Some(current))
                if current.identity == KENSINGTON_WIRED_IDENTITY
                    && current.bcd_device.as_deref() == Some("0475") =>
            {
                physical_path.get_or_insert(current.sysfs);
                match usbfs::send_normal_report(device, NormalReport::reset_to_loader()) {
                    Ok(()) => {
                        attempts = attempts.saturating_add(1);
                        last_error = None;
                    },
                    Err(error) => last_error = Some(error.to_string()),
                }
            },
            Ok(Some(current)) => {
                return Err(format!(
                    "refusing usbfs reset for {:04x}:{:04x} bcdDevice={:?}",
                    current.identity.vendor_id, current.identity.product_id, current.bcd_device
                ));
            },
            Ok(None) => {},
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::Interrupted
                ) => {},
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "usbfs recovery timed out after {attempts} accepted transfers at {:?}; last error: {}",
        physical_path,
        last_error.as_deref().unwrap_or("device did not enumerate")
    ))
}

fn set_late_marker(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing persistent marker write without --confirm".to_owned());
    }
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0456")
    {
        return Err(format!(
            "refusing marker command for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0456",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let mut hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    hidraw
        .write_report(NormalReport::command(0x0e).as_bytes())
        .map_err(|error| format!("late-marker report failed: {error}"))?;
    let response = hidraw
        .read_normal_report(timeout.max(Duration::from_secs(3)))
        .map_err(|error| format!("late-marker response failed: {error}"))?
        .ok_or_else(|| "late-marker command did not return a vendor response".to_owned())?;
    if !late_marker_response_is_success(response) {
        return Err("late-marker command returned an unexpected response".to_owned());
    }
    println!(
        "late_marker=ack command=0e status=01 sysfs={}",
        parent.sysfs
    );
    Ok(())
}

fn start_experiment(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing marker-then-hang experiment without --confirm".to_owned());
    }
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0457")
    {
        return Err(format!(
            "refusing experiment command for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0457",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let mut hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    hidraw
        .write_report(NormalReport::command(0x0e).as_bytes())
        .map_err(|error| format!("experiment-entry report failed: {error}"))?;
    if hidraw
        .read_normal_report(timeout.max(Duration::from_secs(3)))
        .map_err(|error| format!("experiment-entry observation failed: {error}"))?
        .is_some()
    {
        return Err(
            "experiment returned an unexpected vendor response instead of hanging".to_owned(),
        );
    }
    println!(
        "experiment_entry=sent command=0e response=none expected=marker-then-hang sysfs={}",
        parent.sysfs
    );
    Ok(())
}

fn run_rust_response(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing marker-first Rust response probe without --confirm".to_owned());
    }
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0458")
    {
        return Err(format!(
            "refusing Rust response command for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0458",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let mut hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    hidraw
        .write_report(NormalReport::command(0x0e).as_bytes())
        .map_err(|error| format!("Rust response report failed: {error}"))?;
    let response = hidraw
        .read_normal_report(timeout.max(Duration::from_secs(3)))
        .map_err(|error| format!("Rust response read failed: {error}"))?
        .ok_or_else(|| "Rust response probe did not return a vendor response".to_owned())?;
    if !rust_response_is_success(response) {
        return Err("Rust response probe returned an unexpected signature or status".to_owned());
    }
    println!(
        "rust_response=ack command=0e status=01 signature=58 sysfs={}",
        parent.sysfs
    );
    Ok(())
}

fn exchange_vendor_command(
    hidraw: &mut Hidraw,
    command: u8,
    timeout: Duration,
) -> Result<NormalReport, String> {
    exchange_vendor_report(hidraw, NormalReport::command(command), timeout)
}

fn exchange_vendor_report(
    hidraw: &mut Hidraw,
    report: NormalReport,
    timeout: Duration,
) -> Result<NormalReport, String> {
    let command = report.command_byte();
    hidraw
        .write_report(report.as_bytes())
        .map_err(|error| format!("vendor command {command:#04x} failed: {error}"))?;
    hidraw
        .read_normal_report(timeout.max(Duration::from_secs(3)))
        .map_err(|error| format!("vendor response {command:#04x} failed: {error}"))?
        .ok_or_else(|| format!("vendor command {command:#04x} returned no response"))
}

fn run_post_init_hook(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing persistent-marker hook probe without --confirm".to_owned());
    }
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY {
        return Err(format!(
            "refusing post-init hook command for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let (expected_state, expected_signature, armed_state) = match parent.bcd_device.as_deref() {
        Some("0459") => (2_u8, 0xa3_u8, 3_u8),
        Some("0460") => (0_u8, 0xa5_u8, 5_u8),
        Some("0461") => (0_u8, 0xa6_u8, 5_u8),
        Some("0462") => (0_u8, 0xa7_u8, 5_u8),
        Some("0463") => (0_u8, 0xa8_u8, 5_u8),
        Some("0464") => (0_u8, 0xa9_u8, 5_u8),
        _ => {
            return Err(format!(
                "refusing post-init hook command for bcdDevice={:?}; expected 0459, 0460, 0461, 0462, 0463, or 0464",
                parent.bcd_device
            ));
        },
    };
    let mut hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }

    let initial = exchange_vendor_command(&mut hidraw, 0x0f, timeout)?;
    let initial_state = post_init_hook_state(initial);
    if initial_state != Some(expected_state) {
        return Err(format!(
            "post-init hook preflight reported mode {initial_state:?}, expected Some({expected_state})"
        ));
    }
    let armed = exchange_vendor_command(&mut hidraw, 0x0e, timeout)?;
    let arm_succeeded = match expected_signature {
        0xa3 => post_init_arm_response_is_success(armed),
        0xa5 => wired_loop_arm_response_is_success(armed),
        0xa6 => active_loop_arm_response_is_success(armed),
        0xa7 => steady_loop_arm_response_is_success(armed),
        0xa8 => dispatcher_return_arm_response_is_success(armed),
        0xa9 => experiment_dispatch_arm_response_is_success(armed),
        _ => false,
    };
    if !arm_succeeded {
        return Err(format!(
            "marker command did not return status 01 and signature {expected_signature:02x}"
        ));
    }

    for attempt in 1_u8..=8_u8 {
        let response = exchange_vendor_command(&mut hidraw, 0x0f, timeout)?;
        match post_init_hook_state(response) {
            Some(state) if state == expected_state => {
                println!(
                    "post_init_hook=pass initial={expected_state:02x} arm_signature={expected_signature:02x} final={state:02x} attempts={attempt} sysfs={}",
                    parent.sysfs
                );
                return Ok(());
            },
            Some(state) if state == armed_state => {},
            Some(state) => {
                return Err(format!(
                    "post-init hook returned unexpected mode {state:#04x}"
                ));
            },
            None => return Err("post-init hook state response was malformed".to_owned()),
        }
    }
    Err("post-init hook remained armed after eight queries".to_owned())
}

fn run_unsolicited_report_probe(
    device: &Path,
    timeout: Duration,
    confirmed: bool,
) -> Result<(), String> {
    if !confirmed {
        return Err(
            "refusing persistent-marker unsolicited-report probe without --confirm".to_owned(),
        );
    }
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0471")
    {
        return Err(format!(
            "refusing unsolicited-report probe for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0471",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let mut hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }

    hidraw
        .write_report(NormalReport::command(0x0e).as_bytes())
        .map_err(|error| format!("unsolicited-report arm failed: {error}"))?;
    let response_timeout = timeout.max(Duration::from_secs(3));
    let acknowledged = hidraw
        .read_normal_report(response_timeout)
        .map_err(|error| format!("acknowledged response failed: {error}"))?
        .ok_or_else(|| "marker command did not return its acknowledged response".to_owned())?;
    if !unsolicited_report_probe_response_is_success(acknowledged) {
        return Err("marker command did not return status 01 and signature ab".to_owned());
    }
    let unsolicited = hidraw
        .read_normal_report(response_timeout)
        .map_err(|error| format!("unsolicited response failed: {error}"))?
        .ok_or_else(|| "endpoint 0x82 did not emit an unsolicited second report".to_owned())?;
    if unsolicited != acknowledged {
        return Err("unsolicited report did not reproduce the acknowledged response".to_owned());
    }
    if hidraw
        .read_normal_report(Duration::from_millis(100))
        .map_err(|error| format!("one-shot completion check failed: {error}"))?
        .is_some()
    {
        return Err("one-shot probe emitted an unexpected third vendor report".to_owned());
    }
    println!(
        "unsolicited_report=pass acknowledged=1 unsolicited=1 extra=0 signature=ab sysfs={}",
        parent.sysfs
    );
    Ok(())
}

fn open_input_diagnostics(device: &Path) -> Result<(UsbDevice, Hidraw), String> {
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0465")
    {
        return Err(format!(
            "refusing input diagnostic for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0465",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    Ok((parent, hidraw))
}

fn arm_input_diagnostics(hidraw: &mut Hidraw, timeout: Duration) -> Result<(), String> {
    let armed = exchange_vendor_command(hidraw, 0x0e, timeout)?;
    if experiment_dispatch_arm_response_is_success(armed) {
        Ok(())
    } else {
        Err("marker command did not return status 01 and signature a9".to_owned())
    }
}

fn query_input_snapshot(hidraw: &mut Hidraw, timeout: Duration) -> Result<InputSnapshot, String> {
    let response = exchange_vendor_command(hidraw, 0x0f, timeout)?;
    input_snapshot(response)
        .ok_or_else(|| "input diagnostic returned a malformed snapshot".to_owned())
}

fn print_input_snapshot(snapshot: InputSnapshot, elapsed_ms: u128, sysfs: &str) {
    println!(
        "input elapsed_ms={elapsed_ms} prefix={:02x}{:02x} sequence={} buttons={:#04x} motion_x={} motion_y={} report_6={:#04x} report_7={:#04x} report_8={:#04x} report_9={:#04x} sysfs={sysfs}",
        snapshot.prefix[0],
        snapshot.prefix[1],
        snapshot.sequence,
        snapshot.buttons,
        snapshot.motion_x,
        snapshot.motion_y,
        snapshot.report_6,
        snapshot.report_7,
        snapshot.report_8,
        snapshot.report_9,
    );
}

fn read_input(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing marker-first input diagnostic without --confirm".to_owned());
    }
    let (parent, mut hidraw) = open_input_diagnostics(device)?;
    arm_input_diagnostics(&mut hidraw, timeout)?;
    let snapshot = query_input_snapshot(&mut hidraw, timeout)?;
    print_input_snapshot(snapshot, 0, &parent.sysfs);
    Ok(())
}

fn capture_input(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing marker-first input capture without --confirm".to_owned());
    }
    let (parent, mut hidraw) = open_input_diagnostics(device)?;
    arm_input_diagnostics(&mut hidraw, timeout)?;
    let started = Instant::now();
    let duration = Duration::from_secs(15);
    let mut previous = None;
    while started.elapsed() < duration {
        let snapshot = query_input_snapshot(&mut hidraw, timeout)?;
        if previous != Some(snapshot) {
            print_input_snapshot(snapshot, started.elapsed().as_millis(), &parent.sysfs);
            previous = Some(snapshot);
        }
        thread::sleep(Duration::from_millis(20));
    }
    println!(
        "input_capture=complete duration_ms=15000 sysfs={}",
        parent.sysfs
    );
    Ok(())
}

const INPUT_STATE_SELECTORS: [u8; 5] = [0, 2, 6, 15, 20];

fn open_paged_input_diagnostics(device: &Path) -> Result<(UsbDevice, Hidraw), String> {
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0466")
    {
        return Err(format!(
            "refusing paged input diagnostic for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0466",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    Ok((parent, hidraw))
}

fn query_input_state_page(
    hidraw: &mut Hidraw,
    selector: u8,
    timeout: Duration,
) -> Result<InputStatePage, String> {
    let request = NormalReport::command_with_parameter(0x0f, selector);
    let response = exchange_vendor_report(hidraw, request, timeout)?;
    input_state_page(response, selector).ok_or_else(|| {
        format!("paged input diagnostic returned a malformed selector {selector} response")
    })
}

const fn tracked_input_bytes(page: InputStatePage) -> Option<[u8; 4]> {
    let [_, _, b2, b3, b4, b5, b6, b7, _, _, _, _] = page.bytes;
    match page.selector {
        0 | 2 | 20 => Some([b4, b5, b6, b7]),
        6 | 15 => Some([b2, b3, b4, b5]),
        _ => None,
    }
}

fn print_tracked_input(page: InputStatePage, tracked: [u8; 4], elapsed_ms: u128, sysfs: &str) {
    let [t0, t1, t2, t3] = tracked;
    let first = u16::from_le_bytes([t0, t1]);
    let second = u16::from_le_bytes([t2, t3]);
    let first_signed = i16::from_le_bytes(first.to_le_bytes());
    let second_signed = i16::from_le_bytes(second.to_le_bytes());
    let label = match page.selector {
        0 => "buttons-debounced",
        2 => "sensor-a-accumulator",
        6 => "combined-motion",
        15 => "sensor-b-accumulator",
        20 => "buttons-processed",
        _ => "unknown",
    };
    println!(
        "state elapsed_ms={elapsed_ms} source={label} address={:#010x} raw={:02x}{:02x}{:02x}{:02x} words={first:04x},{second:04x} signed={first_signed},{second_signed} sysfs={sysfs}",
        page.address()
            + if matches!(page.selector, 6 | 15) {
                2
            } else {
                4
            },
        t0,
        t1,
        t2,
        t3,
    );
}

fn capture_state(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing marker-first paged input capture without --confirm".to_owned());
    }
    let (parent, mut hidraw) = open_paged_input_diagnostics(device)?;
    arm_input_diagnostics(&mut hidraw, timeout)?;
    let started = Instant::now();
    let duration = Duration::from_secs(15);
    let mut previous: [Option<[u8; 4]>; INPUT_STATE_SELECTORS.len()] =
        [None; INPUT_STATE_SELECTORS.len()];
    while started.elapsed() < duration {
        for (index, selector) in INPUT_STATE_SELECTORS.into_iter().enumerate() {
            let page = query_input_state_page(&mut hidraw, selector, timeout)?;
            let tracked = tracked_input_bytes(page)
                .ok_or_else(|| format!("no tracked field mapping for selector {selector}"))?;
            if previous.get(index).copied().flatten() != Some(tracked) {
                print_tracked_input(page, tracked, started.elapsed().as_millis(), &parent.sysfs);
                let slot = previous
                    .get_mut(index)
                    .ok_or_else(|| "input selector index escaped fixed page array".to_owned())?;
                *slot = Some(tracked);
            }
        }
    }
    println!(
        "state_capture=complete duration_ms=15000 sysfs={}",
        parent.sysfs
    );
    Ok(())
}

fn open_sensor_shadow_diagnostics(device: &Path) -> Result<(UsbDevice, Hidraw), String> {
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0470")
    {
        return Err(format!(
            "refusing sensor shadow diagnostic for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0470",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let hidraw = Hidraw::open_read_write(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let (_, identity) = hidraw
        .identity()
        .map_err(|error| format!("could not query HID identity: {error}"))?;
    if identity != parent.identity {
        return Err("HID identity and USB parent disagree".to_owned());
    }
    Ok((parent, hidraw))
}

fn capture_sensors(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing marker-first sensor capture without --confirm".to_owned());
    }
    let (parent, mut hidraw) = open_sensor_shadow_diagnostics(device)?;
    let armed = exchange_vendor_command(&mut hidraw, 0x0e, timeout)?;
    if !sensor_shadow_arm_response_is_success(armed) {
        return Err("marker command did not return status 01 and signature aa".to_owned());
    }
    println!(
        "sensor_capture=armed duration_ms=10000 sysfs={}",
        parent.sysfs
    );
    thread::sleep(Duration::from_secs(10));
    let response = exchange_vendor_command(&mut hidraw, 0x0f, timeout)?;
    let snapshot = sensor_shadow(response)
        .ok_or_else(|| "sensor shadow diagnostic returned a malformed response".to_owned())?;
    println!(
        "sensors sequence={} a_x={} a_y={} b_x={} b_y={} sysfs={}",
        snapshot.sequence,
        snapshot.sensor_a_x,
        snapshot.sensor_a_y,
        snapshot.sensor_b_x,
        snapshot.sensor_b_y,
        parent.sysfs
    );
    println!(
        "sensor_capture=complete duration_ms=10000 sysfs={}",
        parent.sysfs
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct AxisStats {
    minimum: i16,
    maximum: i16,
}

impl AxisStats {
    const fn new() -> Self {
        Self {
            minimum: i16::MAX,
            maximum: i16::MIN,
        }
    }

    fn observe(&mut self, value: i16) {
        self.minimum = self.minimum.min(value);
        self.maximum = self.maximum.max(value);
    }
}

#[derive(Clone, Copy, Debug)]
struct SensorPollStats {
    a_x: AxisStats,
    a_y: AxisStats,
    b_x: AxisStats,
    b_y: AxisStats,
}

impl SensorPollStats {
    const fn new() -> Self {
        Self {
            a_x: AxisStats::new(),
            a_y: AxisStats::new(),
            b_x: AxisStats::new(),
            b_y: AxisStats::new(),
        }
    }

    fn observe_changed(&mut self, sample: SensorShadow) {
        self.a_x.observe(sample.sensor_a_x);
        self.a_y.observe(sample.sensor_a_y);
        self.b_x.observe(sample.sensor_b_x);
        self.b_y.observe(sample.sensor_b_y);
    }
}

fn poll_sensors(device: &Path, timeout: Duration, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("refusing RAM-only sensor polling without --confirm".to_owned());
    }
    let (parent, mut hidraw) = open_sensor_shadow_diagnostics(device)?;
    let started = Instant::now();
    let duration = Duration::from_secs(15);
    let mut tracker = SensorTracker::default();
    let mut stats = SensorPollStats::new();
    let mut next_report = Duration::ZERO;
    while started.elapsed() < duration {
        let response = exchange_vendor_command(&mut hidraw, 0x0f, timeout)?;
        let snapshot = sensor_shadow(response)
            .ok_or_else(|| "sensor shadow diagnostic returned a malformed response".to_owned())?;
        let observation = tracker
            .observe(snapshot)
            .map_err(|error| error.to_string())?;
        if observation.kind == SensorObservationKind::Changed {
            stats.observe_changed(snapshot);
        }
        let elapsed = started.elapsed();
        if elapsed >= next_report {
            println!(
                "sensors elapsed_ms={} sequence={} a_x={} a_y={} b_x={} b_y={} sysfs={}",
                elapsed.as_millis(),
                snapshot.sequence,
                snapshot.sensor_a_x,
                snapshot.sensor_a_y,
                snapshot.sensor_b_x,
                snapshot.sensor_b_y,
                parent.sysfs
            );
            next_report = next_report
                .checked_add(Duration::from_millis(250))
                .ok_or_else(|| "sensor report interval overflow".to_owned())?;
        }
    }
    let totals = tracker.totals();
    println!(
        "sensor_poll=complete duration_ms=15000 polls={} changed_samples={} skipped_samples={} a_x_min={} a_x_max={} a_x_sum={} a_y_min={} a_y_max={} a_y_sum={} b_x_min={} b_x_max={} b_x_sum={} b_y_min={} b_y_max={} b_y_sum={} sysfs={}",
        tracker.polls(),
        tracker.changed_samples(),
        tracker.skipped_samples(),
        stats.a_x.minimum,
        stats.a_x.maximum,
        totals.sensor_a_x,
        stats.a_y.minimum,
        stats.a_y.maximum,
        totals.sensor_a_y,
        stats.b_x.minimum,
        stats.b_x.maximum,
        totals.sensor_b_x,
        stats.b_y.minimum,
        stats.b_y.maximum,
        totals.sensor_b_y,
        parent.sysfs
    );
    Ok(())
}

fn stream_sensors(
    device: &Path,
    timeout: Duration,
    duration: Option<Duration>,
    confirmed: bool,
) -> Result<(), String> {
    if !confirmed {
        return Err("refusing RAM-only sensor streaming without --confirm".to_owned());
    }
    let (parent, mut hidraw) = open_sensor_shadow_diagnostics(device)?;
    eprintln!(
        "sensor_stream=started format=ndjson bcd_device=0470 sysfs={}",
        parent.sysfs
    );
    let started = Instant::now();
    let mut tracker = SensorTracker::default();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    while duration.is_none_or(|limit| started.elapsed() < limit) {
        let response = exchange_vendor_command(&mut hidraw, 0x0f, timeout)?;
        let snapshot = sensor_shadow(response)
            .ok_or_else(|| "sensor shadow diagnostic returned a malformed response".to_owned())?;
        let observation = tracker
            .observe(snapshot)
            .map_err(|error| error.to_string())?;
        let kind = match observation.kind {
            SensorObservationKind::Initial => "initial",
            SensorObservationKind::Changed => "sample",
            SensorObservationKind::Retained => continue,
        };
        writeln!(
            output,
            "{{\"type\":\"{kind}\",\"elapsed_us\":{},\"sequence\":{},\"sequence_gap\":{},\"skipped_total\":{},\"a_x\":{},\"a_y\":{},\"b_x\":{},\"b_y\":{},\"a_x_total\":{},\"a_y_total\":{},\"b_x_total\":{},\"b_y_total\":{}}}",
            started.elapsed().as_micros(),
            snapshot.sequence,
            observation.sequence_gap,
            observation.skipped_samples,
            snapshot.sensor_a_x,
            snapshot.sensor_a_y,
            snapshot.sensor_b_x,
            snapshot.sensor_b_y,
            observation.totals.sensor_a_x,
            observation.totals.sensor_a_y,
            observation.totals.sensor_b_x,
            observation.totals.sensor_b_y,
        )
        .map_err(|error| format!("could not write sensor stream: {error}"))?;
        output
            .flush()
            .map_err(|error| format!("could not flush sensor stream: {error}"))?;
    }
    let totals = tracker.totals();
    writeln!(
        output,
        "{{\"type\":\"summary\",\"elapsed_us\":{},\"polls\":{},\"changed_samples\":{},\"skipped_samples\":{},\"a_x_total\":{},\"a_y_total\":{},\"b_x_total\":{},\"b_y_total\":{}}}",
        started.elapsed().as_micros(),
        tracker.polls(),
        tracker.changed_samples(),
        tracker.skipped_samples(),
        totals.sensor_a_x,
        totals.sensor_a_y,
        totals.sensor_b_x,
        totals.sensor_b_y,
    )
    .map_err(|error| format!("could not write sensor stream summary: {error}"))?;
    Ok(())
}

fn probe_stream_transport(device: &Path, timeout: Duration) -> Result<(), String> {
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0474")
    {
        return Err(format!(
            "refusing stream probe for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0474",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let mut hidraw = Hidraw::open_read_only(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "stream timeout overflow".to_owned())?;
    let mut first_sequence = None;
    let mut previous_sequence = None;
    let mut reports = 0_u8;
    while reports < 8 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("stream stopped after {reports} valid reports"));
        }
        let envelope = hidraw
            .read_normal_report(remaining)
            .map_err(|error| format!("stream read failed: {error}"))?
            .ok_or_else(|| format!("stream stopped after {reports} valid reports"))?;
        let report = SensorStreamReport::decode(envelope)
            .map_err(|error| format!("invalid sensor stream report: {error}"))?;
        if report.flags != 0
            || report.sensor_a_x != 0
            || report.sensor_a_y != 0
            || report.sensor_b_x != 0
            || report.sensor_b_y != 0
            || report.buttons != 0
            || report.sample_count != 0
        {
            return Err("transport probe emitted nonzero diagnostic fields".to_owned());
        }
        if previous_sequence.is_some_and(|previous: u16| previous == report.sequence) {
            return Err(format!(
                "transport probe repeated sequence {}",
                report.sequence
            ));
        }
        first_sequence.get_or_insert(report.sequence);
        previous_sequence = Some(report.sequence);
        reports = reports
            .checked_add(1)
            .ok_or_else(|| "stream report counter overflow".to_owned())?;
    }
    println!(
        "stream_transport=pass reports={reports} first_sequence={} last_sequence={} sysfs={}",
        first_sequence.ok_or_else(|| "stream had no first sequence".to_owned())?,
        previous_sequence.ok_or_else(|| "stream had no final sequence".to_owned())?,
        parent.sysfs
    );
    Ok(())
}

fn stream_sensor_reports(
    device: &Path,
    timeout: Duration,
    duration: Option<Duration>,
) -> Result<(), String> {
    let parent = usb_parent_for_hidraw(device, Path::new(HIDRAW_SYSFS_ROOT))
        .map_err(|error| format!("could not resolve USB parent: {error}"))?
        .ok_or_else(|| "could not find USB parent".to_owned())?;
    if parent.identity != KENSINGTON_WIRED_IDENTITY || parent.bcd_device.as_deref() != Some("0475")
    {
        return Err(format!(
            "refusing sensor stream for identity {:04x}:{:04x} bcdDevice={:?}; expected 047d:80d7/0475",
            parent.identity.vendor_id, parent.identity.product_id, parent.bcd_device
        ));
    }
    let mut hidraw = Hidraw::open_read_only(device)
        .map_err(|error| format!("could not open {}: {error}", device.display()))?;
    let started = Instant::now();
    let limit = duration.unwrap_or(Duration::from_secs(1));
    let mut reports = 0_u64;
    let mut moving_reports = 0_u64;
    let mut samples = 0_u64;
    let mut saturated_reports = 0_u64;
    let mut previous_sequence = None;
    let mut sequence_gaps = 0_u64;
    let mut totals = [0_i64; 4];
    let stdout = io::stdout();
    let mut output = stdout.lock();
    while started.elapsed() < limit {
        let report = hidraw
            .read_normal_report(timeout)
            .map_err(|error| format!("sensor stream read failed: {error}"))?
            .ok_or_else(|| "sensor stream timed out".to_owned())?;
        let report = SensorStreamReport::decode(report)
            .map_err(|error| format!("invalid sensor stream report: {error}"))?;
        if let Some(previous) = previous_sequence {
            sequence_gaps = sequence_gaps.saturating_add(u64::from(
                report.sequence.wrapping_sub(previous).saturating_sub(1),
            ));
        }
        previous_sequence = Some(report.sequence);
        reports = reports.saturating_add(1);
        samples = samples.saturating_add(u64::from(report.sample_count));
        if report.flags != 0 {
            saturated_reports = saturated_reports.saturating_add(1);
        }
        let axes = [
            report.sensor_a_x,
            report.sensor_a_y,
            report.sensor_b_x,
            report.sensor_b_y,
        ];
        for (total, axis) in totals.iter_mut().zip(axes) {
            *total = total.saturating_add(i64::from(axis));
        }
        if axes != [0; 4] {
            moving_reports = moving_reports.saturating_add(1);
            writeln!(
                output,
                "{{\"sequence\":{},\"flags\":{},\"samples\":{},\"a_x\":{},\"a_y\":{},\"b_x\":{},\"b_y\":{}}}",
                report.sequence,
                report.flags,
                report.sample_count,
                report.sensor_a_x,
                report.sensor_a_y,
                report.sensor_b_x,
                report.sensor_b_y,
            )
            .map_err(|error| format!("could not write sensor report: {error}"))?;
        }
    }
    writeln!(
        output,
        "{{\"type\":\"summary\",\"elapsed_us\":{},\"reports\":{},\"moving_reports\":{},\"samples\":{},\"sequence_gaps\":{},\"saturated_reports\":{},\"a_x_total\":{},\"a_y_total\":{},\"b_x_total\":{},\"b_y_total\":{}}}",
        started.elapsed().as_micros(),
        reports,
        moving_reports,
        samples,
        sequence_gaps,
        saturated_reports,
        totals[0],
        totals[1],
        totals[2],
        totals[3],
    )
    .map_err(|error| format!("could not write sensor summary: {error}"))?;
    Ok(())
}

fn query_loader(device: &Path, timeout: Duration) -> Result<(), String> {
    let loader = wait_for_queried_loader(device, timeout.max(Duration::from_secs(8)))
        .map_err(|error| error.to_string())?;
    println!(
        "loader=d2 identity={:04x}:{:04x} device={} sysfs={}",
        loader.usb_parent.identity.vendor_id,
        loader.usb_parent.identity.product_id,
        loader.path.display(),
        loader.usb_parent.sysfs
    );
    Ok(())
}

fn flash_artifact(
    device: &Path,
    timeout: Duration,
    artifact: FlashArtifact,
    firmware: &Path,
    confirmation: &str,
) -> Result<(), String> {
    if let Some(reason) = artifact.flash_refusal_reason() {
        return Err(format!("refusing flash: {reason}"));
    }
    if !artifact.confirmation_matches(confirmation) {
        return Err(format!(
            "refusing flash: --confirm-sha256 must equal {}",
            artifact.confirmation_sha256()
        ));
    }
    let image = fs::read(firmware)
        .map_err(|error| format!("could not read {}: {error}", firmware.display()))?;
    let payload = artifact
        .identity()
        .validate(&image)
        .map_err(|error| format!("refusing flash: {error}"))?;
    let mut loader = wait_for_queried_loader(device, timeout.max(Duration::from_secs(8)))
        .map_err(|error| format!("no erase was attempted: {error}"))?;
    println!(
        "loader query: d2; image={} payload={} bytes crc={:08x}",
        artifact.confirmation_sha256(),
        payload.len(),
        artifact.identity().payload_crc
    );
    let previous = loader.usb_parent.clone();
    let mut next_percent = 5_usize;
    let blocks = transfer_payload(loader.transport_mut(), payload, timeout, |done, total| {
        let percent = done.saturating_mul(100).checked_div(total).unwrap_or(0);
        if percent >= next_percent || done == total {
            println!("write/verify: {percent}% ({done}/{total})");
            next_percent = percent.saturating_add(5);
        }
    })
    .map_err(|error| format!("flash failed after erase boundary: {error}"))?;
    drop(loader);
    match artifact.post_flash_expectation() {
        PostFlashExpectation::Application { bcd_device } => {
            let application = wait_for_reenumeration(
                &previous,
                &[KENSINGTON_WIRED_IDENTITY],
                Duration::from_secs(20),
            )
            .map_err(|error| format!("post-flash USB observation failed: {error}"))?
            .ok_or_else(|| {
                "final block echoed, but the application did not return at the same USB path"
                    .to_owned()
            })?;
            if application.bcd_device.as_deref() != Some(bcd_device) {
                return Err(format!(
                    "application returned with bcdDevice={:?}, expected {bcd_device}",
                    application.bcd_device
                ));
            }
            println!(
                "application={:04x}:{:04x} bcdDevice={bcd_device} sysfs={}",
                application.identity.vendor_id, application.identity.product_id, application.sysfs
            );
            println!("flash complete: {blocks} blocks echoed");
        },
        PostFlashExpectation::ResidentLoader => {
            let resident =
                wait_for_reenumeration(&previous, &BOOT_IDENTITIES, Duration::from_secs(20))
                    .map_err(|error| format!("post-flash USB observation failed: {error}"))?
                    .ok_or_else(|| {
                        "final block echoed, but a new resident-loader enumeration did not appear"
                            .to_owned()
                    })?;
            println!(
                "resident_loader={:04x}:{:04x} sysfs={}",
                resident.identity.vendor_id, resident.identity.product_id, resident.sysfs
            );
            println!("flash complete: {blocks} blocks echoed");
        },
        PostFlashExpectation::UsbSilence => {
            if !observe_usb_silence(&previous, timeout.max(Duration::from_secs(5)))
                .map_err(|error| format!("post-flash USB observation failed: {error}"))?
            {
                return Err(
                    "final block echoed, but expected marker-first USB silence was not observed"
                        .to_owned(),
                );
            }
            println!("guard complete: {blocks} blocks echoed; expected USB silence observed");
        },
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    match arguments.command {
        Command::Identify => identify(&arguments.device),
        Command::EnterLoader { confirmed } => {
            enter_loader(&arguments.device, arguments.timeout, confirmed)
        },
        Command::UsbfsEnterLoader { confirmed } => {
            usbfs_enter_loader(&arguments.device, arguments.timeout, confirmed)
        },
        Command::SetLateMarker { confirmed } => {
            set_late_marker(&arguments.device, arguments.timeout, confirmed)
        },
        Command::StartExperiment { confirmed } => {
            start_experiment(&arguments.device, arguments.timeout, confirmed)
        },
        Command::RunRustResponse { confirmed } => {
            run_rust_response(&arguments.device, arguments.timeout, confirmed)
        },
        Command::RunPostInitHook { confirmed } => {
            run_post_init_hook(&arguments.device, arguments.timeout, confirmed)
        },
        Command::RunUnsolicitedReportProbe { confirmed } => {
            run_unsolicited_report_probe(&arguments.device, arguments.timeout, confirmed)
        },
        Command::ReadInput { confirmed } => {
            read_input(&arguments.device, arguments.timeout, confirmed)
        },
        Command::CaptureInput { confirmed } => {
            capture_input(&arguments.device, arguments.timeout, confirmed)
        },
        Command::CaptureState { confirmed } => {
            capture_state(&arguments.device, arguments.timeout, confirmed)
        },
        Command::CaptureSensors { confirmed } => {
            capture_sensors(&arguments.device, arguments.timeout, confirmed)
        },
        Command::PollSensors { confirmed } => {
            poll_sensors(&arguments.device, arguments.timeout, confirmed)
        },
        Command::StreamSensors {
            confirmed,
            duration,
        } => stream_sensors(&arguments.device, arguments.timeout, duration, confirmed),
        Command::ProbeStreamTransport => {
            probe_stream_transport(&arguments.device, arguments.timeout)
        },
        Command::StreamSensorReports { duration } => {
            stream_sensor_reports(&arguments.device, arguments.timeout, duration)
        },
        Command::QueryLoader => query_loader(&arguments.device, arguments.timeout),
        Command::Flash {
            artifact,
            firmware,
            confirmation,
        } => flash_artifact(
            &arguments.device,
            arguments.timeout,
            artifact,
            &firmware,
            &confirmation,
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}\n{}", usage());
            ExitCode::from(2)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{SensorPollStats, SensorShadow};

    #[test]
    fn sensor_poll_stats_track_changed_ranges() {
        let mut stats = SensorPollStats::new();
        stats.observe_changed(SensorShadow {
            sequence: 1,
            sensor_a_x: -2,
            sensor_a_y: 3,
            sensor_b_x: 4,
            sensor_b_y: -5,
        });
        stats.observe_changed(SensorShadow {
            sequence: 2,
            sensor_a_x: 6,
            sensor_a_y: -7,
            sensor_b_x: -8,
            sensor_b_y: 9,
        });

        assert_eq!(stats.a_x.minimum, -2);
        assert_eq!(stats.a_x.maximum, 6);
        assert_eq!(stats.a_y.minimum, -7);
        assert_eq!(stats.a_y.maximum, 3);
        assert_eq!(stats.b_x.minimum, -8);
        assert_eq!(stats.b_x.maximum, 4);
        assert_eq!(stats.b_y.minimum, -5);
        assert_eq!(stats.b_y.maximum, 9);
    }
}
