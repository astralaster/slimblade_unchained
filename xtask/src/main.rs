use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use slimblade_image::{
    ACTIVE_LOOP_HOOK_PROBE_ARTIFACT, APPLICATION_PREFIX_OFFSET, ArtifactIdentity,
    CUSTOM_MAIN_HANDOFF_PROBE_ARTIFACT, CUSTOM_MAIN_SENSOR_STREAM_PROBE_ARTIFACT,
    CUSTOM_MAIN_SENSOR_STREAM_RUNTIME_ARTIFACT, CUSTOM_MAIN_SENSOR_STREAM_SUPPORT_ARTIFACT,
    CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_ARTIFACT, CUSTOM_MAIN_STREAM_TRANSPORT_RUNTIME_ARTIFACT,
    CUSTOM_MAIN_USB_RECOVERY_PROBE_ARTIFACT, DISPATCHER_RETURN_HOOK_PROBE_ARTIFACT,
    EXPERIMENT_DISPATCH_GUARD_ARTIFACT, EXPERIMENT_ENTRY_PROBE_ARTIFACT,
    INPUT_DIAGNOSTICS_ARTIFACT, LATE_MARKER_PROBE_ARTIFACT, OFFICIAL_V449,
    PAGED_INPUT_DIAGNOSTICS_ARTIFACT, POST_INIT_HOOK_PROBE_ARTIFACT, RECOVERY_GUARD,
    RECOVERY_GUARD_ARTIFACT, RUST_RESPONSE_PROBE_ARTIFACT, SENSOR_SHADOW_DIAGNOSTICS_ARTIFACT,
    STEADY_LOOP_HOOK_PROBE_ARTIFACT, STOCK_HARNESS_ARTIFACT, UNSOLICITED_REPORT_PROBE_ARTIFACT,
    USB_RECOVERY_PROBE, USB_RECOVERY_PROBE_ARTIFACT, WIRED_LOOP_HOOK_PROBE_ARTIFACT, sha256,
};
use slimblade_protocol::updater_crc32;
use slimblade_verify::experiment_entry_probe;
use slimblade_verify::late_marker_probe;
use slimblade_verify::post_init_hook_probe;
use slimblade_verify::post_link::audit_nm_outputs;
use slimblade_verify::rust_response_probe;
use slimblade_verify::stock_harness;
use slimblade_verify::usb_probe::{EXPERIMENT_ADDRESS, audit_code};

const FIRMWARE_TOOLCHAIN: &str = "+nightly-2026-08-14";
const POST_LINK_ELFS: &[&str] =
    &["firmware/bk3635-rs/target/thumbv5te-none-eabi/release/slimblade-guard"];
const USB_PROBE_BINARY: &str = "slimblade-usb-recovery-probe";
const STOCK_HARNESS_BINARY: &str = "slimblade-stock-harness";
const LATE_MARKER_PROBE_BINARY: &str = "slimblade-late-marker-probe";
const EXPERIMENT_ENTRY_PROBE_BINARY: &str = "slimblade-experiment-entry-probe";
const RUST_RESPONSE_PROBE_BINARY: &str = "slimblade-rust-response-probe";
const POST_INIT_HOOK_PROBE_BINARY: &str = "slimblade-post-init-hook-probe";
const WIRED_LOOP_HOOK_PROBE_BINARY: &str = "slimblade-wired-loop-hook-probe";
const ACTIVE_LOOP_HOOK_PROBE_BINARY: &str = "slimblade-active-loop-hook-probe";
const STEADY_LOOP_HOOK_PROBE_BINARY: &str = "slimblade-steady-loop-hook-probe";
const DISPATCHER_RETURN_HOOK_PROBE_BINARY: &str = "slimblade-dispatcher-return-hook-probe";
const EXPERIMENT_DISPATCH_GUARD_BINARY: &str = "slimblade-experiment-dispatch-guard";
const UNSOLICITED_REPORT_PROBE_BINARY: &str = "slimblade-unsolicited-report-probe";
const CUSTOM_MAIN_HANDOFF_PROBE_BINARY: &str = "slimblade-custom-main-handoff-probe";
const CUSTOM_MAIN_USB_RECOVERY_PROBE_BINARY: &str = "slimblade-custom-main-usb-recovery-probe";
const CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_BINARY: &str =
    "slimblade-custom-main-stream-transport-probe";
const CUSTOM_MAIN_SENSOR_STREAM_PROBE_BINARY: &str = "slimblade-custom-main-sensor-stream-probe";
const INPUT_DIAGNOSTICS_BINARY: &str = "slimblade-input-diagnostics";
const PAGED_INPUT_DIAGNOSTICS_BINARY: &str = "slimblade-paged-input-diagnostics";
const SENSOR_SHADOW_DIAGNOSTICS_BINARY: &str = "slimblade-sensor-shadow-diagnostics";
const USB_PROBE_MAX_STACK_BYTES: usize = 256;
const USB_PROBE_CODE_ADDRESS: u32 = 0x0000_2020;
const SYSTEM_MMIO_START: u32 = 0x0080_0000;
const SYSTEM_MMIO_END: u32 = 0x0081_0000;
const ALLOWED_USB_PROBE_MMIO: &[u32] = &[
    0x0080_0020,
    0x0080_0040,
    0x0080_0044,
    0x0080_4000,
    0x0080_4011,
    0x0080_4020,
    0x0080_4080,
    0x0080_6520,
    0x0080_6524,
];

type StockMarkerBuild = fn(&[u8], &[u8]) -> Result<Vec<u8>, late_marker_probe::BuildError>;
type StockMarkerVerify =
    fn(
        &[u8],
        &[u8],
        &[u8],
        &[u8],
    ) -> Result<late_marker_probe::LateMarkerReport, late_marker_probe::VerificationError>;
type HookBuild = fn(&[u8], &[u8]) -> Result<Vec<u8>, post_init_hook_probe::Error>;
type HookVerify = fn(
    &[u8],
    &[u8],
    &[u8],
    &[u8],
) -> Result<post_init_hook_probe::Report, post_init_hook_probe::Error>;
type RuntimeHookBuild = fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>, post_init_hook_probe::Error>;
type RuntimeHookVerify = fn(
    &[u8],
    &[u8],
    &[u8],
    &[u8],
    &[u8],
) -> Result<post_init_hook_probe::Report, post_init_hook_probe::Error>;
type SensorRuntimeBuild =
    fn(&[u8], &[u8], &[u8], &[u8]) -> Result<Vec<u8>, post_init_hook_probe::Error>;
type SensorRuntimeVerify = fn(
    &[u8],
    &[u8],
    &[u8],
    &[u8],
    &[u8],
    &[u8],
) -> Result<post_init_hook_probe::Report, post_init_hook_probe::Error>;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn run(root: &Path, program: &str, arguments: &[&str]) -> Result<(), String> {
    eprintln!("+ {program} {}", arguments.join(" "));
    let status = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

fn host_checks(root: &Path) -> Result<(), String> {
    run(root, "cargo", &["fmt", "--all", "--check"])?;
    run(
        root,
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(root, "cargo", &["test", "--workspace"])?;
    run(
        root,
        "cargo",
        &[
            "check",
            "--package",
            "slimblade-verify",
            "--no-default-features",
        ],
    )?;

    let firmware = root.join("firmware/bk3635-rs");
    run(&firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--lib",
            "--bin",
            "slimblade-guard",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &firmware,
        "cargo",
        &[FIRMWARE_TOOLCHAIN, "build", "--release"],
    )?;
    build_rust_guard(root)?;
    post_link_checks(root)?;
    build_usb_probe(root)?;
    build_stock_harness(root)?;
    build_late_marker_probe(root)?;
    build_experiment_entry_probe(root)?;
    build_rust_response_probe(root)?;
    build_post_init_hook_probe(root)?;
    build_wired_loop_hook_probe(root)?;
    build_active_loop_hook_probe(root)?;
    build_steady_loop_hook_probe(root)?;
    build_dispatcher_return_hook_probe(root)?;
    build_experiment_dispatch_guard(root)?;
    build_unsolicited_report_probe(root)?;
    build_custom_main_handoff_probe(root)?;
    build_custom_main_usb_recovery_probe(root)?;
    build_custom_main_stream_transport_probe(root)?;
    build_custom_main_sensor_stream_probe(root)?;
    build_input_diagnostics(root)?;
    build_paged_input_diagnostics(root)?;
    build_sensor_shadow_diagnostics(root)
}

fn build_rust_guard(root: &Path) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-rs");
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "build",
            "--release",
            "--bin",
            "slimblade-guard",
        ],
    )?;

    let elf = firmware.join("target/thumbv5te-none-eabi/release/slimblade-guard");
    let artifact_dir = firmware.join("target/guard");
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let code_path = artifact_dir.join("DO_NOT_FLASH-rust-marker-first-guard.code.bin");
    let container_path = artifact_dir.join("DO_NOT_FLASH-rust-marker-first-guard.container.bin");
    eprintln!(
        "+ llvm-objcopy -O binary {} {}",
        elf.display(),
        code_path.display()
    );
    let status = Command::new("llvm-objcopy")
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&code_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objcopy: {error}"))?;
    if !status.success() {
        return Err(format!("llvm-objcopy exited with {status}"));
    }

    let code = fs::read(&code_path)
        .map_err(|error| format!("could not read {}: {error}", code_path.display()))?;
    if !RECOVERY_GUARD_ARTIFACT.code_matches(&code) {
        return Err("Rust guard code does not match the live-tested 422-byte identity".to_owned());
    }
    let container = slimblade_verify::recovery_stub::build(&code)
        .map_err(|error| format!("could not pack Rust guard: {error}"))?;
    RECOVERY_GUARD
        .validate(&container)
        .map_err(|error| format!("Rust guard container identity failed: {error}"))?;
    fs::write(&container_path, &container)
        .map_err(|error| format!("could not write {}: {error}", container_path.display()))?;
    eprintln!(
        "Rust guard PASS: {} code bytes, {} container bytes",
        code.len(),
        container.len()
    );
    Ok(())
}

fn llvm_nm(root: &Path, elf: &str, mode: &str) -> Result<String, String> {
    eprintln!("+ llvm-nm {mode} --demangle {elf}");
    let output = Command::new("llvm-nm")
        .args([mode, "--demangle", elf])
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not inspect {elf}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "llvm-nm failed for {elf}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("llvm-nm returned non-UTF-8 output for {elf}: {error}"))
}

fn post_link_checks(root: &Path) -> Result<(), String> {
    for elf in POST_LINK_ELFS {
        let defined = llvm_nm(root, elf, "--defined-only")?;
        let undefined = llvm_nm(root, elf, "--undefined-only")?;
        let report = audit_nm_outputs(&defined, &undefined)
            .map_err(|error| format!("post-link audit failed for {elf}: {error}"))?;
        eprintln!(
            "post-link PASS: {elf} ({} defined symbols)",
            report.defined_symbols
        );
    }
    Ok(())
}

fn command_output(directory: &Path, program: &str, arguments: &[String]) -> Result<String, String> {
    eprintln!("+ {program} {}", arguments.join(" "));
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("{program} returned non-UTF-8 output: {error}"))
}

fn audit_probe_disassembly(
    disassembly: &str,
    code: &[u8],
    executable_end: u32,
) -> Result<usize, String> {
    const FORBIDDEN_MNEMONICS: &[&str] = &["svc", "swi", "udf"];

    let mut mmio_literals = 0_usize;
    let mut has_usb_clock_control = false;
    let mut has_usb_controller = false;
    let mut has_usb_platform_control = false;
    for line in disassembly.lines() {
        let mut columns = line.split_whitespace();
        let Some(address) = columns.next() else {
            continue;
        };
        if !address.ends_with(':') {
            continue;
        }
        let Some(_encoding) = columns.next() else {
            continue;
        };
        let Some(mnemonic) = columns.next() else {
            continue;
        };
        let operands = columns.collect::<Vec<_>>().join(" ");
        let writes_pc = (mnemonic == "mov" || mnemonic == "add" || mnemonic == "ldr")
            && operands
                .split(',')
                .next()
                .is_some_and(|operand| operand.trim() == "pc");
        let indirect_blx = mnemonic == "blx" && operands.trim_start().starts_with('r');
        let non_return_bx = mnemonic == "bx" && operands.trim() != "lr";
        if FORBIDDEN_MNEMONICS.contains(&mnemonic) || writes_pc || indirect_blx || non_return_bx {
            return Err(format!("forbidden experiment instruction: {line}"));
        }

        let direct_branch = mnemonic == "bl"
            || (mnemonic.starts_with('b')
                && mnemonic != "bic"
                && mnemonic != "bics"
                && mnemonic != "blx"
                && mnemonic != "bx");
        if direct_branch {
            let target = operands
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("branch has no decoded target: {line}"))?;
            let target = u32::try_from(parse_address(target)?).map_err(|error| {
                format!("branch target does not fit the BK3635 address space: {error}")
            })?;
            let internal = (EXPERIMENT_ADDRESS..executable_end).contains(&target);
            let reviewed_reset = mnemonic == "bl" && target == 0x0000_20fc;
            if !internal && !reviewed_reset {
                return Err(format!("branch escapes reviewed experiment code: {line}"));
            }
        }

        if mnemonic != "ldr" || !operands.contains("[pc") {
            continue;
        }
        let target = operands
            .split_whitespace()
            .skip_while(|field| *field != "@")
            .nth(1)
            .ok_or_else(|| format!("PC-relative load has no decoded target: {line}"))?;
        let target = u32::try_from(parse_address(target)?).map_err(|error| {
            format!("literal target does not fit the BK3635 address space: {error}")
        })?;
        let offset = target
            .checked_sub(USB_PROBE_CODE_ADDRESS)
            .ok_or_else(|| format!("literal target precedes probe code: {line}"))?;
        let offset = usize::try_from(offset)
            .map_err(|error| format!("literal offset does not fit usize: {error}"))?;
        let end = offset
            .checked_add(4)
            .ok_or_else(|| "literal offset overflow".to_owned())?;
        let bytes = code
            .get(offset..end)
            .and_then(|literal| <[u8; 4]>::try_from(literal).ok())
            .ok_or_else(|| format!("literal target lies outside extracted code: {line}"))?;
        let value = u32::from_le_bytes(bytes);
        if (SYSTEM_MMIO_START..SYSTEM_MMIO_END).contains(&value) {
            if !ALLOWED_USB_PROBE_MMIO.contains(&value) {
                return Err(format!(
                    "unreviewed MMIO literal {value:#010x} loaded by: {line}"
                ));
            }
            mmio_literals = mmio_literals.saturating_add(1);
            has_usb_clock_control |= value == 0x0080_0020;
            has_usb_controller |= value == 0x0080_4000;
            has_usb_platform_control |= value == 0x0080_6520;
        }
    }
    if !has_usb_clock_control {
        return Err("experiment does not load the stock USB clock-control address".to_owned());
    }
    if !has_usb_controller {
        return Err("experiment does not load the reviewed USB base address".to_owned());
    }
    if !has_usb_platform_control {
        return Err("experiment does not load the stock USB platform-control address".to_owned());
    }
    Ok(mmio_literals)
}

fn experiment_executable_end(sized_symbols: &str) -> Result<u32, String> {
    let mut executable_end = None::<u32>;
    for line in sized_symbols.lines() {
        let mut fields = line.split_whitespace();
        let Some(address) = fields
            .next()
            .and_then(|value| u32::from_str_radix(value, 16).ok())
        else {
            continue;
        };
        let Some(size) = fields
            .next()
            .and_then(|value| u32::from_str_radix(value, 16).ok())
        else {
            continue;
        };
        let Some(kind) = fields.next() else {
            continue;
        };
        if !matches!(kind, "t" | "T") || address < EXPERIMENT_ADDRESS || size == 0 {
            continue;
        }
        let end = address
            .checked_add(size)
            .ok_or_else(|| format!("symbol address overflow: {line}"))?;
        executable_end = Some(executable_end.map_or(end, |current| current.max(end)));
    }
    executable_end.ok_or_else(|| "probe ELF has no sized experiment text symbols".to_owned())
}

fn audit_probe_stack_sizes(stack_sizes: &str) -> Result<usize, String> {
    let mut maximum = None::<usize>;
    let mut found_entry = false;
    for line in stack_sizes.lines() {
        let mut fields = line.split_whitespace();
        let Some(size) = fields.next().and_then(|value| value.parse::<usize>().ok()) else {
            continue;
        };
        let function = fields.collect::<Vec<_>>().join(" ");
        found_entry |= function == "rust_experiment";
        maximum = Some(maximum.map_or(size, |current| current.max(size)));
    }
    let maximum = maximum.ok_or_else(|| "probe ELF has no stack-size records".to_owned())?;
    if !found_entry {
        return Err("probe ELF has no rust_experiment stack-size record".to_owned());
    }
    if maximum > USB_PROBE_MAX_STACK_BYTES {
        return Err(format!(
            "probe stack requirement {maximum} exceeds {USB_PROBE_MAX_STACK_BYTES} bytes"
        ));
    }
    Ok(maximum)
}

fn format_sha256(digest: [u8; 32]) -> Result<String, String> {
    use core::fmt::Write as _;

    let mut text = String::with_capacity(64);
    for byte in digest {
        write!(text, "{byte:02x}")
            .map_err(|error| format!("could not format SHA-256 digest: {error}"))?;
    }
    Ok(text)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedProbeReport {
    container_bytes: usize,
    container_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    payload_crc: u32,
}

fn pack_usb_probe(code: &[u8], artifact_dir: &Path) -> Result<PackedProbeReport, String> {
    let container = slimblade_verify::recovery_stub::build(code)
        .map_err(|error| format!("could not pack USB probe: {error}"))?;
    if !USB_RECOVERY_PROBE_ARTIFACT.code_matches(code) {
        return Err("USB probe code differs from its reviewed identity".to_owned());
    }
    let embedded_code = container
        .get(slimblade_image::APPLICATION_CODE_OFFSET..)
        .and_then(|payload| payload.get(..code.len()))
        .ok_or_else(|| "packed USB probe does not contain its complete code".to_owned())?;
    if embedded_code != code {
        return Err("packed USB probe code differs from the audited binary".to_owned());
    }
    let payload = container
        .get(APPLICATION_PREFIX_OFFSET..)
        .ok_or_else(|| "packed USB probe has no updater payload".to_owned())?;
    let report = PackedProbeReport {
        container_bytes: container.len(),
        container_sha256: sha256(&container),
        payload_sha256: sha256(payload),
        payload_crc: updater_crc32(payload),
    };
    USB_RECOVERY_PROBE.validate(&container).map_err(|error| {
        format!(
            "USB probe container identity failed: {error}; actual container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
            format_sha256(report.container_sha256).unwrap_or_else(|_| "unavailable".to_owned()),
            format_sha256(report.payload_sha256).unwrap_or_else(|_| "unavailable".to_owned()),
            report.payload_crc,
        )
    })?;
    let path = artifact_dir.join("DO_NOT_FLASH-usb-recovery-probe.container.bin");
    fs::write(&path, container)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    Ok(report)
}

fn compile_usb_probe(firmware: &Path) -> Result<(), String> {
    run(firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--bin",
            USB_PROBE_BINARY,
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "build",
            "--release",
            "--bin",
            USB_PROBE_BINARY,
        ],
    )
}

fn build_usb_probe(root: &Path) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-usb-probe");
    compile_usb_probe(&firmware)?;

    let elf = firmware
        .join("target/thumbv5te-none-eabi/release")
        .join(USB_PROBE_BINARY);
    let artifact_dir = firmware.join("target/probe");
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let code_path = artifact_dir.join("DO_NOT_FLASH-usb-recovery-probe.code.bin");
    eprintln!(
        "+ llvm-objcopy -O binary {} {}",
        elf.display(),
        code_path.display()
    );
    let status = Command::new("llvm-objcopy")
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&code_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objcopy: {error}"))?;
    if !status.success() {
        return Err(format!("llvm-objcopy exited with {status}"));
    }

    let code = fs::read(&code_path)
        .map_err(|error| format!("could not read {}: {error}", code_path.display()))?;
    let guard_path =
        root.join("firmware/bk3635-rs/target/guard/DO_NOT_FLASH-rust-marker-first-guard.code.bin");
    let guard = fs::read(&guard_path)
        .map_err(|error| format!("could not read {}: {error}", guard_path.display()))?;
    let report = audit_code(&code, &guard)
        .map_err(|error| format!("USB probe binary audit failed: {error}"))?;

    let elf_text = elf.to_string_lossy().into_owned();
    let defined = llvm_nm(root, &elf_text, "--defined-only")?;
    let undefined = llvm_nm(root, &elf_text, "--undefined-only")?;
    let symbols = audit_nm_outputs(&defined, &undefined)
        .map_err(|error| format!("USB probe symbol audit failed: {error}"))?;
    let sized_symbols = command_output(
        root,
        "llvm-nm",
        &[
            "-S".to_owned(),
            "--defined-only".to_owned(),
            elf_text.clone(),
        ],
    )?;
    let executable_end = experiment_executable_end(&sized_symbols)?;

    let disassembly = command_output(
        root,
        "llvm-objdump",
        &[
            "-d".to_owned(),
            "--triple=thumbv5te-none-eabi".to_owned(),
            format!("--start-address={EXPERIMENT_ADDRESS:#x}"),
            format!("--stop-address={executable_end:#x}"),
            elf_text.clone(),
        ],
    )?;
    let mmio_literals = audit_probe_disassembly(&disassembly, &code, executable_end)?;

    let stack_sizes = command_output(
        root,
        "llvm-readelf",
        &["--stack-sizes".to_owned(), elf_text],
    )?;
    let maximum_stack = audit_probe_stack_sizes(&stack_sizes)?;
    let packed = pack_usb_probe(&code, &artifact_dir)?;
    eprintln!(
        "USB probe PASS: {} code bytes, {} experiment bytes, {} reviewed MMIO literals, {} defined symbols, max stack {} bytes, code SHA-256 {}",
        report.code_bytes,
        report.experiment_bytes,
        mmio_literals,
        symbols.defined_symbols,
        maximum_stack,
        format_sha256(sha256(&code))?
    );
    eprintln!(
        "USB probe container: {} bytes, SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        packed.container_bytes,
        format_sha256(packed.container_sha256)?,
        format_sha256(packed.payload_sha256)?,
        packed.payload_crc
    );
    Ok(())
}

fn build_stock_harness(root: &Path) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-stock-harness");
    run(&firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--bin",
            STOCK_HARNESS_BINARY,
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "build",
            "--release",
            "--bin",
            STOCK_HARNESS_BINARY,
        ],
    )?;

    let elf = firmware
        .join("target/thumbv5te-none-eabi/release")
        .join(STOCK_HARNESS_BINARY);
    let artifact_dir = firmware.join("target/harness");
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let injection_path = artifact_dir.join("DO_NOT_FLASH-stock-harness.injection.bin");
    let container_path = artifact_dir.join("DO_NOT_FLASH-stock-harness.container.bin");
    eprintln!(
        "+ llvm-objcopy -O binary {} {}",
        elf.display(),
        injection_path.display()
    );
    let status = Command::new("llvm-objcopy")
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&injection_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objcopy: {error}"))?;
    if !status.success() {
        return Err(format!("llvm-objcopy exited with {status}"));
    }

    let injection = fs::read(&injection_path)
        .map_err(|error| format!("could not read {}: {error}", injection_path.display()))?;
    if !STOCK_HARNESS_ARTIFACT.code_matches(&injection) {
        return Err("stock-harness injection differs from its reviewed identity".to_owned());
    }
    let elf_text = elf.to_string_lossy().into_owned();
    let defined = llvm_nm(root, &elf_text, "--defined-only")?;
    let undefined = llvm_nm(root, &elf_text, "--undefined-only")?;
    let symbols = audit_nm_outputs(&defined, &undefined)
        .map_err(|error| format!("stock-harness symbol audit failed: {error}"))?;

    let base_path = root.join(
        "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
    );
    let base = fs::read(&base_path).map_err(|error| {
        format!(
            "could not read exact v4.53 base {}: {error}",
            base_path.display()
        )
    })?;
    let container = stock_harness::build(&base, &injection)
        .map_err(|error| format!("could not pack stock harness: {error}"))?;
    let elf_bytes =
        fs::read(&elf).map_err(|error| format!("could not read {}: {error}", elf.display()))?;
    let report = stock_harness::verify(&base, &container, &injection, &elf_bytes)
        .map_err(|error| format!("stock-harness audit failed: {error}"))?;
    fs::write(&container_path, &container)
        .map_err(|error| format!("could not write {}: {error}", container_path.display()))?;

    eprintln!(
        "stock harness PASS: {} injection bytes, {} defined symbols, injection SHA-256 {}",
        report.injection_bytes,
        symbols.defined_symbols,
        format_sha256(report.injection_sha256)?
    );
    eprintln!(
        "stock harness container: {} bytes, SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        report.container_bytes,
        format_sha256(report.container_sha256)?,
        format_sha256(report.payload_sha256)?,
        report.payload_crc
    );
    Ok(())
}

fn build_late_marker_probe(root: &Path) -> Result<(), String> {
    build_stock_marker_probe(
        root,
        LATE_MARKER_PROBE_BINARY,
        "late-marker",
        "late-marker-probe",
        "late marker",
        LATE_MARKER_PROBE_ARTIFACT,
        late_marker_probe::build,
        late_marker_probe::verify,
    )
}

fn build_experiment_entry_probe(root: &Path) -> Result<(), String> {
    build_stock_marker_probe(
        root,
        EXPERIMENT_ENTRY_PROBE_BINARY,
        "experiment-entry",
        "experiment-entry-probe",
        "experiment entry",
        EXPERIMENT_ENTRY_PROBE_ARTIFACT,
        experiment_entry_probe::build,
        experiment_entry_probe::verify,
    )
}

fn build_rust_response_probe(root: &Path) -> Result<(), String> {
    build_stock_marker_probe(
        root,
        RUST_RESPONSE_PROBE_BINARY,
        "rust-response",
        "rust-response-probe",
        "Rust response",
        RUST_RESPONSE_PROBE_ARTIFACT,
        rust_response_probe::build,
        rust_response_probe::verify,
    )
}

fn build_post_init_hook_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        POST_INIT_HOOK_PROBE_BINARY,
        "post-init-hook",
        "post-init-hook-probe",
        "post-init hook",
        POST_INIT_HOOK_PROBE_ARTIFACT,
        post_init_hook_probe::build,
        post_init_hook_probe::verify,
    )
}

fn build_wired_loop_hook_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        WIRED_LOOP_HOOK_PROBE_BINARY,
        "wired-loop-hook",
        "wired-loop-hook-probe",
        "wired-loop hook",
        WIRED_LOOP_HOOK_PROBE_ARTIFACT,
        post_init_hook_probe::build_wired,
        post_init_hook_probe::verify_wired,
    )
}

fn build_active_loop_hook_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        ACTIVE_LOOP_HOOK_PROBE_BINARY,
        "active-loop-hook",
        "active-loop-hook-probe",
        "active-loop hook",
        ACTIVE_LOOP_HOOK_PROBE_ARTIFACT,
        post_init_hook_probe::build_active,
        post_init_hook_probe::verify_active,
    )
}

fn build_steady_loop_hook_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        STEADY_LOOP_HOOK_PROBE_BINARY,
        "steady-loop-hook",
        "steady-loop-hook-probe",
        "steady-loop hook",
        STEADY_LOOP_HOOK_PROBE_ARTIFACT,
        post_init_hook_probe::build_steady,
        post_init_hook_probe::verify_steady,
    )
}

fn build_dispatcher_return_hook_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        DISPATCHER_RETURN_HOOK_PROBE_BINARY,
        "dispatcher-return-hook",
        "dispatcher-return-hook-probe",
        "dispatcher-return hook",
        DISPATCHER_RETURN_HOOK_PROBE_ARTIFACT,
        post_init_hook_probe::build_dispatcher_return,
        post_init_hook_probe::verify_dispatcher_return,
    )
}

fn build_experiment_dispatch_guard(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        EXPERIMENT_DISPATCH_GUARD_BINARY,
        "experiment-dispatch-guard",
        "experiment-dispatch-guard",
        "experiment-dispatch guard",
        EXPERIMENT_DISPATCH_GUARD_ARTIFACT,
        post_init_hook_probe::build_experiment_dispatch,
        post_init_hook_probe::verify_experiment_dispatch,
    )
}

fn build_unsolicited_report_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        UNSOLICITED_REPORT_PROBE_BINARY,
        "unsolicited-report-probe",
        "unsolicited-report-probe",
        "unsolicited report",
        UNSOLICITED_REPORT_PROBE_ARTIFACT,
        post_init_hook_probe::build_unsolicited_report_probe,
        post_init_hook_probe::verify_unsolicited_report_probe,
    )
}

fn build_custom_main_handoff_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        CUSTOM_MAIN_HANDOFF_PROBE_BINARY,
        "custom-main-handoff",
        "custom-main-handoff-probe",
        "custom main handoff",
        CUSTOM_MAIN_HANDOFF_PROBE_ARTIFACT,
        post_init_hook_probe::build_custom_main_handoff_probe,
        post_init_hook_probe::verify_custom_main_handoff_probe,
    )
}

fn build_custom_main_usb_recovery_probe(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        CUSTOM_MAIN_USB_RECOVERY_PROBE_BINARY,
        "custom-main-usb-recovery",
        "custom-main-usb-recovery-probe",
        "custom main USB recovery",
        CUSTOM_MAIN_USB_RECOVERY_PROBE_ARTIFACT,
        post_init_hook_probe::build_custom_main_usb_recovery_probe,
        post_init_hook_probe::verify_custom_main_usb_recovery_probe,
    )
}

fn build_custom_main_stream_transport_probe(root: &Path) -> Result<(), String> {
    build_runtime_hook_probe(
        root,
        CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_BINARY,
        "custom-main-stream-transport",
        "custom-main-stream-transport-probe",
        "custom main stream transport",
        CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_ARTIFACT,
        CUSTOM_MAIN_STREAM_TRANSPORT_RUNTIME_ARTIFACT,
        post_init_hook_probe::build_custom_main_stream_transport_probe,
        post_init_hook_probe::verify_custom_main_stream_transport_probe,
    )
}

fn build_custom_main_sensor_stream_probe(root: &Path) -> Result<(), String> {
    build_sensor_runtime_probe(
        root,
        CUSTOM_MAIN_SENSOR_STREAM_PROBE_BINARY,
        "custom-main-sensor-stream",
        "custom-main-sensor-stream-probe",
        "custom main sensor stream",
        CUSTOM_MAIN_SENSOR_STREAM_PROBE_ARTIFACT,
        CUSTOM_MAIN_SENSOR_STREAM_RUNTIME_ARTIFACT,
        CUSTOM_MAIN_SENSOR_STREAM_SUPPORT_ARTIFACT,
        post_init_hook_probe::build_custom_main_sensor_stream_probe,
        post_init_hook_probe::verify_custom_main_sensor_stream_probe,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the three independently locked firmware regions remain explicit"
)]
fn build_sensor_runtime_probe(
    root: &Path,
    binary: &str,
    artifact_directory: &str,
    artifact_stem: &str,
    label: &str,
    injection_artifact: ArtifactIdentity,
    runtime_artifact: ArtifactIdentity,
    support_artifact: ArtifactIdentity,
    build: SensorRuntimeBuild,
    verify: SensorRuntimeVerify,
) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-stock-harness");
    run(&firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--bin",
            binary,
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &firmware,
        "cargo",
        &[FIRMWARE_TOOLCHAIN, "build", "--release", "--bin", binary],
    )?;

    let elf = firmware
        .join("target/thumbv5te-none-eabi/release")
        .join(binary);
    let artifact_dir = firmware.join("target").join(artifact_directory);
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let injection_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.injection.bin"));
    let runtime_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.runtime.bin"));
    let support_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.sensor.bin"));
    let container_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.container.bin"));

    for (path, sections) in [
        (&injection_path, &[".carrier", ".probe", ".trampoline"][..]),
        (&runtime_path, &[".custom_runtime"][..]),
        (&support_path, &[".sensor_hook", ".sensor_support"][..]),
    ] {
        let mut command = Command::new("llvm-objcopy");
        command.args(["-O", "binary"]);
        for section in sections {
            command.arg(format!("--only-section={section}"));
        }
        let status = command
            .arg(&elf)
            .arg(path)
            .current_dir(root)
            .status()
            .map_err(|error| format!("could not extract {}: {error}", path.display()))?;
        if !status.success() {
            return Err(format!("llvm-objcopy exited with {status}"));
        }
    }

    let injection = fs::read(&injection_path)
        .map_err(|error| format!("could not read {}: {error}", injection_path.display()))?;
    let runtime = fs::read(&runtime_path)
        .map_err(|error| format!("could not read {}: {error}", runtime_path.display()))?;
    let support = fs::read(&support_path)
        .map_err(|error| format!("could not read {}: {error}", support_path.display()))?;
    for (name, artifact, code) in [
        ("injection", injection_artifact, injection.as_slice()),
        ("runtime", runtime_artifact, runtime.as_slice()),
        ("sensor support", support_artifact, support.as_slice()),
    ] {
        if !artifact.code_matches(code) {
            return Err(format!("{label} {name} identity changed"));
        }
    }

    let elf_text = elf.to_string_lossy().into_owned();
    let defined = llvm_nm(root, &elf_text, "--defined-only")?;
    let undefined = llvm_nm(root, &elf_text, "--undefined-only")?;
    let symbols = audit_nm_outputs(&defined, &undefined)
        .map_err(|error| format!("{label} symbol audit failed: {error}"))?;
    let base_path = root.join(
        "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
    );
    let base = fs::read(&base_path)
        .map_err(|error| format!("could not read {}: {error}", base_path.display()))?;
    let container = build(&base, &injection, &runtime, &support)
        .map_err(|error| format!("could not pack {label} probe: {error}"))?;
    let payload = container
        .get(APPLICATION_PREFIX_OFFSET..)
        .ok_or_else(|| format!("{label} container has no updater payload"))?;
    eprintln!(
        "{label} candidate: {} bytes, injection SHA-256 {}, runtime SHA-256 {}, support SHA-256 {}, container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        container.len(),
        format_sha256(sha256(&injection))?,
        format_sha256(sha256(&runtime))?,
        format_sha256(sha256(&support))?,
        format_sha256(sha256(&container))?,
        format_sha256(sha256(payload))?,
        updater_crc32(payload)
    );

    let elf_bytes =
        fs::read(&elf).map_err(|error| format!("could not read {}: {error}", elf.display()))?;
    let report = verify(
        &base, &container, &injection, &runtime, &support, &elf_bytes,
    )
    .map_err(|error| format!("{label} audit failed: {error}"))?;
    fs::write(&container_path, &container)
        .map_err(|error| format!("could not write {}: {error}", container_path.display()))?;
    eprintln!(
        "{label} PASS: {} defined symbols, container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        symbols.defined_symbols,
        format_sha256(report.container_sha256)?,
        format_sha256(report.payload_sha256)?,
        report.payload_crc
    );
    Ok(())
}

fn build_input_diagnostics(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        INPUT_DIAGNOSTICS_BINARY,
        "input-diagnostics",
        "input-diagnostics",
        "input diagnostics",
        INPUT_DIAGNOSTICS_ARTIFACT,
        post_init_hook_probe::build_input_diagnostics,
        post_init_hook_probe::verify_input_diagnostics,
    )
}

fn build_paged_input_diagnostics(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        PAGED_INPUT_DIAGNOSTICS_BINARY,
        "paged-input-diagnostics",
        "paged-input-diagnostics",
        "paged input diagnostics",
        PAGED_INPUT_DIAGNOSTICS_ARTIFACT,
        post_init_hook_probe::build_paged_input_diagnostics,
        post_init_hook_probe::verify_paged_input_diagnostics,
    )
}

fn build_sensor_shadow_diagnostics(root: &Path) -> Result<(), String> {
    build_hook_probe(
        root,
        SENSOR_SHADOW_DIAGNOSTICS_BINARY,
        "sensor-shadow-diagnostics",
        "sensor-shadow-diagnostics",
        "sensor shadow diagnostics",
        SENSOR_SHADOW_DIAGNOSTICS_ARTIFACT,
        post_init_hook_probe::build_sensor_shadow_diagnostics,
        post_init_hook_probe::verify_sensor_shadow_diagnostics,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the runtime probe builder keeps both independently locked code regions explicit"
)]
fn build_runtime_hook_probe(
    root: &Path,
    binary: &str,
    artifact_directory: &str,
    artifact_stem: &str,
    label: &str,
    injection_artifact: ArtifactIdentity,
    runtime_artifact: ArtifactIdentity,
    build: RuntimeHookBuild,
    verify: RuntimeHookVerify,
) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-stock-harness");
    run(&firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--bin",
            binary,
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &firmware,
        "cargo",
        &[FIRMWARE_TOOLCHAIN, "build", "--release", "--bin", binary],
    )?;

    let elf = firmware
        .join("target/thumbv5te-none-eabi/release")
        .join(binary);
    let artifact_dir = firmware.join("target").join(artifact_directory);
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let injection_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.injection.bin"));
    let runtime_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.runtime.bin"));
    let container_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.container.bin"));

    let injection_status = Command::new("llvm-objcopy")
        .args([
            "-O",
            "binary",
            "--only-section=.carrier",
            "--only-section=.probe",
            "--only-section=.trampoline",
        ])
        .arg(&elf)
        .arg(&injection_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not extract {}: {error}", injection_path.display()))?;
    if !injection_status.success() {
        return Err(format!("llvm-objcopy exited with {injection_status}"));
    }
    let runtime_status = Command::new("llvm-objcopy")
        .args(["-O", "binary", "--only-section=.custom_runtime"])
        .arg(&elf)
        .arg(&runtime_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not extract {}: {error}", runtime_path.display()))?;
    if !runtime_status.success() {
        return Err(format!("llvm-objcopy exited with {runtime_status}"));
    }

    let injection = fs::read(&injection_path)
        .map_err(|error| format!("could not read {}: {error}", injection_path.display()))?;
    if !injection_artifact.code_matches(&injection) {
        return Err(format!("{label} injection identity changed"));
    }
    let runtime = fs::read(&runtime_path)
        .map_err(|error| format!("could not read {}: {error}", runtime_path.display()))?;
    if !runtime_artifact.code_matches(&runtime) {
        return Err(format!("{label} runtime identity changed"));
    }

    let elf_text = elf.to_string_lossy().into_owned();
    let defined = llvm_nm(root, &elf_text, "--defined-only")?;
    let undefined = llvm_nm(root, &elf_text, "--undefined-only")?;
    let symbols = audit_nm_outputs(&defined, &undefined)
        .map_err(|error| format!("{label} symbol audit failed: {error}"))?;
    let base_path = root.join(
        "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
    );
    let base = fs::read(&base_path)
        .map_err(|error| format!("could not read {}: {error}", base_path.display()))?;
    let container = build(&base, &injection, &runtime)
        .map_err(|error| format!("could not pack {label} probe: {error}"))?;
    let payload = container
        .get(APPLICATION_PREFIX_OFFSET..)
        .ok_or_else(|| format!("{label} container has no updater payload"))?;
    eprintln!(
        "{label} candidate: {} bytes, injection SHA-256 {}, runtime SHA-256 {}, container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        container.len(),
        format_sha256(sha256(&injection))?,
        format_sha256(sha256(&runtime))?,
        format_sha256(sha256(&container))?,
        format_sha256(sha256(payload))?,
        updater_crc32(payload)
    );

    let elf_bytes =
        fs::read(&elf).map_err(|error| format!("could not read {}: {error}", elf.display()))?;
    let report = verify(&base, &container, &injection, &runtime, &elf_bytes)
        .map_err(|error| format!("{label} audit failed: {error}"))?;
    fs::write(&container_path, &container)
        .map_err(|error| format!("could not write {}: {error}", container_path.display()))?;
    eprintln!(
        "{label} PASS: {} defined symbols, injection SHA-256 {}, runtime SHA-256 {}, container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        symbols.defined_symbols,
        format_sha256(report.injection_sha256)?,
        format_sha256(sha256(&runtime))?,
        format_sha256(report.container_sha256)?,
        format_sha256(report.payload_sha256)?,
        report.payload_crc
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the hook builder keeps each locked artifact parameter explicit at its call site"
)]
fn build_hook_probe(
    root: &Path,
    binary: &str,
    artifact_directory: &str,
    artifact_stem: &str,
    label: &str,
    artifact: ArtifactIdentity,
    build: HookBuild,
    verify: HookVerify,
) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-stock-harness");
    run(&firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--bin",
            binary,
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &firmware,
        "cargo",
        &[FIRMWARE_TOOLCHAIN, "build", "--release", "--bin", binary],
    )?;

    let elf = firmware
        .join("target/thumbv5te-none-eabi/release")
        .join(binary);
    let artifact_dir = firmware.join("target").join(artifact_directory);
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let injection_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.injection.bin"));
    let container_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.container.bin"));
    let objcopy = Command::new("llvm-objcopy")
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&injection_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objcopy: {error}"))?;
    if !objcopy.success() {
        return Err(format!("llvm-objcopy exited with {objcopy}"));
    }
    let injection = fs::read(&injection_path)
        .map_err(|error| format!("could not read {}: {error}", injection_path.display()))?;
    if !artifact.code_matches(&injection) {
        return Err(format!("{label} injection identity changed"));
    }
    let elf_text = elf.to_string_lossy().into_owned();
    let defined = llvm_nm(root, &elf_text, "--defined-only")?;
    let undefined = llvm_nm(root, &elf_text, "--undefined-only")?;
    let symbols = audit_nm_outputs(&defined, &undefined)
        .map_err(|error| format!("{label} symbol audit failed: {error}"))?;

    let base_path = root.join(
        "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
    );
    let base = fs::read(&base_path)
        .map_err(|error| format!("could not read {}: {error}", base_path.display()))?;
    let container = build(&base, &injection)
        .map_err(|error| format!("could not pack {label} probe: {error}"))?;
    let payload = container
        .get(APPLICATION_PREFIX_OFFSET..)
        .ok_or_else(|| format!("{label} container has no updater payload"))?;
    eprintln!(
        "{label} candidate: {} bytes, injection SHA-256 {}, container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        container.len(),
        format_sha256(sha256(&injection))?,
        format_sha256(sha256(&container))?,
        format_sha256(sha256(payload))?,
        updater_crc32(payload)
    );

    let elf_bytes =
        fs::read(&elf).map_err(|error| format!("could not read {}: {error}", elf.display()))?;
    let report = verify(&base, &container, &injection, &elf_bytes)
        .map_err(|error| format!("{label} audit failed: {error}"))?;
    fs::write(&container_path, &container)
        .map_err(|error| format!("could not write {}: {error}", container_path.display()))?;
    eprintln!(
        "{label} PASS: {} defined symbols, injection SHA-256 {}, container SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        symbols.defined_symbols,
        format_sha256(report.injection_sha256)?,
        format_sha256(report.container_sha256)?,
        format_sha256(report.payload_sha256)?,
        report.payload_crc
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the probe builder keeps each locked artifact parameter explicit at its call site"
)]
fn build_stock_marker_probe(
    root: &Path,
    binary: &str,
    artifact_directory: &str,
    artifact_stem: &str,
    label: &str,
    artifact: ArtifactIdentity,
    build: StockMarkerBuild,
    verify: StockMarkerVerify,
) -> Result<(), String> {
    let firmware = root.join("firmware/bk3635-stock-harness");
    run(&firmware, "cargo", &[FIRMWARE_TOOLCHAIN, "fmt", "--check"])?;
    run(
        &firmware,
        "cargo",
        &[
            FIRMWARE_TOOLCHAIN,
            "clippy",
            "--bin",
            binary,
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &firmware,
        "cargo",
        &[FIRMWARE_TOOLCHAIN, "build", "--release", "--bin", binary],
    )?;

    let elf = firmware
        .join("target/thumbv5te-none-eabi/release")
        .join(binary);
    let artifact_dir = firmware.join("target").join(artifact_directory);
    fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("could not create {}: {error}", artifact_dir.display()))?;
    let injection_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.injection.bin"));
    let container_path = artifact_dir.join(format!("DO_NOT_FLASH-{artifact_stem}.container.bin"));
    eprintln!(
        "+ llvm-objcopy -O binary {} {}",
        elf.display(),
        injection_path.display()
    );
    let objcopy = Command::new("llvm-objcopy")
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&injection_path)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objcopy: {error}"))?;
    if !objcopy.success() {
        return Err(format!("llvm-objcopy exited with {objcopy}"));
    }
    let injection = fs::read(&injection_path)
        .map_err(|error| format!("could not read {}: {error}", injection_path.display()))?;
    if !artifact.code_matches(&injection) {
        return Err(format!(
            "{label} injection differs from its reviewed identity"
        ));
    }
    let elf_text = elf.to_string_lossy().into_owned();
    let defined = llvm_nm(root, &elf_text, "--defined-only")?;
    let undefined = llvm_nm(root, &elf_text, "--undefined-only")?;
    let symbols = audit_nm_outputs(&defined, &undefined)
        .map_err(|error| format!("{label} symbol audit failed: {error}"))?;

    let base_path = root.join(
        "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
    );
    let base = fs::read(&base_path).map_err(|error| {
        format!(
            "could not read exact v4.53 base {}: {error}",
            base_path.display()
        )
    })?;
    let container = build(&base, &injection)
        .map_err(|error| format!("could not pack {label} probe: {error}"))?;
    let payload = container
        .get(APPLICATION_PREFIX_OFFSET..)
        .ok_or_else(|| format!("{label} container has no updater payload"))?;
    eprintln!(
        "{label} candidate: {} bytes, SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        container.len(),
        format_sha256(sha256(&container))?,
        format_sha256(sha256(payload))?,
        updater_crc32(payload)
    );
    let elf_bytes =
        fs::read(&elf).map_err(|error| format!("could not read {}: {error}", elf.display()))?;
    let report = verify(&base, &container, &injection, &elf_bytes)
        .map_err(|error| format!("{label} audit failed: {error}"))?;
    fs::write(&container_path, &container)
        .map_err(|error| format!("could not write {}: {error}", container_path.display()))?;
    eprintln!(
        "{label} PASS: {} injection bytes, {} defined symbols, injection SHA-256 {}",
        report.injection_bytes,
        symbols.defined_symbols,
        format_sha256(report.injection_sha256)?
    );
    eprintln!(
        "{label} container: {} bytes, SHA-256 {}, payload SHA-256 {}, payload CRC {:08x}",
        report.container_bytes,
        format_sha256(report.container_sha256)?,
        format_sha256(report.payload_sha256)?,
        report.payload_crc
    );
    Ok(())
}

fn parse_address(value: &str) -> Result<usize, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    digits
        .map_or_else(|| value.parse(), |hex| usize::from_str_radix(hex, 16))
        .map_err(|error| format!("invalid address {value:?}: {error}"))
}

fn disassemble_stock(
    root: &Path,
    firmware: &str,
    start: &str,
    stop: &str,
    state: &str,
) -> Result<(), String> {
    let firmware = Path::new(firmware);
    let image = fs::read(firmware)
        .map_err(|error| format!("could not read {}: {error}", firmware.display()))?;
    OFFICIAL_V449
        .validate(&image)
        .map_err(|error| format!("refusing image other than exact official v4.49: {error}"))?;
    let start = parse_address(start)?;
    let stop = parse_address(stop)?;
    if start >= stop || stop > image.len() {
        return Err(format!(
            "invalid disassembly range {start:#x}..{stop:#x} for {} bytes",
            image.len()
        ));
    }
    let triple = match state {
        "arm" => "armv5te-none-eabi",
        "thumb" => "thumbv5te-none-eabi",
        _ => return Err("state must be arm or thumb".to_owned()),
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    let elf = env::temp_dir().join(format!("slimblade-disasm-{}-{nonce}.elf", process::id()));
    let objcopy = Command::new("llvm-objcopy")
        .args(["-I", "binary", "-O", "elf32-littlearm", "-B", "arm"])
        .arg(firmware)
        .arg(&elf)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objcopy: {error}"))?;
    if !objcopy.success() {
        return Err(format!("llvm-objcopy exited with {objcopy}"));
    }
    let result = Command::new("llvm-objdump")
        .arg("-D")
        .arg(format!("--triple={triple}"))
        .arg(format!("--start-address={start:#x}"))
        .arg(format!("--stop-address={stop:#x}"))
        .arg(&elf)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run llvm-objdump: {error}"));
    let cleanup = fs::remove_file(&elf)
        .map_err(|error| format!("could not remove {}: {error}", elf.display()));
    let status = result?;
    cleanup?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("llvm-objdump exited with {status}"))
    }
}

fn usage() {
    eprintln!(
        "usage:\n  cargo xtask <check|rust-guard|usb-probe|stock-harness|late-marker-probe|experiment-entry-probe|rust-response-probe|post-init-hook-probe|wired-loop-hook-probe|active-loop-hook-probe|steady-loop-hook-probe|dispatcher-return-hook-probe|experiment-dispatch-guard|unsolicited-report-probe|custom-main-handoff-probe|custom-main-usb-recovery-probe|custom-main-stream-transport-probe|custom-main-sensor-stream-probe|input-diagnostics|paged-input-diagnostics|sensor-shadow-diagnostics|postlink|all>\n  cargo xtask disassemble-stock FIRMWARE START STOP <arm|thumb>"
    );
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let root = repository_root();
    let result = match arguments.as_slice() {
        [command] if command == "check" || command == "all" => host_checks(&root),
        [command] if command == "rust-guard" => build_rust_guard(&root),
        [command] if command == "usb-probe" => {
            build_rust_guard(&root).and_then(|()| build_usb_probe(&root))
        },
        [command] if command == "stock-harness" => build_stock_harness(&root),
        [command] if command == "late-marker-probe" => build_late_marker_probe(&root),
        [command] if command == "experiment-entry-probe" => build_experiment_entry_probe(&root),
        [command] if command == "rust-response-probe" => build_rust_response_probe(&root),
        [command] if command == "post-init-hook-probe" => build_post_init_hook_probe(&root),
        [command] if command == "wired-loop-hook-probe" => build_wired_loop_hook_probe(&root),
        [command] if command == "active-loop-hook-probe" => build_active_loop_hook_probe(&root),
        [command] if command == "steady-loop-hook-probe" => build_steady_loop_hook_probe(&root),
        [command] if command == "dispatcher-return-hook-probe" => {
            build_dispatcher_return_hook_probe(&root)
        },
        [command] if command == "experiment-dispatch-guard" => {
            build_experiment_dispatch_guard(&root)
        },
        [command] if command == "unsolicited-report-probe" => build_unsolicited_report_probe(&root),
        [command] if command == "custom-main-handoff-probe" => {
            build_custom_main_handoff_probe(&root)
        },
        [command] if command == "custom-main-usb-recovery-probe" => {
            build_custom_main_usb_recovery_probe(&root)
        },
        [command] if command == "custom-main-stream-transport-probe" => {
            build_custom_main_stream_transport_probe(&root)
        },
        [command] if command == "custom-main-sensor-stream-probe" => {
            build_custom_main_sensor_stream_probe(&root)
        },
        [command] if command == "input-diagnostics" => build_input_diagnostics(&root),
        [command] if command == "paged-input-diagnostics" => build_paged_input_diagnostics(&root),
        [command] if command == "sensor-shadow-diagnostics" => {
            build_sensor_shadow_diagnostics(&root)
        },
        [command] if command == "postlink" => post_link_checks(&root),
        [command, firmware, start, stop, state] if command == "disassemble-stock" => {
            disassemble_stock(&root, firmware, start, stop, state)
        },
        _ => {
            usage();
            return ExitCode::from(2);
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{audit_probe_disassembly, audit_probe_stack_sizes, experiment_executable_end};

    fn literal_code(second: u32) -> Vec<u8> {
        let mut code = vec![0; 16];
        code.extend_from_slice(&0x0080_0020_u32.to_le_bytes());
        code.extend_from_slice(&second.to_le_bytes());
        code.extend_from_slice(&0x0080_6520_u32.to_le_bytes());
        code
    }

    #[test]
    fn disassembly_audit_resolves_only_actual_pc_relative_literals() {
        let disassembly = "\
21c4: 4802 ldr r0, [pc, #0x8] @ 0x2030\n\
21c6: 4903 ldr r1, [pc, #0xc] @ 0x2034\n\
21c8: 4a04 ldr r2, [pc, #0x10] @ 0x2038\n\
21ca: 9005 str r0, [sp, #0x14]\n\
21cc: 0080 lsls r0, r0, #0x2\n";

        assert_eq!(
            audit_probe_disassembly(disassembly, &literal_code(0x0080_4000), 0x2200),
            Ok(3)
        );
    }

    #[test]
    fn disassembly_audit_rejects_unreviewed_mmio_and_computed_pc() {
        let loads = "\
21c4: 4802 ldr r0, [pc, #0x8] @ 0x2030\n\
21c6: 4903 ldr r1, [pc, #0xc] @ 0x2034\n\
21c8: 4a04 ldr r2, [pc, #0x10] @ 0x2038\n";
        assert!(audit_probe_disassembly(loads, &literal_code(0x0080_6000), 0x2200).is_err());
        assert!(audit_probe_disassembly("21c4: 4687 mov pc, r0\n", &[], 0x2200).is_err());
        assert!(audit_probe_disassembly("21c4: f000 f800 bl 0x2084\n", &[], 0x2200).is_err());
    }

    #[test]
    fn stack_audit_requires_entry_and_enforces_limit() {
        assert_eq!(
            audit_probe_stack_sizes("176 rust_experiment\n56 helper\n"),
            Ok(176)
        );
        assert!(audit_probe_stack_sizes("300 rust_experiment\n").is_err());
        assert!(audit_probe_stack_sizes("56 helper\n").is_err());
    }

    #[test]
    fn sized_text_symbols_bound_disassembly_before_rodata() {
        let symbols = "\
000021c4 00000844 T rust_experiment\n\
00002a08 000000f0 t apply_response\n\
00002bc4 0000009a t packet_for\n\
00002c5e 00000000 r descriptor_data\n";

        assert_eq!(experiment_executable_end(symbols), Ok(0x2c5e));
    }
}
