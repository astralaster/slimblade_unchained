use slimblade_image::{RUST_RESPONSE_PROBE, RUST_RESPONSE_PROBE_ARTIFACT};

use crate::{
    ThumbAddress, decode_thumb_bl,
    late_marker_probe::{
        BuildError, LateMarkerReport, ProbeSpec, VerificationError, build_with_spec,
        verify_with_spec,
    },
    recovery_guard::verify_experiment_storage_isolation,
};

const RUST_PROBE_OFFSET: usize = 0x114;
const RUST_PROBE_END: usize = 0x11c;
const RUST_PROBE_ADDRESS: u32 = 0x22c0;
const SHIM_CALL_OFFSET: usize = 0x1a;
const SHIM_CALL_ADDRESS: u32 = 0x21c6;

const SPEC: ProbeSpec = ProbeSpec {
    artifact: RUST_RESPONSE_PROBE_ARTIFACT,
    identity: RUST_RESPONSE_PROBE,
    dispatch: [
        0x0d, 0x28, 0x03, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x70, 0x47, 0xc0, 0x46, 0x31, 0x4b, 0x18,
        0x47, 0xc0, 0x46,
    ],
    marker_entry_tail: [0xff, 0xe7],
    response_shim: Some([0x00, 0xf0, 0x7b, 0xf8, 0xe0, 0x70, 0x10, 0xbd]),
    gap: [
        0x80, 0xb5, 0x00, 0xaf, 0x58, 0x20, 0x80, 0xbd, 0x00, 0x00, 0x00, 0x00,
    ],
    probe_section_size: 8,
    device_version_low: 0x58,
    usb_bcd_device: 0x0458,
};

/// Builds the marker-first Rust response probe from the exact v4.53 base.
///
/// # Errors
///
/// Returns an error for any base, injection, branch, layout, or header mismatch.
pub fn build(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, BuildError> {
    build_with_spec(base, injection, SPEC)
}

/// Audits the complete response probe and its isolated Rust function.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, container, ELF, or isolation invariant.
pub fn verify(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<LateMarkerReport, VerificationError> {
    let report = verify_with_spec(base, image, injection, elf_bytes, SPEC)?;
    let call = injection
        .get(SHIM_CALL_OFFSET..SHIM_CALL_OFFSET + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or(VerificationError::WordUnavailable {
            offset: SHIM_CALL_OFFSET,
        })?;
    let target = decode_thumb_bl(
        call,
        ThumbAddress::new(SHIM_CALL_ADDRESS).map_err(VerificationError::Branch)?,
    )
    .map_err(VerificationError::Branch)?;
    if target.get() != RUST_PROBE_ADDRESS {
        return Err(VerificationError::BytesChanged {
            offset: SHIM_CALL_OFFSET,
        });
    }
    verify_experiment_storage_isolation(injection, RUST_PROBE_OFFSET, RUST_PROBE_END).map_err(
        |_| VerificationError::BytesChanged {
            offset: RUST_PROBE_OFFSET,
        },
    )?;
    Ok(report)
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
        late_marker_injection: Vec<u8>,
        container: Vec<u8>,
        elf: Vec<u8>,
    }

    fn read_if_present(path: PathBuf) -> Option<Vec<u8>> {
        path.exists()
            .then(|| std::fs::read(path).expect("read Rust-response fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(
                target.join("rust-response/DO_NOT_FLASH-rust-response-probe.injection.bin"),
            )?,
            late_marker_injection: read_if_present(
                target.join("late-marker/DO_NOT_FLASH-late-marker-probe.injection.bin"),
            )?,
            container: read_if_present(
                target.join("rust-response/DO_NOT_FLASH-rust-response-probe.container.bin"),
            )?,
            elf: read_if_present(
                target.join("thumbv5te-none-eabi/release/slimblade-rust-response-probe"),
            )?,
        })
    }

    #[test]
    fn exact_probe_rebuilds_and_passes() {
        let Some(data) = fixtures() else { return };
        assert_eq!(
            build(&data.base, &data.injection),
            Ok(data.container.clone())
        );
        let report = verify(&data.base, &data.container, &data.injection, &data.elf)
            .expect("audit exact Rust-response probe");
        assert_eq!(report.usb_bcd_device, 0x0458);
    }

    #[test]
    fn marker_writer_bytes_are_identical_to_live_tested_probe() {
        let Some(data) = fixtures() else { return };
        assert_eq!(
            &data.injection[0x22..0x114],
            &data.late_marker_injection[0x22..0x114]
        );
    }

    #[test]
    fn changed_rust_return_value_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[0x118] ^= 1;
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::InjectionIdentity)
        ));
    }

    #[test]
    fn changed_shim_call_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[SHIM_CALL_OFFSET] ^= 1;
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::InjectionIdentity)
        ));
    }
}
