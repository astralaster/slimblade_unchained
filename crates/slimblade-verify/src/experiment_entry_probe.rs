use slimblade_image::{EXPERIMENT_ENTRY_PROBE, EXPERIMENT_ENTRY_PROBE_ARTIFACT};

use crate::late_marker_probe::{
    BuildError, LateMarkerReport, ProbeSpec, VerificationError, build_with_spec, verify_with_spec,
};

const SPEC: ProbeSpec = ProbeSpec {
    artifact: EXPERIMENT_ENTRY_PROBE_ARTIFACT,
    identity: EXPERIMENT_ENTRY_PROBE,
    dispatch: [
        0x0d, 0x28, 0x04, 0xd0, 0x0e, 0x28, 0x04, 0xd0, 0x0f, 0x28, 0x06, 0xd0, 0x06, 0xe0, 0x31,
        0x4b, 0x18, 0x47,
    ],
    marker_entry_tail: [0xfe, 0xe7],
    response_shim: None,
    gap: [0; 12],
    probe_section_size: 0,
    device_version_low: 0x57,
    usb_bcd_device: 0x0457,
};

/// Builds the marker-first experiment-entry probe from the exact v4.53 base.
///
/// # Errors
///
/// Returns an error for any base, injection, branch, layout, or header mismatch.
pub fn build(base: &[u8], injection: &[u8]) -> Result<Vec<u8>, BuildError> {
    build_with_spec(base, injection, SPEC)
}

/// Audits the complete experiment-entry probe, including marker-before-hang ordering.
///
/// # Errors
///
/// Returns the first failed identity, instruction, branch, container, or ELF invariant.
pub fn verify(
    base: &[u8],
    image: &[u8],
    injection: &[u8],
    elf_bytes: &[u8],
) -> Result<LateMarkerReport, VerificationError> {
    verify_with_spec(base, image, injection, elf_bytes, SPEC)
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
            .then(|| std::fs::read(path).expect("read experiment-entry fixture"))
    }

    fn fixtures() -> Option<Fixtures> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = root.join("firmware/bk3635-stock-harness/target");
        Some(Fixtures {
            base: read_if_present(root.join(
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            ))?,
            injection: read_if_present(target.join(
                "experiment-entry/DO_NOT_FLASH-experiment-entry-probe.injection.bin",
            ))?,
            late_marker_injection: read_if_present(
                target.join("late-marker/DO_NOT_FLASH-late-marker-probe.injection.bin"),
            )?,
            container: read_if_present(target.join(
                "experiment-entry/DO_NOT_FLASH-experiment-entry-probe.container.bin",
            ))?,
            elf: read_if_present(target.join(
                "thumbv5te-none-eabi/release/slimblade-experiment-entry-probe",
            ))?,
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
            .expect("audit exact experiment-entry probe");
        assert_eq!(report.result, "PASS");
        assert_eq!(report.late_marker_entry, 0x21be);
        assert_eq!(report.stock_resume_pointer, 0x2213);
        assert_eq!(report.usb_bcd_device, 0x0457);
    }

    #[test]
    fn injection_only_replaces_marker_return_with_hang() {
        let Some(data) = fixtures() else { return };
        let differences = data
            .late_marker_injection
            .iter()
            .zip(&data.injection)
            .enumerate()
            .filter_map(|(offset, (late, experiment))| (late != experiment).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(differences, [0x18, 0x19]);
        assert_eq!(&data.late_marker_injection[0x18..0x1a], &[0x10, 0xbd]);
        assert_eq!(&data.injection[0x18..0x1a], &[0xfe, 0xe7]);
    }

    #[test]
    fn return_after_marker_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.injection[0x18..0x1a].copy_from_slice(&[0x10, 0xbd]);
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::InjectionIdentity)
        ));
    }

    #[test]
    fn changed_base_is_rejected() {
        let Some(mut data) = fixtures() else { return };
        data.base[0] ^= 1;
        assert!(matches!(
            build(&data.base, &data.injection),
            Err(BuildError::BaseIdentity(_))
        ));
    }
}
