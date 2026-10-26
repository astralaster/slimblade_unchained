use core::fmt;

pub const MARKER_FIRST_PREFIX_LENGTH: usize = 420;
pub const EXPERIMENT_ADDRESS: u32 = 0x0000_21c4;

const FORBIDDEN_WORDS: &[u32] = &[
    0x0000_807c,
    0x0080_3000,
    0x0080_3008,
    0x19d2_bc9a,
    0x7856_3412,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeAuditReport {
    pub code_bytes: usize,
    pub experiment_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeAuditError {
    GuardTooShort { actual: usize },
    ProbeTooShort { actual: usize },
    MarkerPrefixChanged,
    ForbiddenWord { offset: usize, word: u32 },
}

impl fmt::Display for ProbeAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuardTooShort { actual } => write!(
                formatter,
                "guard is {actual} bytes, shorter than the marker-first prefix"
            ),
            Self::ProbeTooShort { actual } => write!(
                formatter,
                "probe is {actual} bytes and has no post-marker experiment"
            ),
            Self::MarkerPrefixChanged => formatter.write_str("live-tested marker prefix changed"),
            Self::ForbiddenWord { offset, word } => write!(
                formatter,
                "forbidden word {word:#010x} at experiment offset {offset:#x}"
            ),
        }
    }
}

impl core::error::Error for ProbeAuditError {}

/// Checks prefix identity and rejects storage, marker, and reset-controller words.
///
/// # Errors
///
/// Returns an error if the live marker prefix differs or a forbidden word occurs
/// after it. ELF-aware tooling separately audits actual PC-relative MMIO loads;
/// raw instruction bytes cannot safely be classified as address literals.
pub fn audit_code(probe: &[u8], live_guard: &[u8]) -> Result<ProbeAuditReport, ProbeAuditError> {
    let Some(guard_prefix) = live_guard.get(..MARKER_FIRST_PREFIX_LENGTH) else {
        return Err(ProbeAuditError::GuardTooShort {
            actual: live_guard.len(),
        });
    };
    let Some(probe_prefix) = probe.get(..MARKER_FIRST_PREFIX_LENGTH) else {
        return Err(ProbeAuditError::ProbeTooShort {
            actual: probe.len(),
        });
    };
    if probe_prefix != guard_prefix {
        return Err(ProbeAuditError::MarkerPrefixChanged);
    }
    let Some(experiment) = probe.get(MARKER_FIRST_PREFIX_LENGTH..) else {
        return Err(ProbeAuditError::ProbeTooShort {
            actual: probe.len(),
        });
    };
    if experiment.is_empty() {
        return Err(ProbeAuditError::ProbeTooShort {
            actual: probe.len(),
        });
    }

    for (offset, window) in experiment.windows(4).enumerate() {
        let Ok(bytes) = <[u8; 4]>::try_from(window) else {
            continue;
        };
        let word = u32::from_le_bytes(bytes);
        if FORBIDDEN_WORDS.contains(&word) {
            return Err(ProbeAuditError::ForbiddenWord { offset, word });
        }
    }

    Ok(ProbeAuditReport {
        code_bytes: probe.len(),
        experiment_bytes: experiment.len(),
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use explicit panic sites to keep failure diagnostics local"
)]
mod tests {
    use super::{MARKER_FIRST_PREFIX_LENGTH, ProbeAuditError, audit_code};

    fn valid_images() -> (Vec<u8>, Vec<u8>) {
        let guard = vec![0x5a; MARKER_FIRST_PREFIX_LENGTH + 2];
        let mut probe = vec![0x5a; MARKER_FIRST_PREFIX_LENGTH];
        probe.extend_from_slice(&0x0080_000c_u32.to_le_bytes());
        (probe, guard)
    }

    #[test]
    fn exact_prefix_passes() {
        let (probe, guard) = valid_images();
        let report = audit_code(&probe, &guard).expect("valid synthetic probe");

        assert_eq!(report.experiment_bytes, 4);
    }

    #[test]
    fn prefix_change_is_rejected() {
        let (mut probe, guard) = valid_images();
        probe[0] ^= 1;

        assert_eq!(
            audit_code(&probe, &guard),
            Err(ProbeAuditError::MarkerPrefixChanged)
        );
    }

    #[test]
    fn storage_and_marker_words_are_rejected() {
        let (mut storage, guard) = valid_images();
        storage.extend_from_slice(&0x0080_3000_u32.to_le_bytes());
        assert!(matches!(
            audit_code(&storage, &guard),
            Err(ProbeAuditError::ForbiddenWord {
                word: 0x0080_3000,
                ..
            })
        ));

        let (mut marker, guard) = valid_images();
        marker.extend_from_slice(&0x19d2_bc9a_u32.to_le_bytes());
        assert!(matches!(
            audit_code(&marker, &guard),
            Err(ProbeAuditError::ForbiddenWord {
                word: 0x19d2_bc9a,
                ..
            })
        ));
    }
}
