use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForbiddenSymbolKind {
    Allocation,
    CompilerHelper,
    PanicOrUnwind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolAuditReport {
    pub defined_symbols: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolAuditError<'output> {
    EmptyDefinedSymbolTable,
    ForbiddenSymbol {
        kind: ForbiddenSymbolKind,
        line: &'output str,
    },
    UndefinedSymbol {
        line: &'output str,
    },
}

impl fmt::Display for SymbolAuditError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDefinedSymbolTable => formatter.write_str("ELF has no defined symbols"),
            Self::ForbiddenSymbol { kind, line } => {
                write!(formatter, "forbidden {kind:?} symbol: {line}")
            },
            Self::UndefinedSymbol { line } => write!(formatter, "undefined symbol: {line}"),
        }
    }
}

impl core::error::Error for SymbolAuditError<'_> {}

/// Audits demangled `llvm-nm` output for firmware-hostile symbols.
///
/// # Errors
///
/// Returns an error if the defined table is empty, any symbol is unresolved, or a defined symbol
/// indicates panic/unwind machinery, allocation, or an unexpected compiler runtime helper.
pub fn audit_nm_outputs<'output>(
    defined: &'output str,
    undefined: &'output str,
) -> Result<SymbolAuditReport, SymbolAuditError<'output>> {
    if let Some(line) = undefined.lines().find(|line| !line.trim().is_empty()) {
        return Err(SymbolAuditError::UndefinedSymbol { line });
    }

    let mut defined_symbols = 0_usize;
    for line in defined.lines().filter(|line| !line.trim().is_empty()) {
        defined_symbols = defined_symbols.saturating_add(1);
        if let Some(kind) = forbidden_kind(line) {
            return Err(SymbolAuditError::ForbiddenSymbol { kind, line });
        }
    }
    if defined_symbols == 0 {
        return Err(SymbolAuditError::EmptyDefinedSymbolTable);
    }
    Ok(SymbolAuditReport { defined_symbols })
}

fn forbidden_kind(symbol_line: &str) -> Option<ForbiddenSymbolKind> {
    const PANIC_OR_UNWIND: &[&str] = &["panic", "unwind", "Unwind", "personality", "__cxa_throw"];
    const ALLOCATION: &[&str] = &[
        "alloc::",
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
    ];
    const COMPILER_HELPERS: &[&str] = &["bcmp", "memcmp", "memcpy", "memmove", "memset"];
    let symbol = symbol_line
        .split_ascii_whitespace()
        .nth(2)
        .unwrap_or(symbol_line);

    if symbol == "abort"
        || PANIC_OR_UNWIND
            .iter()
            .any(|pattern| symbol.contains(pattern))
    {
        Some(ForbiddenSymbolKind::PanicOrUnwind)
    } else if ALLOCATION.iter().any(|pattern| symbol.contains(pattern)) {
        Some(ForbiddenSymbolKind::Allocation)
    } else if symbol.starts_with("__") || COMPILER_HELPERS.contains(&symbol) {
        Some(ForbiddenSymbolKind::CompilerHelper)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE_SYMBOLS: &str =
        "00002020 T _vector_start\n00002050 t data_abort_vector\n00002080 T stub_main\n";

    #[test]
    fn accepts_small_self_contained_firmware() {
        assert_eq!(
            audit_nm_outputs(SAFE_SYMBOLS, ""),
            Ok(SymbolAuditReport { defined_symbols: 3 })
        );
    }

    #[test]
    fn rejects_empty_and_undefined_symbol_tables() {
        assert_eq!(
            audit_nm_outputs("", ""),
            Err(SymbolAuditError::EmptyDefinedSymbolTable)
        );
        assert!(matches!(
            audit_nm_outputs(SAFE_SYMBOLS, "         U external_call\n"),
            Err(SymbolAuditError::UndefinedSymbol { .. })
        ));
    }

    #[test]
    fn rejects_panic_allocation_and_compiler_helpers() {
        for (symbol, expected) in [
            (
                "00002000 T core::panicking::panic_fmt\n",
                ForbiddenSymbolKind::PanicOrUnwind,
            ),
            ("00002000 T __rust_alloc\n", ForbiddenSymbolKind::Allocation),
            (
                "00002000 T __aeabi_uidiv\n",
                ForbiddenSymbolKind::CompilerHelper,
            ),
            (
                "00002000 T __gnu_thumb1_case_uqi\n",
                ForbiddenSymbolKind::CompilerHelper,
            ),
        ] {
            assert!(matches!(
                audit_nm_outputs(symbol, ""),
                Err(SymbolAuditError::ForbiddenSymbol { kind, .. }) if kind == expected
            ));
        }
    }
}
