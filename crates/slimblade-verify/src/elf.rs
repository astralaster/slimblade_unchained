use core::{fmt, str};

pub const ELF32_HEADER_SIZE: usize = 52;
pub const ELF32_SECTION_HEADER_SIZE: usize = 40;
pub const ELF_TYPE_EXECUTABLE: u16 = 2;
pub const ELF_MACHINE_ARM: u16 = 40;
pub const SECTION_TYPE_RELA: u32 = 4;
pub const SECTION_TYPE_REL: u32 = 9;
pub const SECTION_FLAG_WRITE: u32 = 1;
pub const SECTION_FLAG_ALLOCATE: u32 = 2;
pub const SECTION_FLAG_EXECUTE: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elf32<'data> {
    data: &'data [u8],
    elf_type: u16,
    machine: u16,
    entry: u32,
    section_table_offset: usize,
    section_count: u16,
    names: &'data [u8],
}

impl<'data> Elf32<'data> {
    /// Parses a 32-bit little-endian ELF image and its section table.
    ///
    /// # Errors
    ///
    /// Returns an error when the ELF format, offsets, or section-name table are invalid.
    pub fn parse(data: &'data [u8]) -> Result<Self, ElfError> {
        if data.len() < ELF32_HEADER_SIZE {
            return Err(ElfError::TruncatedHeader { size: data.len() });
        }
        if data.get(..7) != Some(b"\x7fELF\x01\x01\x01") {
            return Err(ElfError::WrongFormat);
        }

        let section_table_offset = usize_from_u32(read_u32(data, 32)?)?;
        let section_entry_size = read_u16(data, 46)?;
        if usize::from(section_entry_size) != ELF32_SECTION_HEADER_SIZE {
            return Err(ElfError::UnexpectedSectionEntrySize {
                actual: section_entry_size,
            });
        }
        let section_count = read_u16(data, 48)?;
        let names_index = read_u16(data, 50)?;
        if section_count == 0 || names_index >= section_count {
            return Err(ElfError::InvalidSectionTable {
                count: section_count,
                names_index,
            });
        }
        let table_size = ELF32_SECTION_HEADER_SIZE
            .checked_mul(usize::from(section_count))
            .ok_or(ElfError::ArithmeticOverflow)?;
        let table_end = section_table_offset
            .checked_add(table_size)
            .ok_or(ElfError::ArithmeticOverflow)?;
        if table_end > data.len() {
            return Err(ElfError::TruncatedSectionTable {
                end: table_end,
                size: data.len(),
            });
        }

        let names_header = raw_section(data, section_table_offset, names_index)?;
        let names_offset = usize_from_u32(names_header.file_offset)?;
        let names_size = usize_from_u32(names_header.size)?;
        let names_end = names_offset
            .checked_add(names_size)
            .ok_or(ElfError::ArithmeticOverflow)?;
        let names = data
            .get(names_offset..names_end)
            .ok_or(ElfError::TruncatedSectionNames {
                end: names_end,
                size: data.len(),
            })?;

        Ok(Self {
            data,
            elf_type: read_u16(data, 16)?,
            machine: read_u16(data, 18)?,
            entry: read_u32(data, 24)?,
            section_table_offset,
            section_count,
            names,
        })
    }

    #[must_use]
    pub const fn elf_type(self) -> u16 {
        self.elf_type
    }

    #[must_use]
    pub const fn machine(self) -> u16 {
        self.machine
    }

    #[must_use]
    pub const fn entry(self) -> u32 {
        self.entry
    }

    #[must_use]
    pub const fn sections(self) -> Elf32Sections<'data> {
        Elf32Sections {
            data: self.data,
            names: self.names,
            section_table_offset: self.section_table_offset,
            section_count: self.section_count,
            index: 0,
        }
    }

    /// Finds a section by its decoded name.
    ///
    /// # Errors
    ///
    /// Returns an error when a section header or name is malformed.
    pub fn section_by_name(self, expected: &str) -> Result<Option<Elf32Section<'data>>, ElfError> {
        for section in self.sections() {
            let section = section?;
            if section.name == expected {
                return Ok(Some(section));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elf32Section<'data> {
    pub name: &'data str,
    pub section_type: u32,
    pub flags: u32,
    pub address: u32,
    pub file_offset: u32,
    pub size: u32,
}

impl Elf32Section<'_> {
    #[must_use]
    pub const fn is_relocation(self) -> bool {
        self.section_type == SECTION_TYPE_RELA || self.section_type == SECTION_TYPE_REL
    }

    #[must_use]
    pub const fn is_writable_allocated(self) -> bool {
        self.flags & (SECTION_FLAG_WRITE | SECTION_FLAG_ALLOCATE)
            == (SECTION_FLAG_WRITE | SECTION_FLAG_ALLOCATE)
    }

    #[must_use]
    pub const fn is_allocated_executable(self) -> bool {
        self.flags & (SECTION_FLAG_ALLOCATE | SECTION_FLAG_EXECUTE)
            == (SECTION_FLAG_ALLOCATE | SECTION_FLAG_EXECUTE)
    }
}

#[derive(Debug)]
pub struct Elf32Sections<'data> {
    data: &'data [u8],
    names: &'data [u8],
    section_table_offset: usize,
    section_count: u16,
    index: u16,
}

impl<'data> Iterator for Elf32Sections<'data> {
    type Item = Result<Elf32Section<'data>, ElfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.section_count {
            return None;
        }
        let index = self.index;
        self.index += 1;
        Some(
            raw_section(self.data, self.section_table_offset, index)
                .and_then(|raw| section_from_raw(raw, self.names)),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.section_count - self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Elf32Sections<'_> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    TruncatedHeader { size: usize },
    WrongFormat,
    UnexpectedSectionEntrySize { actual: u16 },
    InvalidSectionTable { count: u16, names_index: u16 },
    TruncatedSectionTable { end: usize, size: usize },
    TruncatedSectionNames { end: usize, size: usize },
    SectionNameOutOfBounds { offset: u32, size: usize },
    UnterminatedSectionName { offset: u32 },
    NonAsciiSectionName { offset: u32 },
    ArithmeticOverflow,
}

impl fmt::Display for ElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { size } => {
                write!(formatter, "ELF header is truncated ({size} bytes)")
            },
            Self::WrongFormat => formatter.write_str("ELF is not 32-bit little-endian"),
            Self::UnexpectedSectionEntrySize { actual } => {
                write!(formatter, "ELF section headers are {actual} bytes, not 40")
            },
            Self::InvalidSectionTable { count, names_index } => write!(
                formatter,
                "invalid ELF section table: count={count}, names_index={names_index}"
            ),
            Self::TruncatedSectionTable { end, size } => write!(
                formatter,
                "ELF section table ends at {end:#x}, beyond {size:#x}"
            ),
            Self::TruncatedSectionNames { end, size } => write!(
                formatter,
                "ELF section names end at {end:#x}, beyond {size:#x}"
            ),
            Self::SectionNameOutOfBounds { offset, size } => write!(
                formatter,
                "ELF section name offset {offset:#x} is beyond {size:#x}"
            ),
            Self::UnterminatedSectionName { offset } => {
                write!(formatter, "ELF section name at {offset:#x} is unterminated")
            },
            Self::NonAsciiSectionName { offset } => {
                write!(formatter, "ELF section name at {offset:#x} is not ASCII")
            },
            Self::ArithmeticOverflow => formatter.write_str("ELF offset arithmetic overflowed"),
        }
    }
}

impl core::error::Error for ElfError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmExecutableText {
    pub entry: u32,
    pub address: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmExecutableError {
    Elf(ElfError),
    WrongType { actual: u16 },
    WrongMachine { actual: u16 },
    WrongEntry { actual: u32, expected: u32 },
    TextMissing,
    WrongTextAddress { actual: u32, expected: u32 },
    WrongTextSize { actual: u32, expected: u32 },
    Relocation,
    WritableAllocated,
}

impl fmt::Display for ArmExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => write!(formatter, "ELF: {error}"),
            Self::WrongType { actual } => write!(formatter, "ELF type is {actual}, not executable"),
            Self::WrongMachine { actual } => {
                write!(formatter, "ELF machine is {actual}, not ARM")
            },
            Self::WrongEntry { actual, expected } => {
                write!(formatter, "ELF entry is {actual:#x}, not {expected:#x}")
            },
            Self::TextMissing => formatter.write_str("ELF has no .text section"),
            Self::WrongTextAddress { actual, expected } => {
                write!(
                    formatter,
                    "ELF .text address is {actual:#x}, not {expected:#x}"
                )
            },
            Self::WrongTextSize { actual, expected } => {
                write!(formatter, "ELF .text is {actual} bytes, not {expected}")
            },
            Self::Relocation => formatter.write_str("ELF contains relocations"),
            Self::WritableAllocated => formatter.write_str("ELF contains writable allocated data"),
        }
    }
}

impl core::error::Error for ArmExecutableError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

/// Verifies the common executable and `.text` invariants for a linked ARM artifact.
///
/// # Errors
///
/// Returns the first ELF parsing, identity, section, relocation, or writable-data failure.
pub fn verify_arm_executable_text(
    elf_bytes: &[u8],
    expected: ArmExecutableText,
) -> Result<(), ArmExecutableError> {
    let elf = Elf32::parse(elf_bytes).map_err(ArmExecutableError::Elf)?;
    if elf.elf_type() != ELF_TYPE_EXECUTABLE {
        return Err(ArmExecutableError::WrongType {
            actual: elf.elf_type(),
        });
    }
    if elf.machine() != ELF_MACHINE_ARM {
        return Err(ArmExecutableError::WrongMachine {
            actual: elf.machine(),
        });
    }
    if elf.entry() != expected.entry {
        return Err(ArmExecutableError::WrongEntry {
            actual: elf.entry(),
            expected: expected.entry,
        });
    }

    let mut found_text = false;
    for section in elf.sections() {
        let section = section.map_err(ArmExecutableError::Elf)?;
        if section.name == ".text" {
            found_text = true;
            if section.address != expected.address {
                return Err(ArmExecutableError::WrongTextAddress {
                    actual: section.address,
                    expected: expected.address,
                });
            }
            if section.size != expected.size {
                return Err(ArmExecutableError::WrongTextSize {
                    actual: section.size,
                    expected: expected.size,
                });
            }
        }
        if section.is_relocation() {
            return Err(ArmExecutableError::Relocation);
        }
        if section.is_writable_allocated() {
            return Err(ArmExecutableError::WritableAllocated);
        }
    }
    if !found_text {
        return Err(ArmExecutableError::TextMissing);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawSection {
    name_offset: u32,
    section_type: u32,
    flags: u32,
    address: u32,
    file_offset: u32,
    size: u32,
}

fn raw_section(data: &[u8], table_offset: usize, index: u16) -> Result<RawSection, ElfError> {
    let relative = ELF32_SECTION_HEADER_SIZE
        .checked_mul(usize::from(index))
        .ok_or(ElfError::ArithmeticOverflow)?;
    let offset = table_offset
        .checked_add(relative)
        .ok_or(ElfError::ArithmeticOverflow)?;
    Ok(RawSection {
        name_offset: read_u32(data, offset)?,
        section_type: read_u32(data, offset + 4)?,
        flags: read_u32(data, offset + 8)?,
        address: read_u32(data, offset + 12)?,
        file_offset: read_u32(data, offset + 16)?,
        size: read_u32(data, offset + 20)?,
    })
}

fn section_from_raw(raw: RawSection, names: &[u8]) -> Result<Elf32Section<'_>, ElfError> {
    let name_offset = usize_from_u32(raw.name_offset)?;
    if name_offset >= names.len() && name_offset != 0 {
        return Err(ElfError::SectionNameOutOfBounds {
            offset: raw.name_offset,
            size: names.len(),
        });
    }
    let suffix = names
        .get(name_offset..)
        .ok_or(ElfError::SectionNameOutOfBounds {
            offset: raw.name_offset,
            size: names.len(),
        })?;
    let length =
        suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ElfError::UnterminatedSectionName {
                offset: raw.name_offset,
            })?;
    let name_bytes = suffix
        .get(..length)
        .ok_or(ElfError::UnterminatedSectionName {
            offset: raw.name_offset,
        })?;
    if !name_bytes.is_ascii() {
        return Err(ElfError::NonAsciiSectionName {
            offset: raw.name_offset,
        });
    }
    let name = str::from_utf8(name_bytes).map_err(|_| ElfError::NonAsciiSectionName {
        offset: raw.name_offset,
    })?;
    Ok(Elf32Section {
        name,
        section_type: raw.section_type,
        flags: raw.flags,
        address: raw.address,
        file_offset: raw.file_offset,
        size: raw.size,
    })
}

#[allow(
    clippy::indexing_slicing,
    reason = "get() first proves that the returned slice contains exactly two bytes"
)]
fn read_u16(data: &[u8], offset: usize) -> Result<u16, ElfError> {
    let end = offset.checked_add(2).ok_or(ElfError::ArithmeticOverflow)?;
    let bytes = data
        .get(offset..end)
        .ok_or(ElfError::TruncatedHeader { size: data.len() })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[allow(
    clippy::indexing_slicing,
    reason = "get() first proves that the returned slice contains exactly four bytes"
)]
fn read_u32(data: &[u8], offset: usize) -> Result<u32, ElfError> {
    let end = offset.checked_add(4).ok_or(ElfError::ArithmeticOverflow)?;
    let bytes = data
        .get(offset..end)
        .ok_or(ElfError::TruncatedHeader { size: data.len() })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn usize_from_u32(value: u32) -> Result<usize, ElfError> {
    usize::try_from(value).map_err(|_| ElfError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::as_conversions,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::std_instead_of_alloc,
        reason = "tests construct bounded synthetic ELF fixtures and use checked-size casts"
    )]
    use std::{path::Path, vec, vec::Vec};

    use super::*;

    const SECTION_TABLE_OFFSET: usize = ELF32_HEADER_SIZE;
    const SECTION_COUNT: u16 = 3;
    const NAMES_OFFSET: usize =
        SECTION_TABLE_OFFSET + ELF32_SECTION_HEADER_SIZE * SECTION_COUNT as usize;
    const NAMES: &[u8] = b"\0.text\0.shstrtab\0";

    fn write_u16(output: &mut [u8], offset: usize, value: u16) {
        output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(output: &mut [u8], offset: usize, value: u32) {
        output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_elf() -> Vec<u8> {
        let mut elf = vec![0_u8; NAMES_OFFSET + NAMES.len()];
        elf[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        write_u16(&mut elf, 16, ELF_TYPE_EXECUTABLE);
        write_u16(&mut elf, 18, ELF_MACHINE_ARM);
        write_u32(&mut elf, 24, 0x2020);
        write_u32(&mut elf, 32, SECTION_TABLE_OFFSET as u32);
        write_u16(&mut elf, 46, ELF32_SECTION_HEADER_SIZE as u16);
        write_u16(&mut elf, 48, SECTION_COUNT);
        write_u16(&mut elf, 50, 2);

        let text = SECTION_TABLE_OFFSET + ELF32_SECTION_HEADER_SIZE;
        write_u32(&mut elf, text, 1);
        write_u32(&mut elf, text + 4, 1);
        write_u32(
            &mut elf,
            text + 8,
            SECTION_FLAG_ALLOCATE | SECTION_FLAG_EXECUTE,
        );
        write_u32(&mut elf, text + 12, 0x2020);
        write_u32(&mut elf, text + 16, 0x200);
        write_u32(&mut elf, text + 20, 0x40);

        let names = SECTION_TABLE_OFFSET + ELF32_SECTION_HEADER_SIZE * 2;
        write_u32(&mut elf, names, 7);
        write_u32(&mut elf, names + 4, 3);
        write_u32(&mut elf, names + 16, NAMES_OFFSET as u32);
        write_u32(&mut elf, names + 20, NAMES.len() as u32);
        elf[NAMES_OFFSET..].copy_from_slice(NAMES);
        elf
    }

    #[test]
    fn parses_elf32_arm_header_and_sections() {
        let bytes = synthetic_elf();
        let elf = Elf32::parse(&bytes).expect("valid synthetic ELF");
        assert_eq!(elf.elf_type(), ELF_TYPE_EXECUTABLE);
        assert_eq!(elf.machine(), ELF_MACHINE_ARM);
        assert_eq!(elf.entry(), 0x2020);
        assert_eq!(elf.sections().len(), 3);
        let text = elf
            .section_by_name(".text")
            .expect("valid section names")
            .expect("text section");
        assert_eq!(text.address, 0x2020);
        assert_eq!(text.size, 0x40);
        assert!(text.is_allocated_executable());
        assert!(!text.is_writable_allocated());
        assert!(!text.is_relocation());
    }

    #[test]
    fn parses_available_project_elfs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixtures = [
            (
                "firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.elf",
                0x21ad,
                ".text",
                0x21ac,
            ),
            (
                "firmware/reset_trampoline/build/DO_NOT_FLASH-stock-reset-trampoline.elf",
                0x22b4,
                ".text",
                0x22b4,
            ),
            (
                "firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.elf",
                0x2020,
                ".vectors",
                0x2020,
            ),
        ];
        for (path, entry, section_name, section_address) in fixtures {
            let path = root.join(path);
            if !path.exists() {
                continue;
            }
            let bytes = std::fs::read(path).expect("read generated ELF");
            let elf = Elf32::parse(&bytes).expect("parse generated ELF");
            assert_eq!(elf.elf_type(), ELF_TYPE_EXECUTABLE);
            assert_eq!(elf.machine(), ELF_MACHINE_ARM);
            assert_eq!(elf.entry(), entry);
            assert_eq!(
                elf.section_by_name(section_name)
                    .expect("valid generated section names")
                    .expect("expected generated section")
                    .address,
                section_address
            );
        }
    }

    #[test]
    fn rejects_truncated_or_wrong_format_header() {
        assert_eq!(
            Elf32::parse(&[0; ELF32_HEADER_SIZE - 1]),
            Err(ElfError::TruncatedHeader {
                size: ELF32_HEADER_SIZE - 1,
            })
        );
        let mut bytes = synthetic_elf();
        bytes[0] = 0;
        assert_eq!(Elf32::parse(&bytes), Err(ElfError::WrongFormat));
    }

    #[test]
    fn rejects_invalid_or_truncated_section_table() {
        let mut bytes = synthetic_elf();
        write_u16(&mut bytes, 46, 39);
        assert_eq!(
            Elf32::parse(&bytes),
            Err(ElfError::UnexpectedSectionEntrySize { actual: 39 })
        );

        let mut bytes = synthetic_elf();
        write_u16(&mut bytes, 50, SECTION_COUNT);
        assert_eq!(
            Elf32::parse(&bytes),
            Err(ElfError::InvalidSectionTable {
                count: SECTION_COUNT,
                names_index: SECTION_COUNT,
            })
        );

        let mut bytes = synthetic_elf();
        bytes.truncate(NAMES_OFFSET - 1);
        assert!(matches!(
            Elf32::parse(&bytes),
            Err(ElfError::TruncatedSectionTable { .. })
        ));
    }

    #[test]
    fn rejects_truncated_section_names() {
        let mut bytes = synthetic_elf();
        bytes.pop();
        assert!(matches!(
            Elf32::parse(&bytes),
            Err(ElfError::TruncatedSectionNames { .. })
        ));
    }

    #[test]
    fn rejects_bad_section_names_without_panicking() {
        let mut bytes = synthetic_elf();
        let text = SECTION_TABLE_OFFSET + ELF32_SECTION_HEADER_SIZE;
        write_u32(&mut bytes, text, NAMES.len() as u32);
        let elf = Elf32::parse(&bytes).expect("header remains valid");
        assert!(matches!(
            elf.sections().nth(1),
            Some(Err(ElfError::SectionNameOutOfBounds { .. }))
        ));

        let mut bytes = synthetic_elf();
        *bytes.last_mut().expect("names are nonempty") = b'x';
        let elf = Elf32::parse(&bytes).expect("header remains valid");
        assert!(matches!(
            elf.sections().nth(2),
            Some(Err(ElfError::UnterminatedSectionName { .. }))
        ));

        let mut bytes = synthetic_elf();
        bytes[NAMES_OFFSET + 1] = 0xff;
        let elf = Elf32::parse(&bytes).expect("header remains valid");
        assert!(matches!(
            elf.sections().nth(1),
            Some(Err(ElfError::NonAsciiSectionName { .. }))
        ));
    }
}
