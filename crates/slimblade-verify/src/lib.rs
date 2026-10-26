#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;

pub mod elf;
#[cfg(feature = "std")]
pub mod experiment_entry_probe;
#[cfg(feature = "std")]
pub mod late_marker_probe;
#[cfg(feature = "std")]
pub mod post_init_hook_probe;
pub mod post_link;
#[cfg(feature = "std")]
pub mod recovery_carrier;
#[cfg(feature = "std")]
pub mod recovery_guard;
#[cfg(feature = "std")]
pub mod recovery_stub;
#[cfg(feature = "std")]
pub mod reset_trampoline;
#[cfg(feature = "std")]
pub mod rust_response_probe;
#[cfg(feature = "std")]
pub mod sdk_startup;
#[cfg(feature = "std")]
pub mod startup_trampoline;
#[cfg(feature = "std")]
pub mod stock_harness;
pub mod usb_probe;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmAddress(u32);

impl ArmAddress {
    /// Constructs a word-aligned ARM instruction address.
    ///
    /// # Errors
    ///
    /// Returns an error if `address` is not divisible by four.
    pub const fn new(address: u32) -> Result<Self, BranchError> {
        if address.is_multiple_of(4) {
            Ok(Self(address))
        } else {
            Err(BranchError::UnalignedArmAddress { address })
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThumbAddress(u32);

impl ThumbAddress {
    /// Constructs a halfword-aligned Thumb instruction address.
    ///
    /// # Errors
    ///
    /// Returns an error if `address` is not divisible by two.
    pub const fn new(address: u32) -> Result<Self, BranchError> {
        if address.is_multiple_of(2) {
            Ok(Self(address))
        } else {
            Err(BranchError::UnalignedThumbAddress { address })
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmBranchKind {
    Branch,
    BranchLink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchError {
    UnalignedArmAddress { address: u32 },
    UnalignedThumbAddress { address: u32 },
    TargetOutOfRange,
    TargetOutsideAddressSpace { target: i64 },
    InvalidArmBranch { instruction: u32 },
    InvalidArmBranchLinkExchange { instruction: u32 },
    InvalidThumbBranchLink { high: u16, low: u16 },
}

impl fmt::Display for BranchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnalignedArmAddress { address } => {
                write!(formatter, "ARM address {address:#x} is not word-aligned")
            },
            Self::UnalignedThumbAddress { address } => write!(
                formatter,
                "Thumb address {address:#x} is not halfword-aligned"
            ),
            Self::TargetOutOfRange => formatter.write_str("branch target is out of range"),
            Self::TargetOutsideAddressSpace { target } => {
                write!(
                    formatter,
                    "branch target {target:#x} is outside 32-bit address space"
                )
            },
            Self::InvalidArmBranch { instruction } => {
                write!(formatter, "instruction {instruction:#010x} is not ARM B/BL")
            },
            Self::InvalidArmBranchLinkExchange { instruction } => write!(
                formatter,
                "instruction {instruction:#010x} is not immediate ARM BLX"
            ),
            Self::InvalidThumbBranchLink { high, low } => write!(
                formatter,
                "halfwords {high:#06x} {low:#06x} are not ARMv5 Thumb BL"
            ),
        }
    }
}

impl core::error::Error for BranchError {}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the range-checked displacement is intentionally masked into the ARM immediate field"
)]
/// Encodes an unconditional ARM branch.
///
/// # Errors
///
/// Returns an error if the target is outside the instruction's displacement range.
pub fn encode_arm_b(source: ArmAddress, target: ArmAddress) -> Result<[u8; 4], BranchError> {
    let delta = i64::from(target.get()) - (i64::from(source.get()) + 8);
    if !(-(1_i64 << 25_u32)..(1_i64 << 25_u32)).contains(&delta) {
        return Err(BranchError::TargetOutOfRange);
    }
    let immediate = ((delta >> 2_u32) as u32) & 0x00ff_ffff;
    Ok((0xea00_0000 | immediate).to_le_bytes())
}

/// Decodes an ARM branch or branch-with-link instruction.
///
/// # Errors
///
/// Returns an error for another opcode, an out-of-range target, or an unaligned target.
pub fn decode_arm_branch(
    instruction: [u8; 4],
    source: ArmAddress,
) -> Result<(ArmBranchKind, ArmAddress), BranchError> {
    let instruction = u32::from_le_bytes(instruction);
    let kind = match instruction >> 24_u32 {
        0xea => ArmBranchKind::Branch,
        0xeb => ArmBranchKind::BranchLink,
        _ => return Err(BranchError::InvalidArmBranch { instruction }),
    };
    let immediate = i64::from(instruction & 0x00ff_ffff);
    let delta = sign_extend(immediate << 2, 26);
    let target = checked_target(source.get(), 8, delta)?;
    Ok((kind, ArmAddress::new(target)?))
}

/// Decodes an immediate ARM branch-with-link-and-exchange instruction.
///
/// # Errors
///
/// Returns an error for another opcode, an out-of-range target, or an unaligned Thumb target.
pub fn decode_arm_blx(
    instruction: [u8; 4],
    source: ArmAddress,
) -> Result<ThumbAddress, BranchError> {
    let instruction = u32::from_le_bytes(instruction);
    if instruction & 0xfe00_0000 != 0xfa00_0000 {
        return Err(BranchError::InvalidArmBranchLinkExchange { instruction });
    }
    let immediate = i64::from(instruction & 0x00ff_ffff);
    let h_bit = i64::from((instruction >> 23_u32) & 2);
    let delta = sign_extend((immediate << 2) | h_bit, 26);
    let target = checked_target(source.get(), 8, delta)?;
    ThumbAddress::new(target)
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the range-checked displacement is intentionally masked into two 11-bit fields"
)]
/// Encodes a Thumb branch-with-link instruction.
///
/// # Errors
///
/// Returns an error if the target is outside the instruction's displacement range.
pub fn encode_thumb_bl(source: ThumbAddress, target: ThumbAddress) -> Result<[u8; 4], BranchError> {
    let delta = i64::from(target.get()) - (i64::from(source.get()) + 4);
    if !(-(1_i64 << 22_u32)..(1_i64 << 22_u32)).contains(&delta) {
        return Err(BranchError::TargetOutOfRange);
    }
    let encoded = (delta as u32) & 0x007f_ffff;
    let high = 0xf000 | ((encoded >> 12_u32) as u16 & 0x07ff);
    let low = 0xf800 | ((encoded >> 1_u32) as u16 & 0x07ff);
    let mut bytes = [0; 4];
    bytes[..2].copy_from_slice(&high.to_le_bytes());
    bytes[2..].copy_from_slice(&low.to_le_bytes());
    Ok(bytes)
}

/// Decodes a Thumb branch-with-link instruction.
///
/// # Errors
///
/// Returns an error for invalid halfwords, an out-of-range target, or an unaligned target.
pub fn decode_thumb_bl(
    instruction: [u8; 4],
    source: ThumbAddress,
) -> Result<ThumbAddress, BranchError> {
    let high = u16::from_le_bytes([instruction[0], instruction[1]]);
    let low = u16::from_le_bytes([instruction[2], instruction[3]]);
    if high & 0xf800 != 0xf000 || low & 0xf800 != 0xf800 {
        return Err(BranchError::InvalidThumbBranchLink { high, low });
    }
    let encoded = (i64::from(high & 0x07ff) << 12_u32) | (i64::from(low & 0x07ff) << 1_u32);
    let delta = sign_extend(encoded, 23);
    let target = checked_target(source.get(), 4, delta)?;
    ThumbAddress::new(target)
}

const fn sign_extend(value: i64, bits: u32) -> i64 {
    let sign_bit = 1_i64 << (bits - 1);
    if value & sign_bit == 0 {
        value
    } else {
        value - (1_i64 << bits)
    }
}

fn checked_target(source: u32, pc_bias: i64, delta: i64) -> Result<u32, BranchError> {
    let target = i64::from(source) + pc_bias + delta;
    u32::try_from(target).map_err(|_| BranchError::TargetOutsideAddressSpace { target })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests expect successful construction and encoding as part of their assertions"
)]
mod tests {
    use super::*;

    fn arm(address: u32) -> ArmAddress {
        ArmAddress::new(address).expect("word-aligned test address")
    }

    fn thumb(address: u32) -> ThumbAddress {
        ThumbAddress::new(address).expect("halfword-aligned test address")
    }

    #[test]
    fn arm_branch_encodings_match_recorded_bytes() {
        assert_eq!(
            encode_arm_b(arm(0x2064), arm(0x22b4)),
            Ok([0x92, 0x00, 0x00, 0xea])
        );
        assert_eq!(
            encode_arm_b(arm(0x22b8), arm(0x2068)),
            Ok([0x6a, 0xff, 0xff, 0xea])
        );
    }

    #[test]
    fn arm_address_rejects_unaligned_value() {
        assert_eq!(
            ArmAddress::new(0x2065),
            Err(BranchError::UnalignedArmAddress { address: 0x2065 })
        );
    }

    #[test]
    fn arm_branch_round_trip_preserves_kind_and_target() {
        let source = arm(0x2064);
        let target = arm(0x22b4);
        let encoded = encode_arm_b(source, target).expect("in-range ARM branch");
        assert_eq!(
            decode_arm_branch(encoded, source),
            Ok((ArmBranchKind::Branch, target))
        );
        assert_eq!(
            decode_arm_branch(0xeb00_0000_u32.to_le_bytes(), arm(0x100)),
            Ok((ArmBranchKind::BranchLink, arm(0x108)))
        );
    }

    #[test]
    fn arm_branch_rejects_invalid_opcode_and_range() {
        assert!(matches!(
            decode_arm_branch([0; 4], arm(0)),
            Err(BranchError::InvalidArmBranch { .. })
        ));
        assert_eq!(
            encode_arm_b(arm(0), arm(0x0200_0008)),
            Err(BranchError::TargetOutOfRange)
        );
    }

    #[test]
    fn arm_blx_decodes_both_h_values() {
        assert_eq!(
            decode_arm_blx(0xfa00_0000_u32.to_le_bytes(), arm(0x100)),
            Ok(thumb(0x108))
        );
        assert_eq!(
            decode_arm_blx(0xfb00_0000_u32.to_le_bytes(), arm(0x100)),
            Ok(thumb(0x10a))
        );
    }

    #[test]
    fn thumb_branch_encodings_match_recorded_bytes() {
        assert_eq!(
            encode_thumb_bl(thumb(0x18fba), thumb(0x1895c)),
            Ok([0xff, 0xf7, 0xcf, 0xfc])
        );
        assert_eq!(
            encode_thumb_bl(thumb(0x20b6), thumb(0x21c4)),
            Ok([0x00, 0xf0, 0x85, 0xf8])
        );
        assert_eq!(
            encode_thumb_bl(thumb(0x100), thumb(0x80)),
            Ok([0xff, 0xf7, 0xbe, 0xff])
        );
    }

    #[test]
    fn thumb_branch_round_trip_handles_forward_and_backward_targets() {
        for (source, target) in [(0x18fba, 0x1895c), (0x20b6, 0x21c4), (0x100, 0x80)] {
            let source = thumb(source);
            let target = thumb(target);
            let encoded = encode_thumb_bl(source, target).expect("in-range Thumb BL");
            assert_eq!(decode_thumb_bl(encoded, source), Ok(target));
        }
    }

    #[test]
    fn thumb_branch_rejects_unaligned_invalid_and_out_of_range_values() {
        assert_eq!(
            ThumbAddress::new(0x101),
            Err(BranchError::UnalignedThumbAddress { address: 0x101 })
        );
        assert!(matches!(
            decode_thumb_bl([0; 4], thumb(0x100)),
            Err(BranchError::InvalidThumbBranchLink { .. })
        ));
        assert_eq!(
            encode_thumb_bl(thumb(0), thumb(0x0040_0004)),
            Err(BranchError::TargetOutOfRange)
        );
    }
}
