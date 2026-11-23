//! The vocabulary of the application layer: type identifications, the cause of transmission,
//! addresses, quality descriptors, values, commands, qualifiers and every information element.
//!
//! Elements whose octet is a bit field — the quality descriptors, the command octets, the
//! qualifiers — are newtypes over the octet **as received**: reserved bits and values the
//! standard leaves undefined survive a decode and re-encode, and accessors say what the bits
//! mean. Elements whose bits are all defined (a scaled value, a float, a bitstring) are plain
//! fields.

/// Implements the shared surface of a flag-octet newtype: `from_bits`, `bits`, `contains`,
/// `union`, `BitOr`, and a `Debug` that names the flags that are set.
macro_rules! flag_octet {
    ($name:ident, $empty:literal, [$($flag:ident = $bit:literal),* $(,)?]) => {
        impl $name {
            /// The descriptor from its octet, as received (reserved bits included).
            pub const fn from_bits(bits: u8) -> Self {
                Self(bits)
            }

            /// The octet, as received.
            pub const fn bits(self) -> u8 {
                self.0
            }

            /// Whether every flag set in `other` is set in `self`.
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// The flags of both.
            #[must_use]
            pub const fn union(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                self.union(rhs)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                *self = self.union(rhs);
            }
        }

        impl $name {
            fn fmt_flags(&self, f: &mut core::fmt::Formatter<'_>, separator: &str, empty: &str) -> core::fmt::Result {
                let mut known = 0u8;
                let mut first = true;
                $(
                    known |= $bit;
                    if self.0 & $bit != 0 {
                        if !first { f.write_str(separator)?; }
                        f.write_str(stringify!($flag))?;
                        first = false;
                    }
                )*
                let rest = self.0 & !known;
                if rest != 0 {
                    if !first { f.write_str(separator)?; }
                    write!(f, "{rest:#04x}")?;
                    first = false;
                }
                if first { f.write_str(empty)?; }
                Ok(())
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "("))?;
                self.fmt_flags(f, " | ", $empty)?;
                f.write_str(")")
            }
        }
    };
}

mod command;
mod cot;
mod element;
mod quality;
mod type_id;
mod value;

pub use command::{CommandQualifier, DoubleCommand, ParameterQualifier, SetpointQualifier, SingleCommand, StepCommand, StepDirection};
pub use cot::{Cause, CommonAddress, Cot, Ioa};
pub use element::*;
pub use quality::{OutputCircuits, ProtectionQuality, Quality, SingleEvent, StartEvents};
pub use type_id::{TypeId, TypeSet};
pub use value::{BinaryCounterReading, DoublePointValue, Normalized};
