//! Command octets (SCO, DCO, RCO) and the qualifiers of commands, set points and parameters.

use core::fmt;

use super::DoublePointValue;

/// QU, the qualifier of a command: the pulse duration, five bits (0–31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CommandQualifier(u8);

impl CommandQualifier {
    /// 0: no additional definition.
    pub const NONE: CommandQualifier = CommandQualifier(0);
    /// 1: short pulse duration.
    pub const SHORT_PULSE: CommandQualifier = CommandQualifier(1);
    /// 2: long pulse duration.
    pub const LONG_PULSE: CommandQualifier = CommandQualifier(2);
    /// 3: persistent output.
    pub const PERSISTENT: CommandQualifier = CommandQualifier(3);

    /// The qualifier `value`, or `None` if it does not fit five bits.
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 31 { Some(Self(value)) } else { None }
    }

    /// The qualifier as a number, 0–31.
    pub const fn value(self) -> u8 {
        self.0
    }
}

macro_rules! command_octet {
    ($name:ident) => {
        impl $name {
            /// The command from its octet, as received.
            pub const fn from_bits(bits: u8) -> Self {
                Self(bits)
            }

            /// The octet, as received.
            pub const fn bits(self) -> u8 {
                self.0
            }

            /// The same command as a select (S/E = 1) of select-before-operate.
            #[must_use]
            pub const fn select(self) -> Self {
                Self(self.0 | 0x80)
            }

            /// The same command as an execute (S/E = 0).
            #[must_use]
            pub const fn execute(self) -> Self {
                Self(self.0 & 0x7F)
            }

            /// S/E: whether this is the select of select-before-operate.
            pub const fn is_select(self) -> bool {
                self.0 & 0x80 != 0
            }

            /// The same command with the qualifier `qualifier`.
            #[must_use]
            pub const fn with_qualifier(self, qualifier: CommandQualifier) -> Self {
                Self((self.0 & 0x83) | (qualifier.0 << 2))
            }

            /// QU, the qualifier.
            pub const fn qualifier(self) -> CommandQualifier {
                CommandQualifier((self.0 & 0x7C) >> 2)
            }
        }
    };
}

/// SCO, a single command: the state (SCS, bit 0), the qualifier (QU, bits 2–6) and S/E
/// (bit 7). Bit 1 is reserved and kept as received.
///
/// ```
/// use iec60870::types::{CommandQualifier, SingleCommand};
///
/// let sco = SingleCommand::new(true).select().with_qualifier(CommandQualifier::SHORT_PULSE);
/// assert_eq!(sco.bits(), 0x85);
/// assert!(sco.state() && sco.is_select());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SingleCommand(u8);

command_octet!(SingleCommand);

impl SingleCommand {
    /// An execute command to switch on (`true`) or off, with no qualifier.
    pub const fn new(on: bool) -> Self {
        Self(on as u8)
    }

    /// SCS, the commanded state.
    pub const fn state(self) -> bool {
        self.0 & 0x01 != 0
    }
}

/// DCO, a double command: the state (DCS, bits 0–1), the qualifier (QU, bits 2–6) and S/E.
/// DCS 0 and 3 are not permitted by the standard but are kept as received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DoubleCommand(u8);

command_octet!(DoubleCommand);

impl DoubleCommand {
    /// An execute command with state `state` and no qualifier.
    pub const fn new(state: DoublePointValue) -> Self {
        Self(state as u8)
    }

    /// An execute command to switch on.
    pub const fn on() -> Self {
        Self::new(DoublePointValue::On)
    }

    /// An execute command to switch off.
    pub const fn off() -> Self {
        Self::new(DoublePointValue::Off)
    }

    /// DCS, the commanded state.
    pub const fn state(self) -> DoublePointValue {
        DoublePointValue::from_bits(self.0)
    }
}

/// The direction of a regulating step command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StepDirection {
    /// RCS 1: next step lower.
    Lower = 1,
    /// RCS 2: next step higher.
    Higher = 2,
}

/// RCO, a regulating step command: the direction (RCS, bits 0–1), the qualifier and S/E.
/// RCS 0 and 3 are not permitted by the standard but are kept as received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StepCommand(u8);

command_octet!(StepCommand);

impl StepCommand {
    /// An execute command to step in `direction`, with no qualifier.
    pub const fn new(direction: StepDirection) -> Self {
        Self(direction as u8)
    }

    /// An execute command for the next step higher.
    pub const fn higher() -> Self {
        Self::new(StepDirection::Higher)
    }

    /// An execute command for the next step lower.
    pub const fn lower() -> Self {
        Self::new(StepDirection::Lower)
    }

    /// RCS, the direction; `None` for the values 0 and 3 the standard does not permit.
    pub const fn direction(self) -> Option<StepDirection> {
        match self.0 & 0x03 {
            1 => Some(StepDirection::Lower),
            2 => Some(StepDirection::Higher),
            _ => None,
        }
    }
}

impl fmt::Debug for SingleCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reserved = if self.0 & 0x02 != 0 { ", reserved bit 1" } else { "" };
        write!(f, "SingleCommand({}, {}, QU {}{reserved})", if self.state() { "ON" } else { "OFF" }, se(self.is_select()), self.qualifier().0)
    }
}

impl fmt::Debug for DoubleCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DoubleCommand({:?}, {}, QU {})", self.state(), se(self.is_select()), self.qualifier().0)
    }
}

impl fmt::Debug for StepCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.direction() {
            Some(d) => write!(f, "StepCommand({d:?}, {}, QU {})", se(self.is_select()), self.qualifier().0),
            None => write!(f, "StepCommand(RCS {}, {}, QU {})", self.0 & 0x03, se(self.is_select()), self.qualifier().0),
        }
    }
}

const fn se(select: bool) -> &'static str {
    if select { "select" } else { "execute" }
}

/// QOS, the qualifier of a set-point command: QL (bits 0–6) and S/E (bit 7).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SetpointQualifier(u8);

impl SetpointQualifier {
    /// QL 0, execute.
    pub const DEFAULT: SetpointQualifier = SetpointQualifier(0);

    /// The qualifier from its octet, as received.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The octet, as received.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// QL, 0–127 (0 = default).
    pub const fn ql(self) -> u8 {
        self.0 & 0x7F
    }

    /// S/E: whether this is the select of select-before-operate.
    pub const fn is_select(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// The same qualifier with S/E = select.
    #[must_use]
    pub const fn select(self) -> Self {
        Self(self.0 | 0x80)
    }

    /// The same qualifier with S/E = execute.
    #[must_use]
    pub const fn execute(self) -> Self {
        Self(self.0 & 0x7F)
    }

    /// The same qualifier with QL `ql` (only the low seven bits are used).
    #[must_use]
    pub const fn with_ql(self, ql: u8) -> Self {
        Self((self.0 & 0x80) | (ql & 0x7F))
    }
}

impl fmt::Debug for SetpointQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SetpointQualifier({}, QL {})", se(self.is_select()), self.ql())
    }
}

/// QPM, the qualifier of a parameter of measured values: the kind (KPA, bits 0–5), local
/// parameter change (LPC, bit 6) and parameter in operation (POP, bit 7, set = not in operation).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ParameterQualifier(u8);

impl ParameterQualifier {
    /// KPA 1: threshold value.
    pub const THRESHOLD: ParameterQualifier = ParameterQualifier(1);
    /// KPA 2: smoothing factor (filter time constant).
    pub const SMOOTHING: ParameterQualifier = ParameterQualifier(2);
    /// KPA 3: low limit for transmission of measured values.
    pub const LOW_LIMIT: ParameterQualifier = ParameterQualifier(3);
    /// KPA 4: high limit for transmission of measured values.
    pub const HIGH_LIMIT: ParameterQualifier = ParameterQualifier(4);

    /// The qualifier from its octet, as received.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The octet, as received.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// KPA, the kind of parameter, 0–63.
    pub const fn kind(self) -> u8 {
        self.0 & 0x3F
    }

    /// LPC: local parameter change.
    pub const fn local_change(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// POP: the parameter is not in operation.
    pub const fn not_in_operation(self) -> bool {
        self.0 & 0x80 != 0
    }
}

impl fmt::Debug for ParameterQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParameterQualifier(KPA {}", self.kind())?;
        if self.local_change() {
            f.write_str(", LPC")?;
        }
        if self.not_in_operation() {
            f.write_str(", POP")?;
        }
        f.write_str(")")
    }
}
