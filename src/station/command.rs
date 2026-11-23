//! Commands, parameters, and the application's [`CommandHandler`].

use core::fmt;

use super::controlled::ConnectionId;
use crate::time::Cp56Time2a;
use crate::types::{
    BitstringCommand, CommonAddress, CounterInterrogation, DoubleCommand, DoublePointValue, Ioa, Normalized, ParameterActivation, ParameterFloat,
    ParameterNormalized, ParameterScaled, ResetProcess, SetpointFloat, SetpointNormalized, SetpointScaled, SingleCommand, StepCommand, StepDirection, TypeId,
};

/// A command of any type: the element of a single, double, regulating step, set-point
/// (normalized, scaled, float) or bitstring command (types 45–51, 58–64), with its select/execute bit and qualifier.
///
/// ```
/// use iec60870::station::{Command, CommandKind};
/// use iec60870::TypeId;
///
/// let close = Command::single(true);
/// assert!(!close.is_select());
/// assert!(close.select().is_select());
/// assert_eq!(close.select().execute(), close);
/// assert_eq!(close.kind(), CommandKind::Single);
/// assert_eq!(close.type_id(true), TypeId::C_SC_TA_1);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Command {
    /// Single command (45, 58).
    Single(SingleCommand),
    /// Double command (46, 59).
    Double(DoubleCommand),
    /// Regulating step command (47, 60).
    Step(StepCommand),
    /// Set point, normalized (48, 61).
    Normalized(SetpointNormalized),
    /// Set point, scaled (49, 62).
    Scaled(SetpointScaled),
    /// Set point, short float (50, 63).
    Float(SetpointFloat),
    /// Bitstring of 32 bits (51, 64): no select/execute bit, always direct.
    Bitstring(BitstringCommand),
}

/// The kind of a [`Command`], as a controlled station declares its command points.
///
/// ```
/// use iec60870::station::{Command, CommandKind};
/// assert_eq!(Command::setpoint_float(1.0).kind(), CommandKind::Float);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommandKind {
    /// Single command.
    Single,
    /// Double command.
    Double,
    /// Regulating step command.
    Step,
    /// Set point, normalized.
    Normalized,
    /// Set point, scaled.
    Scaled,
    /// Set point, short float.
    Float,
    /// Bitstring of 32 bits.
    Bitstring,
}

impl Command {
    /// An execute single command: `on` or off.
    pub const fn single(on: bool) -> Self {
        Command::Single(SingleCommand::new(on))
    }

    /// An execute double command.
    pub const fn double(state: DoublePointValue) -> Self {
        Command::Double(DoubleCommand::new(state))
    }

    /// An execute regulating step command.
    pub const fn step(direction: StepDirection) -> Self {
        Command::Step(StepCommand::new(direction))
    }

    /// An execute normalized set point.
    pub const fn setpoint_normalized(value: Normalized) -> Self {
        Command::Normalized(SetpointNormalized::new(value))
    }

    /// An execute scaled set point.
    pub const fn setpoint_scaled(value: i16) -> Self {
        Command::Scaled(SetpointScaled::new(value))
    }

    /// An execute short-float set point.
    pub const fn setpoint_float(value: f32) -> Self {
        Command::Float(SetpointFloat::new(value))
    }

    /// A bitstring command.
    pub const fn bitstring(value: u32) -> Self {
        Command::Bitstring(BitstringCommand(value))
    }

    /// The kind.
    pub const fn kind(&self) -> CommandKind {
        match self {
            Command::Single(_) => CommandKind::Single,
            Command::Double(_) => CommandKind::Double,
            Command::Step(_) => CommandKind::Step,
            Command::Normalized(_) => CommandKind::Normalized,
            Command::Scaled(_) => CommandKind::Scaled,
            Command::Float(_) => CommandKind::Float,
            Command::Bitstring(_) => CommandKind::Bitstring,
        }
    }

    /// Whether S/E is set: the select of select-before-operate.
    pub const fn is_select(&self) -> bool {
        match self {
            Command::Single(c) => c.is_select(),
            Command::Double(c) => c.is_select(),
            Command::Step(c) => c.is_select(),
            Command::Normalized(c) => c.qualifier.is_select(),
            Command::Scaled(c) => c.qualifier.is_select(),
            Command::Float(c) => c.qualifier.is_select(),
            Command::Bitstring(_) => false,
        }
    }

    /// The same command with S/E set (a bitstring command is returned unchanged).
    #[must_use]
    pub const fn select(self) -> Self {
        self.with_select(true)
    }

    /// The same command with S/E clear.
    #[must_use]
    pub const fn execute(self) -> Self {
        self.with_select(false)
    }

    const fn with_select(self, select: bool) -> Self {
        macro_rules! octet {
            ($c:expr) => {
                if select { $c.select() } else { $c.execute() }
            };
        }
        macro_rules! qos {
            ($c:expr) => {{
                let mut c = $c;
                c.qualifier = if select { c.qualifier.select() } else { c.qualifier.execute() };
                c
            }};
        }
        match self {
            Command::Single(c) => Command::Single(octet!(c)),
            Command::Double(c) => Command::Double(octet!(c)),
            Command::Step(c) => Command::Step(octet!(c)),
            Command::Normalized(c) => Command::Normalized(qos!(c)),
            Command::Scaled(c) => Command::Scaled(qos!(c)),
            Command::Float(c) => Command::Float(qos!(c)),
            Command::Bitstring(c) => Command::Bitstring(c),
        }
    }

    /// The type identification: the plain type, or the CP56Time2a one when `time_tagged`.
    pub const fn type_id(&self, time_tagged: bool) -> TypeId {
        match (self, time_tagged) {
            (Command::Single(_), false) => TypeId::C_SC_NA_1,
            (Command::Single(_), true) => TypeId::C_SC_TA_1,
            (Command::Double(_), false) => TypeId::C_DC_NA_1,
            (Command::Double(_), true) => TypeId::C_DC_TA_1,
            (Command::Step(_), false) => TypeId::C_RC_NA_1,
            (Command::Step(_), true) => TypeId::C_RC_TA_1,
            (Command::Normalized(_), false) => TypeId::C_SE_NA_1,
            (Command::Normalized(_), true) => TypeId::C_SE_TA_1,
            (Command::Scaled(_), false) => TypeId::C_SE_NB_1,
            (Command::Scaled(_), true) => TypeId::C_SE_TB_1,
            (Command::Float(_), false) => TypeId::C_SE_NC_1,
            (Command::Float(_), true) => TypeId::C_SE_TC_1,
            (Command::Bitstring(_), false) => TypeId::C_BO_NA_1,
            (Command::Bitstring(_), true) => TypeId::C_BO_TA_1,
        }
    }
}

macro_rules! command_from {
    ($($variant:ident($ty:ty)),*) => {$(
        impl From<$ty> for Command {
            fn from(c: $ty) -> Self {
                Command::$variant(c)
            }
        }
    )*};
}
command_from!(
    Single(SingleCommand),
    Double(DoubleCommand),
    Step(StepCommand),
    Normalized(SetpointNormalized),
    Scaled(SetpointScaled),
    Float(SetpointFloat),
    Bitstring(BitstringCommand)
);

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Single(c) => write!(f, "single {}", if c.state() { "ON" } else { "OFF" }),
            Command::Double(c) => write!(f, "double {:?}", c.state()),
            Command::Step(c) => match c.direction() {
                Some(d) => write!(f, "step {d:?}"),
                None => f.write_str("step (invalid direction)"),
            },
            Command::Normalized(c) => write!(f, "set point {}", c.value.to_f32()),
            Command::Scaled(c) => write!(f, "set point {}", c.value),
            Command::Float(c) => write!(f, "set point {}", c.value),
            Command::Bitstring(c) => write!(f, "bitstring {:#010x}", c.0),
        }
    }
}

/// How a controlled station accepts commands for a point.
///
/// ```
/// use iec60870::prelude::*;
///
/// let mut db = Database::new();
/// db.command(CommonAddress(1), Ioa(5000), CommandKind::Double).mode(CommandMode::DirectOrSelect);
/// assert_eq!(CommandMode::default(), CommandMode::SelectBeforeOperate);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum CommandMode {
    /// Direct execute only; a select is refused.
    Direct,
    /// Select, then execute, within the select timeout — the default. A direct execute is
    /// refused.
    #[default]
    SelectBeforeOperate,
    /// Both: an execute that matches a live select completes it, any other is a direct execute.
    DirectOrSelect,
}

/// Which half of a command the station is asking about.
///
/// ```
/// use iec60870::station::{CommandRequest, Decision, Phase};
///
/// let handler = |r: &CommandRequest| Decision::from(r.phase == Phase::Execute);
/// # let _ = handler;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// The select of select-before-operate.
    Select,
    /// The execute (direct, or after an accepted select).
    Execute,
}

/// A command the controlled station has checked and hands to the [`CommandHandler`].
///
/// By the time a handler sees an `Execute` of a select-before-operate point, the station has
/// already checked that a select of the same connection, address, type, originator and value
/// was accepted within the select timeout.
///
/// ```
/// use iec60870::prelude::*;
///
/// let breaker = |r: &CommandRequest| match r.command {
///     Command::Single(c) if r.ioa == Ioa(5000) => {
///         println!("breaker {} by originator {}", if c.state() { "close" } else { "open" }, r.originator);
///         Decision::Accept
///     }
///     _ => Decision::Refuse,
/// };
/// # let _ = breaker;
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CommandRequest {
    /// The connection it arrived on.
    pub connection: ConnectionId,
    /// The common address.
    pub common_address: CommonAddress,
    /// The command point.
    pub ioa: Ioa,
    /// The command, in its execute form (S/E clear).
    pub command: Command,
    /// Select or execute.
    pub phase: Phase,
    /// The originator address of the cause of transmission.
    pub originator: u8,
    /// The test bit of the cause of transmission.
    pub test: bool,
    /// The time tag, for types 58–64.
    pub time: Option<Cp56Time2a>,
}

impl fmt::Display for CommandRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            Phase::Select => "select",
            Phase::Execute => "execute",
        };
        write!(f, "{phase} {} at CA {} IOA {} from {} (originator {})", self.command, self.common_address, self.ioa, self.connection, self.originator)?;
        if self.test {
            f.write_str(", test")?;
        }
        Ok(())
    }
}

/// A parameter of a measured value (110–112) or a parameter activation (113).
///
/// ```
/// use iec60870::station::Parameter;
/// use iec60870::types::{ParameterFloat, ParameterQualifier};
///
/// let threshold = Parameter::from(ParameterFloat { value: 0.5, qualifier: ParameterQualifier::THRESHOLD });
/// assert!(matches!(threshold, Parameter::Float(_)));
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Parameter {
    /// `P_ME_NA_1`.
    Normalized(ParameterNormalized),
    /// `P_ME_NB_1`.
    Scaled(ParameterScaled),
    /// `P_ME_NC_1`.
    Float(ParameterFloat),
    /// `P_AC_NA_1`.
    Activation(ParameterActivation),
}

macro_rules! parameter_from {
    ($($variant:ident($ty:ty)),*) => {$(
        impl From<$ty> for Parameter {
            fn from(p: $ty) -> Self {
                Parameter::$variant(p)
            }
        }
    )*};
}
parameter_from!(Normalized(ParameterNormalized), Scaled(ParameterScaled), Float(ParameterFloat), Activation(ParameterActivation));

/// A parameter request the controlled station hands to the [`CommandHandler`].
///
/// ```
/// use iec60870::station::{CommandHandler, CommandRequest, Decision, ParameterRequest};
///
/// struct Limits;
/// impl CommandHandler for Limits {
///     fn execute(&mut self, _: &CommandRequest) -> Decision { Decision::Refuse }
///     fn parameter(&mut self, p: &ParameterRequest) -> Decision {
///         println!("parameter for IOA {}: {:?}", p.ioa, p.parameter);
///         Decision::Accept
///     }
/// }
/// # let _ = Limits;
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ParameterRequest {
    /// The connection it arrived on.
    pub connection: ConnectionId,
    /// The common address.
    pub common_address: CommonAddress,
    /// The measured point the parameter belongs to (0 for a station-wide activation).
    pub ioa: Ioa,
    /// The parameter.
    pub parameter: Parameter,
}

/// A handler's answer: the station turns it into a positive or negative confirmation.
///
/// ```
/// use iec60870::station::Decision;
/// assert_eq!(Decision::from(true), Decision::Accept);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Confirm positively (and, for an execute, terminate).
    Accept,
    /// Confirm negatively.
    Refuse,
}

impl From<bool> for Decision {
    /// `true` accepts.
    fn from(accept: bool) -> Self {
        if accept { Decision::Accept } else { Decision::Refuse }
    }
}

/// What the application decides when a controlling station asks the outstation to act.
///
/// Only [`execute`](Self::execute) is required; everything else defaults to accepting (a
/// select, a clock synchronisation, a reset, a counter interrogation, a parameter). The
/// station has checked the request before the handler is called — address known, cause
/// valid, select-before-operate in order — so a handler only says whether the process can do
/// it. A closure is a handler:
///
/// ```
/// use iec60870::station::{CommandHandler, CommandRequest, Decision};
///
/// let mut handler = |request: &CommandRequest| {
///     println!("{request}");
///     Decision::Accept
/// };
/// fn takes(_: &mut dyn CommandHandler) {}
/// takes(&mut handler);
/// ```
pub trait CommandHandler {
    /// Executes a command (direct, or after its accepted select).
    fn execute(&mut self, request: &CommandRequest) -> Decision;

    /// Optional monitored-point update in the same common address after an accepted execute.
    /// The station applies it before confirming and before processing the next command.
    /// An unknown IOA or incompatible value makes the station refuse the command.
    fn feedback(&mut self, _request: &CommandRequest, _database: &dyn super::PointSource) -> Option<(Ioa, super::Value)> {
        None
    }

    /// Selects a command point (select-before-operate). Default: accept.
    fn select(&mut self, request: &CommandRequest) -> Decision {
        let _ = request;
        Decision::Accept
    }

    /// The master deactivated (cancelled) an accepted select. Default: nothing.
    fn cancel(&mut self, request: &CommandRequest) {
        let _ = request;
    }

    /// Clock synchronisation: accept to have the station use `time` from now on. The station
    /// keeps it as an offset to its clock; it never sets the operating-system clock.
    fn clock_sync(&mut self, time: Cp56Time2a) -> Decision {
        let _ = time;
        Decision::Accept
    }

    /// Reset process (QRP 1 general, 2 event buffer). Default: accept.
    fn reset_process(&mut self, common_address: CommonAddress, qualifier: ResetProcess) -> Decision {
        let _ = (common_address, qualifier);
        Decision::Accept
    }

    /// Counter interrogation with its freeze/reset qualifier, before the station acts on it.
    /// Default: accept.
    fn counter_interrogation(&mut self, common_address: CommonAddress, qualifier: CounterInterrogation) -> Decision {
        let _ = (common_address, qualifier);
        Decision::Accept
    }

    /// Parameter loading or activation. Default: accept.
    fn parameter(&mut self, request: &ParameterRequest) -> Decision {
        let _ = request;
        Decision::Accept
    }
}

impl<F: FnMut(&CommandRequest) -> Decision> CommandHandler for F {
    fn execute(&mut self, request: &CommandRequest) -> Decision {
        self(request)
    }
}

/// A handler that refuses every command and select (and accepts everything else) — for a
/// monitor-only outstation.
///
/// ```
/// use iec60870::station::{CommandHandler, RefuseCommands};
/// let _: &dyn CommandHandler = &RefuseCommands;
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct RefuseCommands;

impl CommandHandler for RefuseCommands {
    fn execute(&mut self, _: &CommandRequest) -> Decision {
        Decision::Refuse
    }

    fn select(&mut self, _: &CommandRequest) -> Decision {
        Decision::Refuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_execute_round_trip_for_every_kind() {
        let all = [
            Command::single(true),
            Command::double(DoublePointValue::Off),
            Command::step(StepDirection::Higher),
            Command::setpoint_normalized(Normalized(5)),
            Command::setpoint_scaled(-3),
            Command::setpoint_float(1.25),
        ];
        for c in all {
            assert!(!c.is_select());
            assert!(c.select().is_select(), "{c:?}");
            assert_eq!(c.select().execute(), c);
            assert_ne!(c.type_id(false), c.type_id(true));
        }
        let b = Command::bitstring(7);
        assert_eq!(b.select(), b);
        assert_eq!(b.type_id(true), TypeId::C_BO_TA_1);
        assert_eq!(Decision::from(false), Decision::Refuse);
        assert_eq!(alloc::format!("{}", Command::setpoint_float(2.5)), "set point 2.5");
    }
}
