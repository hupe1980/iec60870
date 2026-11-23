//! Human and JSON views of the same decoded records.
use iec60870::{
    Asdu,
    asdu::{Objects, Profile},
    station::{Command, Point, Timestamp, Value},
};
use serde_json::{Value as Json, json};
use std::fmt::Write as _;
use std::io::{self, Write};

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(text, "{b:02x}");
    }
    text
}
struct Field {
    offset: usize,
    len: usize,
    name: &'static str,
    meaning: String,
}
pub struct Record {
    pub meta: serde_json::Map<String, Json>,
    pub line: String,
    fields: Option<Vec<Field>>,
    offset: usize,
}
impl Record {
    pub fn new(explain: bool) -> Self {
        Self { meta: serde_json::Map::new(), line: String::new(), fields: explain.then(Vec::new), offset: 0 }
    }
    pub fn field(&mut self, len: usize, name: &'static str, meaning: impl Into<String>) {
        if let Some(fields) = &mut self.fields
            && len > 0
        {
            fields.push(Field { offset: self.offset, len, name, meaning: meaning.into() });
        }
        self.offset += len;
    }
    pub fn raw(&mut self, bytes: &[u8]) {
        let value = hex(bytes);
        let _ = write!(self.line, ", raw {value}");
        self.meta.insert("raw".into(), json!(value));
        self.field(bytes.len(), "raw", "uninterpreted link user data");
    }
    pub fn asdu(&mut self, a: &Asdu, p: &Profile, bytes: &[u8], utc: bool) {
        let base = self.offset;
        let id = a.type_id();
        let cot = a.cot;
        let _ = write!(self.line, "   {id} {cot}, CA {}", a.common_address);
        self.field(1, "type", id.to_string());
        self.field(1, "vsq", format!("{} objects, SQ={}", a.len(), u8::from(a.sequence)));
        self.field(p.cot.octets(), "cot", cot.to_string());
        self.field(p.ca.octets(), "ca", a.common_address.to_string());
        let points = Point::from_asdu(a);
        let mut objects = Vec::new();
        for (i, ioa) in a.objects.ioas().enumerate() {
            if !a.sequence || i == 0 {
                self.field(p.ioa.octets(), "ioa", ioa.to_string());
            }
            let Some((n, t)) = a.objects.field_lengths(i) else { break };
            let start = self.offset - base;
            let data = bytes.get(start..start + n).unwrap_or_default();
            let (text, object) = if let Some(point) = points.as_ref().and_then(|v| v.get(i)) {
                let mut text = point.value.to_string();
                if let Some(time) = point.time {
                    let _ = write!(text, " at {time}");
                }
                (text, point_json(point, utc))
            } else {
                let mut text = element(&a.objects, i, data);
                let mut object = json!({"ioa":ioa.0,"text":text});
                if let (Some(time), Some(fields)) = (system_time(&a.objects, i), object.as_object_mut()) {
                    let _ = write!(text, " at {time}");
                    time_fields(fields, time, utc);
                }
                (text, object)
            };
            let _ = write!(self.line, ", IOA {ioa}: {text}");
            let split = matches!(id.0,5..=16|20|32..=37|48..=50|61..=63|110..=112) && n > 1;
            let extra = usize::from(split);
            self.field(n - extra, "element", format!("IOA {ioa}: {text}"));
            if split {
                let name = match id.0 {
                    15 | 16 | 37 => "counter flags",
                    48..=50 | 61..=63 | 110..=112 => "qualifier",
                    _ => "quality",
                };
                self.field(1, name, format!("{name} octet {:#04x}", data.last().copied().unwrap_or_default()));
            }
            self.field(t, "time", format!("IOA {ioa}: {t}-octet time tag"));
            let mut object = object;
            if let Some(fields) = object.as_object_mut() {
                fields.insert("derived".into(), json!(a.sequence && i > 0));
            }
            objects.push(object);
        }
        let mut body = json!({"type_id":id.0,"type":id.name(),"cot":{"cause":cot.cause.value(),"name":cot.cause.name(),"test":cot.test,"negative":cot.negative,"originator":cot.originator},"ca":a.common_address.0,"sequence":a.sequence,"objects":objects});
        if let (Objects::Raw(raw), Some(fields)) = (&a.objects, body.as_object_mut()) {
            let v = hex(&raw.body);
            let _ = write!(self.line, ", raw {v}");
            self.field(raw.body.len(), "raw", "opaque information objects");
            fields.insert("raw".into(), json!(v));
            fields.insert("count".into(), json!(raw.count));
        }
        self.meta.insert("asdu".into(), body);
    }
    pub fn write(mut self, input: usize, bytes: &[u8], explain: bool, json_output: bool, color: bool, out: &mut impl Write) -> io::Result<()> {
        if json_output {
            self.meta.insert("kind".into(), json!("frame"));
            self.meta.insert("input".into(), json!(input));
            self.meta.insert("octets".into(), json!(hex(bytes)));
            if explain {
                self.meta.insert("explain".into(), Json::Array(
                    self.fields.unwrap_or_default().into_iter().map(|f| json!({"offset":f.offset,"len":f.len,"field":f.name,"meaning":f.meaning,"octets":hex(bytes.get(f.offset..f.offset+f.len).unwrap_or_default())})).collect(),
                ));
            }
            writeln!(out, "{}", Json::Object(self.meta))
        } else {
            if color {
                writeln!(out, "\x1b[36m{}\x1b[0m", self.line)?;
            } else {
                writeln!(out, "{}", self.line)?;
            }
            for f in self.fields.unwrap_or_default() {
                let end = f.offset + f.len;
                let range = if f.len == 1 { format!("{:02x}", f.offset) } else { format!("{:02x}-{:02x}", f.offset, end - 1) };
                writeln!(out, "  {range:<7} {:<16} {:<10} {}", hex(bytes.get(f.offset..end).unwrap_or_default()), f.name, f.meaning)?;
            }
            Ok(())
        }
    }
}
pub(super) fn value_json(value: Value) -> Json {
    match value {
        Value::Single(v) => json!(v.value()),
        Value::Double(v) => json!(v.value().to_string()),
        Value::Step(v) => json!(v.value),
        Value::Bitstring(v) => json!(v.value),
        Value::Normalized(v) => json!(v.value.to_f32()),
        Value::NormalizedRaw(v) => json!(v.to_f32()),
        Value::Scaled(v) => json!(v.value),
        Value::Float(v) if v.value.is_finite() => json!(v.value),
        Value::Counter(v) => json!(v.value()),
        _ => json!(value.to_string()),
    }
}
pub(super) fn point_json(p: &Point, utc: bool) -> Json {
    let value = value_json(p.value);
    let flags = match p.value {
        Value::ProtectionEvent(v) => v.event.quality().to_string(),
        Value::StartEvents(v) => v.quality.to_string(),
        Value::OutputCircuits(v) => v.quality.to_string(),
        Value::Counter(v) => {
            [(v.carry(), "CY"), (v.adjusted(), "CA"), (v.invalid(), "IV")].into_iter().filter_map(|(set, key)| set.then_some(key)).collect::<Vec<_>>().join(" ")
        }
        _ => p.value.quality().map(|q| q.to_string()).unwrap_or_default(),
    };
    let quality: Vec<_> = flags.split_whitespace().filter(|&s| s != "good").collect();
    let mut obj = json!({"ioa":p.ioa.0,"value":value,"value_kind":p.value.kind().to_string(),"quality":quality});
    if let Some(fields) = obj.as_object_mut() {
        if let Value::Float(v) = p.value
            && !v.value.is_finite()
        {
            fields.remove("value");
            fields.insert("value_text".into(), json!(v.value.to_string()));
        }
        if let Some(time) = p.time {
            time_fields(fields, time, utc);
        }
    }
    obj
}
pub(super) fn time_fields(fields: &mut serde_json::Map<String, Json>, time: Timestamp, utc: bool) {
    fields.insert("time_text".into(), json!(time.to_string()));
    if utc
        && let Timestamp::Cp56(t) = time
        && !t.is_invalid()
        && let Some(d) = t.to_date_time()
    {
        fields.insert(
            "time".into(),
            json!(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", d.year, d.month, d.day, d.hour, d.minute, d.second, d.millisecond)),
        );
    }
}

// Monitor objects carry their own typed timestamp through Point.
fn system_time(objects: &Objects, index: usize) -> Option<Timestamp> {
    macro_rules! timed {
        ($($kind:ident),+) => { match objects {
            $(Objects::$kind(v)=>v.get(index).map(|o|Timestamp::Cp56(o.time)),)+
            _=>None,
        }}
    }
    timed!(
        SingleCommandCp56,
        DoubleCommandCp56,
        StepCommandCp56,
        SetpointNormalizedCp56,
        SetpointScaledCp56,
        SetpointFloatCp56,
        BitstringCommandCp56,
        ClockSync,
        TestCommandCp56,
        Directory
    )
}
fn element(objects: &Objects, i: usize, bytes: &[u8]) -> String {
    macro_rules! cmd {
        ($items:expr,$kind:ident) => {
            $items.get(i).map(|o| Command::$kind(o.element)).map(|c| format!("{} {c}", if c.is_select() { "select" } else { "execute" }))
        };
    }
    macro_rules! describe {
        ($items:expr) => {
            $items.get(i).map(|o| format!("{:?}", o.element))
        };
    }
    let label = match objects {
        Objects::Interrogation(v) => v.get(i).map(|o| match o.element.0 {
            20 => "station interrogation".to_string(),
            21..=36 => format!("interrogate group {}", o.element.0 - 20),
            n => format!("interrogation qualifier {n}"),
        }),
        Objects::Read(_) => Some("read".into()),
        Objects::ClockSync(_) => Some("clock synchronization".into()),
        Objects::CounterInterrogation(v) => v.get(i).map(|o| format!("counter interrogation, request {}, freeze {}", o.element.request(), o.element.freeze())),
        Objects::SingleCommand(v) => cmd!(v, Single),
        Objects::SingleCommandCp56(v) => cmd!(v, Single),
        Objects::DoubleCommand(v) => cmd!(v, Double),
        Objects::DoubleCommandCp56(v) => cmd!(v, Double),
        Objects::StepCommand(v) => cmd!(v, Step),
        Objects::StepCommandCp56(v) => cmd!(v, Step),
        Objects::SetpointNormalized(v) => cmd!(v, Normalized),
        Objects::SetpointNormalizedCp56(v) => cmd!(v, Normalized),
        Objects::SetpointScaled(v) => cmd!(v, Scaled),
        Objects::SetpointScaledCp56(v) => cmd!(v, Scaled),
        Objects::SetpointFloat(v) => cmd!(v, Float),
        Objects::SetpointFloatCp56(v) => cmd!(v, Float),
        Objects::BitstringCommand(v) => cmd!(v, Bitstring),
        Objects::BitstringCommandCp56(v) => cmd!(v, Bitstring),
        Objects::EndOfInitialization(v) => v.get(i).map(|o| format!("end of initialization, cause {}", o.element.0)),
        Objects::TestCommand(v) => v.get(i).map(|o| format!("test pattern {:#06x}", o.element.0)),
        Objects::TestCommandCp56(v) => v.get(i).map(|o| format!("test counter {}", o.element.0)),
        Objects::ResetProcess(v) => v.get(i).map(|o| format!("reset process, qualifier {}", o.element.0)),
        Objects::DelayAcquisition(v) => v.get(i).map(|o| format!("acquisition delay {}", o.element.0)),
        Objects::ParameterNormalized(v) => describe!(v),
        Objects::ParameterScaled(v) => describe!(v),
        Objects::ParameterFloat(v) => describe!(v),
        Objects::ParameterActivation(v) => describe!(v),
        Objects::FileReady(v) => describe!(v),
        Objects::SectionReady(v) => describe!(v),
        Objects::CallSelect(v) => describe!(v),
        Objects::LastSection(v) => describe!(v),
        Objects::FileAck(v) => describe!(v),
        Objects::Segment(v) => v.get(i).map(|o| format!("file {}, section {}, {} octets", o.element.name, o.element.section, o.element.data.len())),
        Objects::QueryLog(v) => describe!(v),
        Objects::Directory(v) => v.get(i).map(|o| format!("file {}, {} octets, status {:#04x}", o.element.name, o.element.length, o.element.status)),
        _ => None,
    };
    label.unwrap_or_else(|| format!("{} [{}]", objects.type_id().description().unwrap_or("element"), hex(bytes)))
}
