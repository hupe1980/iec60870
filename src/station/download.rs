//! Receiving a file selected from a peer's catalog.
use super::{FileName, checksum};
use crate::asdu::Objects;
use crate::types::{CallSelect, FileAck};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub(super) struct Download {
    pub name: FileName,
    pub data: Vec<u8>,
    length: Option<usize>,
    section: u8,
    start: usize,
    end: Option<usize>,
    retry: bool,
}

#[derive(Clone, Copy)]
pub(super) enum Step {
    Call(CallSelect),
    Ack(FileAck),
    Done(FileAck),
    FailedChecksum(FileAck, Option<u8>),
    More,
}

impl Download {
    pub fn new(name: FileName) -> Self {
        Self { name, data: Vec::new(), length: None, section: 0, start: 0, end: None, retry: false }
    }

    pub fn receive(&mut self, objects: &Objects, limit: u32) -> Result<Step, super::FileError> {
        use super::FileError::{Aborted, NotReady, Protocol, TooLarge};
        let name = self.name.0;
        let call = |section, qualifier| Step::Call(CallSelect { name, section, qualifier });
        let ack = |section, qualifier| FileAck { name, section, qualifier };
        match objects {
            Objects::FileReady(o) if self.length.is_none() => {
                let f = o.first().ok_or(Protocol("missing file ready"))?.element;
                if name != 0 && f.name != name {
                    return Err(Protocol("unexpected file name"));
                }
                self.name = FileName(f.name);
                if f.qualifier != 0 {
                    return Err(NotReady);
                }
                if f.length > limit {
                    return Err(TooLarge { length: f.length });
                }
                self.length = Some(f.length as usize);
                Ok(Step::Call(CallSelect { name: f.name, section: 0, qualifier: 2 }))
            }
            Objects::SectionReady(o) if self.length.is_some() && self.end.is_none() => {
                let s = o.first().ok_or(Protocol("missing section ready"))?.element;
                let expected = if self.retry { Some(self.section) } else { self.section.checked_add(1) };
                let end = self.data.len().checked_add(s.length as usize);
                if s.name != name || s.qualifier != 0 || Some(s.section) != expected || end.is_none() || end > self.length {
                    return Err(Protocol("invalid file section"));
                }
                self.section = s.section;
                self.start = self.data.len();
                self.end = end;
                Ok(call(s.section, 6))
            }
            Objects::Segment(o) => {
                let s = &o.first().ok_or(Protocol("missing segment"))?.element;
                if s.name != name
                    || s.section != self.section
                    || s.data.is_empty()
                    || self.end.is_none_or(|end| s.data.len() > end.saturating_sub(self.data.len()))
                {
                    return Err(Protocol("invalid file segment"));
                }
                self.data.extend_from_slice(&s.data);
                Ok(Step::More)
            }
            Objects::LastSection(o) => {
                let s = o.first().ok_or(Protocol("missing transfer marker"))?.element;
                if s.name != name {
                    return Err(Protocol("unexpected file name"));
                }
                match s.qualifier {
                    3 if s.section == self.section && self.end == Some(self.data.len()) => {
                        self.end = None;
                        if self.data.get(self.start..).map(checksum) != Some(s.checksum) {
                            self.data.truncate(self.start);
                            if self.retry {
                                return Ok(Step::FailedChecksum(ack(s.section, 0x22), Some(s.section)));
                            }
                            self.retry = true;
                            return Ok(Step::Ack(ack(s.section, 0x24)));
                        }
                        self.retry = false;
                        Ok(Step::Ack(ack(s.section, 3)))
                    }
                    1 if self.end.is_none()
                        && !self.retry
                        && self.length == Some(self.data.len())
                        && (s.section == self.section || s.section == self.section.wrapping_add(1)) =>
                    {
                        if checksum(&self.data) == s.checksum {
                            Ok(Step::Done(ack(s.section, 1)))
                        } else {
                            Ok(Step::FailedChecksum(ack(s.section, 0x22), None))
                        }
                    }
                    2 | 4 => Err(Aborted),
                    _ => Err(Protocol("unexpected end of file or section")),
                }
            }
            _ => Err(Protocol("unexpected file transfer message")),
        }
    }
}
