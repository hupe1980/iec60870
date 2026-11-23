//! File service state owned by one connection.
use super::{Asdu, Cause, CommonAddress, ControlledStation, Cot, InformationObject, Instant, Ioa, Objects, Output, ServerEvent, StationLink, TypeId};
use crate::station::{FileName, checksum};
use crate::types::{FileReady, LastSection, SectionReady, Segment};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Selected,
    Ready,
    Sending,
    SectionAck,
    FileAck,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Transfer {
    ca: CommonAddress,
    ioa: Ioa,
    name: u16,
    requested_name: u16,
    cot: Cot,
    length: u32,
    offset: u32,
    section_start: u32,
    section_end: u32,
    section: u8,
    sum: u8,
    file_sum: u8,
    repeats: u8,
    phase: Phase,
    pub deadline: Instant,
}

impl<L: StationLink> ControlledStation<L> {
    pub(super) fn end_file(&mut self, i: usize, outcome: super::super::TransferOutcome) {
        let Some(c) = self.connections.get_mut(i) else { return };
        if let Some(t) = c.transfer.take() {
            self.out.push_back(Output::Event(ServerEvent::FileTransfer {
                connection: c.id,
                common_address: t.ca,
                ioa: t.ioa,
                name: FileName(t.name),
                outcome,
            }));
        }
    }

    fn select_file(&mut self, i: usize, a: &Asdu, ioa: Ioa, name: u16) {
        use super::super::TransferOutcome;
        let ca = a.common_address;
        self.end_file(i, TransferOutcome::Superseded);
        let Some(store) = &self.file_store else { return };
        let Some((selected, length)) = store.select(ca, ioa, FileName(name)) else {
            let known = self.database.has_common_address(ca) || !store.directory_with_limit(ca, 1).is_empty();
            return self.mirror(i, a, if known { Cause::UNKNOWN_IOA } else { Cause::UNKNOWN_COMMON_ADDRESS }, true);
        };
        let cfg = self.config.files;
        let size = cfg.section_size.clamp(1, 0xff_ffff);
        let ok = length <= cfg.max_length.min(0xff_ffff)
            && length.div_ceil(size) <= 255
            && (120..=125).all(|n| self.config.profile.permits(TypeId(n)))
            && usize::from(self.config.profile.max_asdu_len) >= self.config.profile.header_len() + self.config.profile.ioa.octets() + 7;
        let ready = FileReady { name: selected.0, length: if ok { length } else { 0 }, qualifier: if ok { 0 } else { 128 } };
        if ok && let Some(c) = self.connections.get_mut(i) {
            c.transfer = Some(Transfer {
                ca,
                ioa,
                name: selected.0,
                requested_name: name,
                cot: a.cot,
                length,
                offset: 0,
                section_start: 0,
                section_end: length.min(size),
                section: 1,
                sum: 0,
                file_sum: 0,
                repeats: 0,
                phase: Phase::Selected,
                deadline: self.now + cfg.timeout,
            });
        }
        self.reply(i, &Asdu::new(ca, a.cot, InformationObject::new(ioa, ready)));
    }
    pub(super) fn file_call(&mut self, i: usize, a: &Asdu) {
        use super::super::TransferOutcome;
        let ca = a.common_address;
        let ioa = a.objects.ioa(0).unwrap_or_default();
        if a.len() != 1 || a.cot.negative || ca.0 == self.config.profile.ca.max() {
            return self.mirror(i, a, Cause::UNKNOWN_CAUSE, true);
        }
        let (name, section, action, ack) = match &a.objects {
            Objects::CallSelect(o) => {
                let Some(o) = o.first() else { return };
                (o.element.name, o.element.section, o.element.qualifier, false)
            }
            Objects::FileAck(o) => {
                let Some(o) = o.first() else { return };
                (o.element.name, o.element.section, o.element.qualifier, true)
            }
            _ => return,
        };
        if !ack && action == 1 && section == 0 {
            return self.select_file(i, a, ioa, name);
        }
        let Some(mut t) = self.connections.get(i).and_then(|c| c.transfer) else { return self.mirror(i, a, Cause::FILE_TRANSFER, true) };
        let original_selection = !ack && action == 3 && section == 0 && t.phase == Phase::Selected && name == t.requested_name;
        if (ca, ioa, a.cot) != (t.ca, t.ioa, t.cot) || (name != t.name && !original_selection) {
            return self.mirror(i, a, Cause::FILE_TRANSFER, true);
        }
        let end = |qualifier| Asdu::new(ca, a.cot, InformationObject::new(ioa, LastSection { name, section: t.section, qualifier, checksum: t.file_sum }));
        match (ack, action, t.phase) {
            (false, 3, _) if section == 0 => return self.end_file(i, TransferOutcome::Rejected),
            (true, 1, Phase::FileAck) if section == t.section => return self.end_file(i, TransferOutcome::Completed),
            (true, q, _) if q & 15 == 2 && section == t.section => return self.end_file(i, TransferOutcome::Rejected),
            (false, 2, Phase::Selected) if section == 0 => t.phase = Phase::Ready,
            (false, 6, Phase::Ready) if section == t.section => t.phase = Phase::Sending,
            (true, 3, Phase::SectionAck) if section == t.section => {
                t.file_sum = t.file_sum.wrapping_add(t.sum);
                if t.offset == t.length {
                    t.phase = Phase::FileAck;
                    self.reply(i, &Asdu::new(ca, a.cot, InformationObject::new(ioa, LastSection { name, section, qualifier: 1, checksum: t.file_sum })));
                } else {
                    t.section += 1;
                    t.section_start = t.offset;
                    t.section_end = t.length.min(t.offset.saturating_add(self.config.files.section_size.clamp(1, 0xff_ffff)));
                    t.repeats = 0;
                    t.sum = 0;
                    t.phase = Phase::Ready;
                }
            }
            (true, q, Phase::SectionAck) if q & 15 == 4 && section == t.section => {
                if t.repeats >= 3 {
                    self.reply(i, &end(4));
                    return self.end_file(i, TransferOutcome::Rejected);
                }
                t.repeats += 1;
                t.offset = t.section_start;
                t.sum = 0;
                t.phase = Phase::Ready;
            }
            _ => return self.mirror(i, a, Cause::FILE_TRANSFER, true),
        }
        if t.phase == Phase::Ready {
            self.reply(
                i,
                &Asdu::new(
                    ca,
                    a.cot,
                    InformationObject::new(ioa, SectionReady { name, section: t.section, length: t.section_end - t.section_start, qualifier: 0 }),
                ),
            );
        }
        t.deadline = self.now + self.config.files.timeout;
        if let Some(c) = self.connections.get_mut(i) {
            c.transfer = Some(t);
        }
    }

    pub(super) fn queue_file_segment(&mut self, i: usize) -> bool {
        let Some(mut t) = self.connections.get(i).and_then(|c| c.transfer) else { return false };
        if t.phase != Phase::Sending {
            return false;
        }
        let profile = self.config.profile;
        let Some(c) = self.connections.get(i) else { return false };
        let cap = usize::from(profile.max_asdu_len).min(c.link.max_asdu_len()).saturating_sub(profile.header_len() + profile.ioa.octets() + 4);
        let len = (t.section_end - t.offset) as usize;
        let reply = if len == 0 {
            t.phase = Phase::SectionAck;
            Asdu::new(t.ca, t.cot, InformationObject::new(t.ioa, LastSection { name: t.name, section: t.section, qualifier: 3, checksum: t.sum }))
        } else {
            let mut data = alloc::vec![0;len.min(cap)];
            let count = self.file_store.as_mut().and_then(|s| s.read(t.ca, t.ioa, FileName(t.name), t.offset, &mut data));
            let Some(n) = count.filter(|n| *n > 0 && *n <= data.len()) else {
                self.reply(
                    i,
                    &Asdu::new(t.ca, t.cot, InformationObject::new(t.ioa, LastSection { name: t.name, section: t.section, qualifier: 2, checksum: 0 })),
                );
                self.end_file(i, super::super::TransferOutcome::StoreFailed);
                return true;
            };
            data.truncate(n);
            t.offset += u32::try_from(n).unwrap_or_default();
            t.sum = t.sum.wrapping_add(checksum(&data));
            Asdu::new(t.ca, t.cot, InformationObject::new(t.ioa, Segment { name: t.name, section: t.section, data }))
        };
        t.deadline = self.now + self.config.files.timeout;
        if let Some(c) = self.connections.get_mut(i) {
            c.transfer = Some(t);
        }
        self.reply(i, &reply);
        true
    }
}
