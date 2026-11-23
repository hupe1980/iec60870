//! File retrieval through the station and blocking client APIs.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod station_support;
use iec60870::prelude::*;
use iec60870::station::{ClientConfig, FileConfig, FileError, FileName, MemoryFileStore, Progress, ServerConfig};
use station_support::{MasterRig, database};
const CA: CommonAddress = CommonAddress(1);
#[test]
fn download_is_byte_exact_across_sections_and_profiles() {
    for profile in [Profile::IEC101, Profile::IEC104] {
        let data: Vec<_> = (0..=255u8).cycle().take(3100).collect();
        let mut store = MemoryFileStore::new();
        store.insert(CA, Ioa(7), FileName(2), data.clone());
        store.insert(CA, Ioa(8), FileName(2), []);
        let server = iec60870::Server::builder()
            .config(ServerConfig { profile, files: FileConfig { section_size: 600, ..FileConfig::default() }, ..ServerConfig::default() })
            .files(store)
            .bind("127.0.0.1:0", database())
            .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = server.spawn(iec60870::station::RefuseCommands).unwrap();
        let mut client = iec60870::Client::builder().config(ClientConfig { profile, ..ClientConfig::default() }).connect(addr).unwrap();
        client.start().unwrap();
        assert_eq!(client.download(CA, Ioa(7), FileName(0)).unwrap(), data);
        assert_eq!(client.download(CA, Ioa(8), FileName(2)).unwrap(), []);
        assert!(matches!(client.download(CA,Ioa(9),FileName(2)),Err(iec60870::Error::Negative{cot}) if cot.cause==Cause::UNKNOWN_IOA));
        handle.shutdown();
    }
}
#[test]
fn download_rejects_oversized_file_before_calling_it() {
    let mut r = MasterRig::new(ClientConfig { files: FileConfig { max_length: 1, ..FileConfig::default() }, ..ClientConfig::default() });
    let id = r.master.download(CA, Ioa(7), FileName(2), r.now).unwrap();
    r.reply(&Asdu::new(CA, Cot::FILE_TRANSFER, InformationObject::new(Ioa(7), FileReady { name: 2, length: 2, qualifier: 0 })));
    assert!(
        r.events.iter().any(|e| matches!(e,Event::Request{id:i,progress:Progress::Failed(iec60870::Error::File(FileError::TooLarge{length:2}))} if *i==id))
    );
}

fn response(objects: impl Into<Objects>) -> Asdu {
    Asdu::new(CA, Cot::FILE_TRANSFER, objects)
}

#[test]
fn checksum_failure_retries_only_the_bad_section_and_rejects_a_bad_file() {
    for (retry_bad, file_bad) in [(false, false), (true, false), (false, true)] {
        let mut r = MasterRig::new(ClientConfig::default());
        let ioa = Ioa(9);
        let _ = r.master.download(CA, ioa, 2, r.now).unwrap();
        r.reply(&response(InformationObject::new(ioa, FileReady { name: 2, length: 2, qualifier: 0 })));
        for attempt in 0..2 {
            r.reply(&response(InformationObject::new(ioa, SectionReady { name: 2, section: 1, length: 2, qualifier: 0 })));
            r.reply(&response(InformationObject::new(ioa, Segment { name: 2, section: 1, data: vec![1, 2] })));
            let bad = attempt == 0 || retry_bad;
            r.reply(&response(InformationObject::new(ioa, LastSection { name: 2, section: 1, qualifier: 3, checksum: if bad { 4 } else { 3 } })));
            let afq = if attempt == 0 {
                0x24
            } else if retry_bad {
                0x22
            } else {
                3
            };
            assert!(matches!(&r.received.last().unwrap().objects,Objects::FileAck(o) if o[0].element.qualifier==afq));
        }
        if !retry_bad {
            r.reply(&response(InformationObject::new(ioa, LastSection { name: 2, section: 1, qualifier: 1, checksum: if file_bad { 4 } else { 3 } })));
        }
        if retry_bad || file_bad {
            assert!(r.events.iter().any(|e|matches!(e, Event::Request{progress:Progress::Failed(iec60870::Error::File(FileError::Checksum{section})),..} if *section==retry_bad.then_some(1))));
            assert!(!r.events.iter().any(|e| matches!(e, Event::File { .. })));
        } else {
            assert!(r.events.iter().any(|e| matches!(e,Event::File{data,..} if data==&[1,2])));
        }
    }
}
#[test]
fn section_overrun_fails_before_returning_data() {
    let mut r = MasterRig::new(ClientConfig::default());
    let ioa = Ioa(1);
    let _ = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.reply(&response(InformationObject::new(ioa, FileReady { name: 2, length: 2, qualifier: 0 })));
    r.reply(&response(InformationObject::new(ioa, SectionReady { name: 2, section: 1, length: 1, qualifier: 0 })));
    r.reply(&response(InformationObject::new(ioa, Segment { name: 2, section: 1, data: vec![1, 2] })));
    assert!(r.events.iter().any(|e| matches!(e, Event::Request { progress: Progress::Failed(iec60870::Error::File(FileError::Protocol(_))), .. })));
    assert!(!r.events.iter().any(|e| matches!(e, Event::File { .. })));
}
#[test]
fn selection_is_connection_scoped_and_released_on_timeout_and_disconnect() {
    use iec60870::station::{GroupId, ServerEvent, TransferOutcome};
    let mut store = MemoryFileStore::new();
    store.insert(CA, Ioa(7), FileName(2), [1]);
    let mut r = station_support::Rig::new(
        database(),
        ServerConfig { files: FileConfig { timeout: core::time::Duration::from_secs(1), ..FileConfig::default() }, ..ServerConfig::default() },
    );
    r.station.set_file_store(store);
    let first = r.connect(GroupId(0));
    let group = r.station.add_group();
    let other = r.connect(group);
    r.start(first);
    r.start(other);
    let call = |qualifier| response(InformationObject::new(Ioa(7), CallSelect { name: 2, section: 0, qualifier }));
    r.send(first, &call(1));
    r.send(first, &call(1));
    assert!(r.events.iter().any(|e| matches!(e, ServerEvent::FileTransfer { outcome: TransferOutcome::Superseded, .. })));
    r.send(other, &call(2));
    assert!(r.take(other).iter().any(|a| a.cot.negative && a.type_id() == TypeId::F_SC_NA_1));
    r.advance(core::time::Duration::from_secs(2));
    assert!(r.events.iter().any(|e| matches!(e, ServerEvent::FileTransfer { outcome: TransferOutcome::TimedOut, .. })));
    r.send(first, &call(1));
    r.station.handle_disconnect(r.masters[first].id, r.now);
    r.pump();
    assert!(r.events.iter().any(|e| matches!(e, ServerEvent::FileTransfer { outcome: TransferOutcome::Disconnected, .. })));
}

#[test]
fn interrupted_client_drops_partial_download() {
    use iec60870::driver::Protocol;
    let mut r = MasterRig::new(ClientConfig::default());
    let ioa = Ioa(7);
    let id = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.reply(&response(InformationObject::new(ioa, FileReady { name: 2, length: 2, qualifier: 0 })));
    r.reply(&response(InformationObject::new(ioa, SectionReady { name: 2, section: 1, length: 2, qualifier: 0 })));
    r.reply(&response(InformationObject::new(ioa, Segment { name: 2, section: 1, data: vec![1] })));
    r.master.handle_disconnect(r.now);
    r.pump();
    assert!(r.events.iter().any(|e| matches!(e,Event::Request{id:r,progress:Progress::Failed(iec60870::Error::Disconnected(_))} if *r==id)));
    assert!(!r.events.iter().any(|e| matches!(e, Event::File { .. })));
}

#[test]
fn file_ready_rejects_oversize_and_completion_reports_the_file_identity() {
    use iec60870::station::{GroupId, ServerEvent, TransferOutcome};
    let mut store = MemoryFileStore::new();
    store.insert(CA, Ioa(7), FileName(2), [1, 2]);
    store.insert(CA, Ioa(8), FileName(2), [1]);
    let mut r = station_support::Rig::new(database(), ServerConfig { files: FileConfig { max_length: 1, ..FileConfig::default() }, ..ServerConfig::default() });
    r.station.set_file_store(store);
    let m = r.connect(GroupId(0));
    r.start(m);
    let call = |ioa, section, qualifier| response(InformationObject::new(Ioa(ioa), CallSelect { name: 2, section, qualifier }));
    r.send(m, &call(7, 0, 1));
    assert!(r.take(m).iter().any(|a| matches!(&a.objects,Objects::FileReady(o) if o[0].element.qualifier==128 && o[0].element.length==0)));
    for (sec, action) in [(0, 1), (0, 2), (1, 6)] {
        r.send(m, &call(8, sec, action));
    }
    for qualifier in [3, 1] {
        r.send(m, &response(InformationObject::new(Ioa(8), FileAck { name: 2, section: 1, qualifier })));
    }
    assert!(r.events.iter().any(|e|matches!(e,ServerEvent::FileTransfer{connection,common_address:CA,ioa:Ioa(8),name:FileName(2),outcome:TransferOutcome::Completed} if *connection==r.masters[m].id)));
}

#[test]
fn cancel_download_targets_one_request_and_uses_resolved_name() {
    let mut r = MasterRig::new(ClientConfig::default());
    let point = r.master.read(CA, Ioa(8), r.now).unwrap();
    let id = r.master.download(CA, Ioa(7), FileName(0), r.now).unwrap();
    r.reply(&response(InformationObject::new(Ioa(7), FileReady { name: 2, length: 8, qualifier: 0 })));
    assert!(!r.master.cancel_download(point, r.now));
    assert!(r.master.cancel_download(id, r.now));
    assert!(!r.master.cancel_download(id, r.now));
    r.pump();
    assert!(r.master.is_pending(point));
    assert!(matches!(&r.received.last().unwrap().objects,Objects::CallSelect(o) if o[0].element==CallSelect{name:2,section:0,qualifier:3}));
    assert!(r.events.iter().any(|e| matches!(e, Event::Request{id:r,progress:Progress::Failed(iec60870::Error::File(FileError::Cancelled))} if *r==id)));
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn dropping_download_future_deactivates_selected_file() {
    use core::future::{Future, poll_fn};
    use core::task::Poll;
    use iec60870::station::{RefuseCommands, ServerEvent, TransferOutcome};
    let mut store = MemoryFileStore::new();
    store.insert(CA, Ioa(7), FileName(2), [1, 2, 3]);
    let server = iec60870::Server::builder().files(store).bind_async("127.0.0.1:0", database()).await.unwrap();
    let addr = server.local_addr();
    let handle = server.handle();
    let task = tokio::spawn(server.run(RefuseCommands));
    let mut client = iec60870::AsyncClient::connect(addr).await.unwrap();
    client.start().await.unwrap();
    {
        let mut download = Box::pin(client.download(CA, Ioa(7), FileName(0)));
        poll_fn(|cx| {
            assert!(download.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if matches!(
                client.next_event().await.unwrap(),
                Some(Event::Request { progress: Progress::Failed(iec60870::Error::File(FileError::Cancelled)), .. })
            ) {
                break;
            }
        }
        loop {
            if matches!(
                handle.next_event(std::time::Duration::from_secs(1)).await,
                Some(ServerEvent::FileTransfer { ioa: Ioa(7), name: FileName(2), outcome: TransferOutcome::Rejected, .. })
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(client.download(CA, Ioa(7), FileName(2)).await.unwrap(), [1, 2, 3]);
    handle.shutdown();
    task.await.unwrap().unwrap();
}

#[test]
fn timeout_deactivates_and_retry_waits_for_ordered_confirmation() {
    let mut r = MasterRig::new(ClientConfig { confirmation_timeout: std::time::Duration::from_secs(1), ..ClientConfig::default() });
    let ioa = Ioa(7);
    let first = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.pump();
    r.advance(std::time::Duration::from_secs(2));
    assert!(!r.master.is_pending(first));
    assert!(matches!(&r.received.last().unwrap().objects,Objects::CallSelect(o) if o[0].element.qualifier==3));
    let abandoned_retry = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.pump();
    let mut stale_confirmation = r.received.last().unwrap().clone();
    stale_confirmation.cot = Cot::ACTIVATION_CON;
    let sent = r.received.len();
    assert!(r.master.cancel_download(abandoned_retry, r.now));
    r.pump();
    assert_eq!(r.received.len(), sent, "the retry never sent a select to deactivate");
    let retry = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.pump();
    let mut confirmation = r.received.last().unwrap().clone();
    assert_eq!(confirmation.type_id(), TypeId::C_TS_TA_1);
    r.reply(&stale_confirmation);
    assert_eq!(r.received.last().unwrap().type_id(), TypeId::C_TS_TA_1);
    r.reply(&response(InformationObject::new(ioa, FileReady { name: 2, length: 17, qualifier: 0 })));
    assert_eq!(r.received.last().unwrap().type_id(), TypeId::C_TS_TA_1);
    confirmation.cot = Cot::ACTIVATION_CON;
    r.reply(&confirmation);
    assert!(matches!(&r.received.last().unwrap().objects,Objects::CallSelect(o) if o[0].element.qualifier==1));
    assert!(r.master.is_pending(retry));
}

#[test]
fn cancelled_downloads_late_reply_cannot_supply_successor_contents() {
    let mut r = MasterRig::new(ClientConfig::default());
    let ioa = Ioa(7);
    let first = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.pump();
    assert!(r.master.cancel_download(first, r.now));
    let retry = r.master.download(CA, ioa, 2, r.now).unwrap();
    r.pump();
    let mut fence = r.received.last().unwrap().clone();
    // Old record length deliberately differs from the record served to the retry.
    r.reply(&response(InformationObject::new(ioa, FileReady { name: 2, length: 17, qualifier: 0 })));
    fence.cot = Cot::ACTIVATION_CON;
    r.reply(&fence);
    r.reply(&response(InformationObject::new(ioa, FileReady { name: 2, length: 2, qualifier: 0 })));
    r.reply(&response(InformationObject::new(ioa, SectionReady { name: 2, section: 1, length: 2, qualifier: 0 })));
    r.reply(&response(InformationObject::new(ioa, Segment { name: 2, section: 1, data: vec![31, 47] })));
    for qualifier in [3, 1] {
        r.reply(&response(InformationObject::new(ioa, LastSection { name: 2, section: 1, qualifier, checksum: 78 })));
    }
    let files: Vec<_> = r
        .events
        .iter()
        .filter_map(|event| match event {
            Event::File { id, data, .. } => Some((*id, data.as_slice())),
            _ => None,
        })
        .collect();
    assert_eq!(files, [(retry, [31, 47].as_slice())]);
}

#[test]
fn failed_retry_confirmation_never_selects_a_file() {
    for rejected in [true, false] {
        let mut r = MasterRig::new(ClientConfig { confirmation_timeout: std::time::Duration::from_secs(1), ..ClientConfig::default() });
        let first = r.master.download(CA, Ioa(7), 2, r.now).unwrap();
        assert!(r.master.cancel_download(first, r.now));
        let retry = r.master.download(CA, Ioa(7), 2, r.now).unwrap();
        r.pump();
        let count = r.received.len();
        if rejected {
            let mut rejection = r.received.last().unwrap().clone();
            rejection.cot = Cot::ACTIVATION_CON.negative();
            r.reply(&rejection);
        } else {
            r.advance(std::time::Duration::from_secs(2));
        }
        assert!(!r.master.is_pending(retry));
        assert_eq!(r.received.len(), count);
        assert!(r.events.iter().any(|e| matches!(e,Event::Request{id,progress:Progress::Failed(_)} if *id==retry)));
    }
}
