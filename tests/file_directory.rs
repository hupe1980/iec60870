//! File directory procedure over the public station and client APIs.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod station_support;

use iec60870::prelude::*;
use iec60870::station::{ClientConfig, FileName, FileStatus, GroupId, MemoryFileStore, Progress, ServerConfig};
use station_support::{MasterRig, Rig, database};

const CA: CommonAddress = CommonAddress(1);

fn records() -> MemoryFileStore {
    let mut store = MemoryFileStore::new();
    for n in 0..40 {
        store.insert(CA, Ioa(n), FileName(2), [1, 2, 3]);
    }
    store
}

#[test]
fn directory_frames_fit_both_profiles_and_only_the_last_entry_ends_the_listing() {
    for profile in [Profile::IEC101, Profile::IEC104] {
        let mut rig = Rig::new(database(), ServerConfig { profile, end_of_initialization: None, ..ServerConfig::default() });
        rig.station.set_file_store(records());
        let m = rig.connect(GroupId(0));
        rig.start(m);
        let call = CallSelect { name: 0, section: 0, qualifier: 0 };
        rig.send(m, &Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(0), call)));
        let replies = rig.take(m);
        assert!(replies.len() > 1);
        let mut count = 0;
        for a in replies {
            assert_eq!(a.type_id(), TypeId::F_DR_TA_1);
            assert_eq!(a.cot, Cot::REQUEST);
            assert!(a.encoded_len(&profile) <= usize::from(profile.max_asdu_len));
            let Objects::Directory(entries) = a.objects else { unreachable!() };
            for item in entries {
                assert_eq!(item.ioa, Ioa(count));
                count += 1;
                assert_eq!(FileStatus(item.element.status).is_last(), count == 40);
            }
        }
        assert_eq!(count, 40);
    }
}

#[test]
fn malformed_end_marker_fails_request_and_releases_it() {
    let mut rig = MasterRig::new(ClientConfig::default());
    let id = rig.master.directory(CA, rig.now).unwrap();
    let entry = InformationObject::new(Ioa(3), DirectoryEntry { name: 2, length: 3, status: FileStatus::LAST_FILE }).at(station_support::clock());
    rig.reply(&Asdu::new(CA, Cot::REQUEST, [entry.clone(), entry]));
    assert!(rig.events.iter().any(|e| matches!(e,Event::Request {id:r,progress:Progress::Failed(iec60870::Error::InvalidDirectory)} if *r==id)));
    assert!(rig.master.directory(CA, rig.now).is_ok());
}

#[cfg(feature = "std")]
#[test]
fn blocking_client_collects_complete_empty_and_unknown_directories() {
    let mut db = database();
    db.insert(CommonAddress(2), Ioa(1), false);
    let server = iec60870::Server::builder().files(records()).bind("127.0.0.1:0", db).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.spawn(iec60870::station::RefuseCommands).unwrap();
    let mut client = iec60870::Client::connect(addr).unwrap();
    client.start().unwrap();
    let listing = client.files(CA).unwrap();
    assert_eq!(listing.len(), 40);
    assert!(listing.iter().all(|f| f.name == FileName(2) && f.length == 3));
    assert_eq!(client.files(CommonAddress(2)).unwrap(), []);
    assert!(matches!(client.files(CommonAddress(3)), Err(iec60870::Error::Negative {cot}) if cot.cause==Cause::UNKNOWN_COMMON_ADDRESS));
    handle.shutdown();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_client_collects_directory_from_async_server() {
    let server = iec60870::Server::builder().files(records()).bind_async("127.0.0.1:0", database()).await.unwrap();
    let addr = server.local_addr();
    let handle = server.handle();
    let task = tokio::spawn(server.run(iec60870::station::RefuseCommands));
    let mut client = iec60870::AsyncClient::connect(addr).await.unwrap();
    client.start().await.unwrap();
    assert_eq!(client.files(CA).await.unwrap().len(), 40);
    assert_eq!(client.download(CA, Ioa(1), FileName(2)).await.unwrap(), [1, 2, 3]);
    handle.shutdown();
    task.await.unwrap().unwrap();
}

#[test]
fn oversized_directory_is_refused_before_any_partial_listing_is_returned() {
    let mut rig = MasterRig::new(ClientConfig::default());
    let id = rig.master.directory(CA, rig.now).unwrap();
    let entry = InformationObject::new(Ioa(1), DirectoryEntry { name: 1, length: 1, status: 0 }).at(station_support::clock());
    let asdu = Asdu::new(CA, Cot::REQUEST, vec![entry; 15]);
    for _ in 0..274 {
        rig.reply(&asdu);
    }
    assert!(!rig.master.is_pending(id));
    assert!(rig.events.iter().any(|e| matches!(e, Event::Request { id:r, progress:Progress::Failed(iec60870::Error::InvalidDirectory)} if *r == id)));
    assert!(!rig.events.iter().any(|e| matches!(e, Event::Directory { .. })));
}

#[test]
fn incomplete_directory_times_out_and_another_station_cannot_finish_it() {
    let mut rig = MasterRig::new(ClientConfig { confirmation_timeout: core::time::Duration::from_secs(1), ..ClientConfig::default() });
    let id = rig.master.directory(CA, rig.now).unwrap();
    let entry = InformationObject::new(Ioa(1), DirectoryEntry { name: 1, length: 1, status: FileStatus::LAST_FILE }).at(station_support::clock());
    rig.reply(&Asdu::new(CommonAddress(2), Cot::REQUEST, entry));
    rig.advance(core::time::Duration::from_secs(2));
    assert!(rig.events.iter().any(|e| matches!(e, Event::Request {id:r, progress:Progress::Failed(iec60870::Error::Timeout(_))} if *r == id)));
    assert!(!rig.events.iter().any(|e| matches!(e, Event::Directory { .. })));
    assert!(rig.master.directory(CA, rig.now).is_ok());
}

#[test]
fn server_refuses_oversized_catalogs_and_unrepresentable_records() {
    let mut store = MemoryFileStore::new();
    for ioa in 0..=4096 {
        store.insert(CA, Ioa(ioa), FileName(2), []);
    }
    let oversized_ioa = CommonAddress(2);
    store.insert(oversized_ioa, Ioa(65536), FileName(2), []);
    let mut rig = Rig::new(database(), ServerConfig { profile: Profile::IEC101, end_of_initialization: None, ..ServerConfig::default() });
    rig.station.set_file_store(store);
    let m = rig.connect(GroupId(0));
    rig.start(m);
    for address in [CA, oversized_ioa] {
        let call = CallSelect { name: 0, section: 0, qualifier: 0 };
        rig.send(m, &Asdu::new(address, Cot::REQUEST, InformationObject::new(Ioa(0), call)));
        let replies = rig.take(m);
        assert!(matches!(replies.as_slice(), [rejection] if rejection.type_id() == TypeId::F_SC_NA_1 && rejection.cot.negative));
    }
}

#[cfg(feature = "std")]
#[test]
fn one_shot_file_queries_can_discard_unrelated_events() {
    let server = iec60870::Server::builder().files(records()).bind("127.0.0.1:0", database()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.spawn(iec60870::station::RefuseCommands).unwrap();
    for buffer in [true, false] {
        let mut client = iec60870::Client::connect(addr).unwrap();
        if !buffer {
            client.set_event_buffering(false);
        }
        client.start().unwrap();
        assert_eq!(client.files(CA).unwrap().len(), 40);
        let mut saw_initialization = false;
        while let Some(event) = client.poll_event(std::time::Duration::from_millis(25)).unwrap() {
            saw_initialization |= matches!(event, Event::EndOfInitialization { .. });
        }
        assert_eq!(saw_initialization, buffer);
    }
    handle.shutdown();
}
