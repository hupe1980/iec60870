//! Exercise file-service ASDU dispatch in both station roles.
#![no_main]

#[path = "../../tests/station_support/mod.rs"]
mod rig;

use iec60870::prelude::*;
use iec60870::station::{FileName, GroupId, MemoryFileStore};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let ca = CommonAddress(1);
    let ioa = Ioa(1);
    let mut store = MemoryFileStore::new();
    store.insert(ca, ioa, FileName(2), [1, 2, 3]);
    let mut server = rig::Rig::new(rig::database(), Default::default());
    server.station.set_file_store(store);
    let connection = server.connect(GroupId(0));
    server.start(connection);
    let mut client = rig::MasterRig::new(Default::default());
    let _ = client.master.download(ca, ioa, 2, client.now);
    client.pump();
    // One length byte per ASDU. Limit each link submission to its supported payload.
    let mut rest = data;
    for _ in 0..64 {
        let Some((&size, payload)) = rest.split_first() else { break };
        let n = usize::from(size).min(249).min(payload.len());
        let (frame, tail) = payload.split_at(n);
        rest = tail;
        if server.masters[connection].link.submit(frame, server.now).is_ok() {
            server.pump();
        }
        if client.outstation.submit(frame, client.now).is_ok() {
            client.pump();
        }
    }
});
