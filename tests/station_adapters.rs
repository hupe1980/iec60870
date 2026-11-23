//! The adapters end to end over loopback TCP: the blocking and the Tokio client against the
//! blocking and the Tokio server.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec60870::prelude::*;
use iec60870::station::{ServerConfig, ServerEvent};
use iec60870::{AsyncClient, AsyncServer, Client, Error, Server};

const CA: CommonAddress = CommonAddress(1);

fn database() -> Database {
    let mut db = Database::new();
    let _ = db.insert(CA, Ioa(100), false);
    let _ = db.insert(CA, Ioa(200), 21.5f32).group(1);
    let _ = db.insert(CA, Ioa(300), BinaryCounterReading::new(42));
    let _ = db.command(CA, Ioa(5000), CommandKind::Single);
    let _ = db.command(CA, Ioa(5001), CommandKind::Scaled).mode(CommandMode::Direct);
    db
}

type Log = Arc<Mutex<Vec<String>>>;

fn handler(log: &Log, server: Option<iec60870::ServerHandle>) -> impl CommandHandler + Send + 'static {
    let log = Arc::clone(log);
    move |r: &CommandRequest| {
        log.lock().unwrap().push(r.to_string());
        // Report the new position from inside the handler.
        if let (Command::Single(c), Some(s)) = (r.command, &server) {
            assert!(s.peer(r.connection).is_some_and(|addr| addr.ip().is_loopback() && addr.port() != 0));
            s.update(CA, Ioa(100), c.state()).unwrap();
        }
        Decision::Accept
    }
}

fn exercise_blocking_client(addr: std::net::SocketAddr) {
    let mut client = Client::connect(addr).unwrap();
    client.start().unwrap();
    let gi: Vec<Event> = client.interrogate(CA).unwrap().map(Result::unwrap).collect();
    let points: Vec<_> = gi.iter().filter_map(|e| if let Event::Point(p) = e { Some(p.ioa.0) } else { None }).collect();
    assert_eq!(points, [100, 200]);
    assert!(matches!(gi.last(), Some(Event::InterrogationComplete { .. })));

    let group: Vec<_> = client.interrogate_group(CA, 1).unwrap().map(Result::unwrap).collect();
    assert_eq!(group.len(), 2);

    let steps: Vec<_> = client.select_and_execute(CA, Ioa(5000), Command::single(true)).unwrap().map(|s| format!("{:?}", s.unwrap())).collect();
    assert_eq!(steps, ["Selected", "Confirmed", "Completed"]);
    client.command(CA, Ioa(5001), Command::setpoint_scaled(7)).unwrap().wait().unwrap();
    match client.command(CA, Ioa(5000), Command::single(false)).unwrap().wait() {
        Err(Error::Negative { cot }) => assert!(cot.negative && cot.cause == Cause::ACTIVATION_CON),
        other => panic!("{other:?}"),
    }
    match client.command(CA, Ioa(4242), Command::single(false)).unwrap().wait() {
        Err(Error::Negative { cot }) => assert_eq!(cot.cause, Cause::UNKNOWN_IOA),
        other => panic!("{other:?}"),
    }
    client.clock_sync(CA).unwrap();
    client.test_command(CA).unwrap();
    client.reset_process(CA, ResetProcess::GENERAL).unwrap();
    client.parameter(CA, Ioa(200), ParameterFloat { value: 0.5, qualifier: ParameterQualifier::THRESHOLD }).unwrap();
    assert_eq!(client.read(CA, Ioa(200)).unwrap().value, Value::from(21.5f32));
    let counters: Vec<_> = client.counter_interrogate(CA, CounterInterrogation::GENERAL).unwrap().map(Result::unwrap).collect();
    assert!(matches!(&counters[0], Event::Point(p) if p.value == Value::from(BinaryCounterReading::new(42))));
    assert!(matches!(counters.last(), Some(Event::CounterInterrogationComplete { .. })));

    // The breaker's new position arrives spontaneously, time-tagged.
    let mut seen = false;
    while let Some(e) = client.poll_event(Duration::from_millis(300)).unwrap() {
        if let Event::Point(p) = e
            && p.ioa == Ioa(100)
            && p.cause.cause == Cause::SPONTANEOUS
        {
            assert_eq!(p.value, Value::from(true));
            assert!(p.time.is_some());
            seen = true;
        }
    }
    assert!(seen, "the update from the handler was sent");
    client.stop().unwrap();
}

#[test]
fn blocking_client_against_blocking_server() {
    let log = Log::default();
    let server = Server::bind("127.0.0.1:0", database()).unwrap();
    let addr = server.local_addr().unwrap();
    let h = server.handle();
    let handle = server.spawn(handler(&log, Some(h))).unwrap();
    exercise_blocking_client(addr);
    assert_eq!(log.lock().unwrap().len(), 2, "{:?}", log.lock().unwrap());
    assert_eq!(handle.value(CA, Ioa(100)), Some(Value::from(true)));
    handle.shutdown();
}

#[test]
fn events_survive_a_reconnection_through_the_adapters() {
    let server = Server::bind("127.0.0.1:0", database()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.spawn(iec60870::station::RefuseCommands).unwrap();
    for i in 0..5i16 {
        handle.update(CA, Ioa(100), i % 2 == 0).unwrap();
    }
    assert!(handle.update(CA, Ioa(100), 1.0f32).is_err(), "kind checked");
    let mut client = Client::connect(addr).unwrap();
    client.start().unwrap();
    let mut events = 0;
    while let Some(e) = client.poll_event(Duration::from_millis(300)).unwrap() {
        if matches!(e, Event::Point(_)) {
            events += 1;
        }
    }
    // Five spontaneous events (and the end of initialisation before them), held for the master.
    assert_eq!(events, 5);
    assert!(handle.next_event(Duration::from_millis(100)).is_some());
    handle.shutdown();
}

#[test]
fn blocking_client_against_async_server() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let log = Log::default();
    let server = rt.block_on(AsyncServer::bind("127.0.0.1:0", database())).unwrap();
    let addr = server.local_addr();
    let handle = server.handle();
    let h2 = handle.clone();
    let l2 = Arc::clone(&log);
    rt.spawn(server.run(move |r: &CommandRequest| {
        assert!(h2.peer(r.connection).is_some_and(|addr| addr.ip().is_loopback() && addr.port() != 0));
        l2.lock().unwrap().push(r.to_string());
        if let Command::Single(c) = r.command {
            h2.update(CA, Ioa(100), c.state()).unwrap();
        }
        Decision::Accept
    }));
    exercise_blocking_client(addr);
    assert_eq!(log.lock().unwrap().len(), 2);
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_client_against_both_servers() {
    // Tokio server.
    let server = AsyncServer::bind("127.0.0.1:0", database()).await.unwrap();
    let addr = server.local_addr();
    let handle = server.handle();
    tokio::spawn(server.run(|_: &CommandRequest| Decision::Accept));
    exercise_async_client(addr).await;
    assert!(handle.next_event(Duration::from_millis(200)).await.is_some());
    for _ in 0..100 {
        if handle.connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(handle.connections(), 0, "the closed connection is gone");
    handle.shutdown();

    // Blocking server.
    let server = Server::builder().config(ServerConfig::default()).bind("127.0.0.1:0", database()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.spawn(|_: &CommandRequest| Decision::Accept).unwrap();
    exercise_async_client(addr).await;
    handle.shutdown();
}

async fn exercise_async_client(addr: std::net::SocketAddr) {
    let mut client = AsyncClient::connect(addr).await.unwrap();
    client.start().await.unwrap();
    let mut replies = client.interrogate(CA).unwrap();
    let mut n = 0;
    while let Some(e) = replies.next().await {
        if matches!(e.unwrap(), Event::Point(_)) {
            n += 1;
        }
    }
    assert_eq!(n, 2);
    let mut steps = client.select_and_execute(CA, Ioa(5000), Command::single(true)).unwrap();
    let mut seen = Vec::new();
    while let Some(s) = steps.next().await {
        seen.push(format!("{:?}", s.unwrap()));
    }
    assert_eq!(seen, ["Selected", "Confirmed", "Completed"]);
    client.clock_sync(CA).await.unwrap();
    assert_eq!(client.read(CA, Ioa(200)).await.unwrap().value, Value::from(21.5f32));
    assert!(matches!(client.command(CA, Ioa(5000), Command::single(false)).unwrap().wait().await, Err(Error::Negative { .. })));
    client.stop().await.unwrap();
}

#[test]
fn a_redundancy_group_by_address_switches_over() {
    let server = Server::builder().group(["127.0.0.1".parse().unwrap()]).bind("127.0.0.1:0", database()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.spawn(iec60870::station::RefuseCommands).unwrap();
    let mut a = Client::connect(addr).unwrap();
    let mut b = Client::connect(addr).unwrap();
    a.start().unwrap();
    handle.update(CA, Ioa(100), true).unwrap();
    let got = |c: &mut Client| {
        let mut n = 0;
        while let Ok(Some(e)) = c.poll_event(Duration::from_millis(300)) {
            if matches!(e, Event::Point(_)) {
                n += 1;
            }
        }
        n
    };
    assert_eq!(got(&mut a), 1);
    assert_eq!(got(&mut b), 0, "the standby connection receives nothing");
    b.start().unwrap();
    handle.update(CA, Ioa(100), false).unwrap();
    // The event a had not acknowledged (w = 8) comes again on b, then the new one.
    assert_eq!(got(&mut b), 2);
    let closed = loop {
        match a.next_event() {
            Ok(None | Some(Event::Disconnected(_))) | Err(_) => break true,
            Ok(Some(_)) => {}
        }
    };
    assert!(closed, "the previously started connection was closed");
    let mut switched = false;
    while let Some(e) = handle.next_event(Duration::from_millis(100)) {
        switched |= matches!(e, ServerEvent::SwitchedOver { .. });
    }
    assert!(switched);
    handle.shutdown();
}

#[test]
fn slow_event_observer_gets_exact_loss_and_keeps_peer_after_close() {
    let server = Server::bind("127.0.0.1:0", database()).unwrap();
    let handle = server.spawn(|_: &CommandRequest| Decision::Accept).unwrap();
    let mut client = Client::connect(handle.local_addr()).unwrap();
    client.start().unwrap();
    for _ in 0..1025 {
        client.clock_sync(CA).unwrap();
    }
    // One STARTDT and 1025 clock records exceeded the 1024-event capacity by two.
    assert!(matches!(handle.next_event_with_peer(Duration::ZERO), Some((ServerEvent::ObserverLagged { count: 2 }, None))));
    let (_, peer) = handle.next_event_with_peer(Duration::ZERO).unwrap();
    let peer = peer.unwrap();
    assert!(peer.ip().is_loopback());
    drop(client);
    loop {
        let (event, source) = handle.next_event_with_peer(Duration::from_secs(3)).unwrap();
        if let ServerEvent::Disconnected { connection, .. } = event {
            assert_eq!(source, Some(peer));
            assert_eq!(handle.peer(connection), None);
            break;
        }
    }
    handle.shutdown();
}
