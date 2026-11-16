use super::{Call, InitializationError, Manager, ProxyHandle, Reply, Request, VmConfig};
use crate::NetType;
use crate::control::Control;
use crate::dhcp_server::DHCP_SERVER_MAC;
use crate::dns_server::DNS_PORT;
use crate::proxy::{Command, Policy};
use crate::wireguard::{self, WireGuard};
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{RData, RecordType, rdata::A};
use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, INVALID_PARAMS_CODE};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use unix_ancillary::UnixStreamExt;
use uuid::Uuid;

const TIMEOUT: Duration = Duration::from_secs(10);

// Use the current user and group for native initialization.
fn native_manager(control: Option<Control>) -> Manager {
    let user = uzers::get_user_by_uid(uzers::get_current_uid()).unwrap();
    let group = uzers::get_group_by_gid(uzers::get_current_gid()).unwrap();

    Manager::new(
        user.name().to_string_lossy().into_owned(),
        group.name().to_string_lossy().into_owned(),
        control,
    )
}

// Clone the descriptor so validation never consumes the caller's socket.
fn vm_config(socket: &impl AsFd, mac: &str) -> VmConfig {
    VmConfig {
        vm_fd: socket.as_fd().try_clone_to_owned().unwrap(),
        vm_mac_address: mac.parse().unwrap(),
        name: None,
        allow: Vec::new(),
        block: Vec::new(),
        exposed_ports: Vec::new(),
    }
}

// Send an RPC and read its response.
async fn rpc(peer: &mut BufReader<tokio::net::UnixStream>, method: &str, params: Value) -> Value {
    let request = json!({"jsonrpc": "2.0", "id": "test", "method": method, "params": params});
    let mut bytes = serde_json::to_vec(&request).unwrap();
    bytes.push(b'\n');
    peer.get_mut().write_all(&bytes).await.unwrap();

    read_reply(peer).await
}

// Read a framed JSON-RPC response and verify its envelope.
async fn read_reply(peer: &mut BufReader<tokio::net::UnixStream>) -> Value {
    let mut line = String::new();
    assert_ne!(
        timeout(TIMEOUT, peer.read_line(&mut line))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], "test");

    response
}

#[tokio::test]
async fn canceling_run_then_shutdown_stops_an_idle_manager() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(socket.into()).unwrap()),
    );

    // Poll the manager once before cancelling its idle run
    tokio::select! {
        biased;
        result = manager.run() => panic!("manager stopped before cancellation: {result:?}"),
        () = async {} => {}
    }

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    peer.set_nonblocking(true).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn canceling_run_during_dispatch_keeps_proxy_cleanup_tracked() {
    let mut manager = Manager::new("unused".into(), "unused".into(), None);
    let id = Uuid::now_v7();
    let (commands_tx, mut commands_rx) = mpsc::channel(1);
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();

    // Hold a policy operation in flight while its dispatch future is cancelled
    manager.proxy_tasks.spawn(id, async move {
        let Some(Command::PolicyGet { reply }) = commands_rx.recv().await else {
            panic!("expected a policy request");
        };

        started_tx.send(()).unwrap();
        release_rx.await.unwrap();
        assert!(reply.send(Policy::default()).is_err());
        assert!(commands_rx.recv().await.is_none());

        Ok(())
    });
    manager.proxy_handles.insert(
        id,
        ProxyHandle {
            commands: commands_tx,
        },
    );

    let (control_calls_tx, control_calls_rx) = mpsc::channel(1);
    manager.control_calls_rx = control_calls_rx;
    let (reply_tx, reply_rx) = oneshot::channel();
    control_calls_tx
        .send(Call {
            request: Request::GetPolicy { vm_id: Some(id) },
            reply: reply_tx,
        })
        .await
        .unwrap();

    timeout(TIMEOUT, async {
        tokio::select! {
            result = manager.run() => panic!("manager stopped before cancellation: {result:?}"),
            result = started_rx => result.unwrap(),
        }
    })
    .await
    .unwrap();

    // Cancellation abandons the RPC reply but shutdown must still join the proxy
    let first_shutdown = timeout(Duration::from_millis(20), manager.shutdown()).await;
    release_tx.send(()).unwrap();
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    assert!(first_shutdown.is_err());
    assert!(reply_rx.await.is_err());
    assert!(manager.proxy_tasks.is_empty());
}

#[tokio::test]
async fn canceled_initialization_and_shutdown_keep_the_blocking_worker_tracked() {
    let mut manager = Manager::new("unused".into(), "unused".into(), None);
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = oneshot::channel();

    // Keep the initialization worker blocked until the test releases it
    manager.initialization = Some(tokio::task::spawn_blocking(move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        finished_tx.send(()).unwrap();

        Ok(())
    }));

    let mut ready = Box::pin(manager.finish_initialization());

    // Cancel the waiter while the manager still owns its blocking worker
    let started = timeout(TIMEOUT, async {
        tokio::select! {
            result = &mut ready => panic!("initialization finished before release: {result:?}"),
            result = started_rx => result.unwrap(),
        }
    })
    .await;
    drop(ready);

    let first_shutdown = timeout(Duration::from_millis(20), manager.shutdown()).await;
    let still_tracked = manager.initialization.is_some();

    // Release the worker before assertions so a failure cannot strand the runtime
    release_tx.send(()).unwrap();
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    finished_rx.await.unwrap();
    assert!(started.is_ok());
    assert!(first_shutdown.is_err());
    assert!(still_tracked);
    assert!(manager.initialization.is_none());
    assert!(manager.proxy_tasks.is_empty());
}

#[tokio::test]
async fn canceled_initialization_preserves_worker_errors_for_shutdown() {
    for should_panic in [false, true] {
        let mut manager = Manager::new("unused".into(), "unused".into(), None);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        // Keep the initialization worker blocked until the test releases it
        manager.initialization = Some(tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            assert!(!should_panic, "test initialization panic");

            Err(std::io::Error::other("test initialization failure").into())
        }));

        let mut ready = Box::pin(manager.finish_initialization());

        // The waiter disappears while the blocking worker still owns its work
        let started = timeout(TIMEOUT, async {
            tokio::select! {
                result = &mut ready => panic!("initialization finished before release: {result:?}"),
                result = started_rx => result.unwrap(),
            }
        })
        .await;
        drop(ready);
        release_tx.send(()).unwrap();

        let error = timeout(TIMEOUT, manager.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        let cause = if should_panic {
            "test initialization panic"
        } else {
            "test initialization failure"
        };
        assert!(started.is_ok());
        assert!(format!("{error:#}").contains(cause));
        assert!(manager.initialization.is_none());
        assert!(manager.proxy_tasks.is_empty());

        if !should_panic {
            assert!(error.downcast_ref::<std::io::Error>().is_some());
        }
    }
}

#[tokio::test]
async fn failed_proxy_tasks_stop_run_and_cleanup_remaining_tasks() {
    for should_panic in [false, true] {
        let mut manager = Manager::new("unused".into(), "unused".into(), None);
        let mut cleanup = Vec::new();

        // Other proxies must all finish even if one fails during cleanup
        for id in [Uuid::from_u128(2), Uuid::from_u128(3)] {
            let (commands_tx, mut commands_rx) = mpsc::channel(1);
            let (stopped, finished) = oneshot::channel();
            cleanup.push(finished);
            manager.proxy_tasks.spawn(id, async move {
                assert!(commands_rx.recv().await.is_none());
                let _ = stopped.send(());

                if id == Uuid::from_u128(2) {
                    anyhow::bail!("test cleanup failure");
                }

                Ok(())
            });
            manager.proxy_handles.insert(
                id,
                ProxyHandle {
                    commands: commands_tx,
                },
            );
        }

        let failed_id = Uuid::from_u128(1);
        let (commands_tx, _commands_rx) = mpsc::channel(1);
        manager.proxy_tasks.spawn(failed_id, async move {
            assert!(!should_panic, "test proxy panic");

            anyhow::bail!("test proxy failure");
        });
        manager.proxy_handles.insert(
            failed_id,
            ProxyHandle {
                commands: commands_tx,
            },
        );

        let error = timeout(TIMEOUT, manager.run()).await.unwrap().unwrap_err();
        let message = format!("{error:#}");
        let cause = if should_panic {
            "test proxy panic"
        } else {
            "test proxy failure"
        };
        assert!(message.contains(&failed_id.to_string()), "{message}");
        assert!(message.contains(cause), "{message}");
        assert_eq!(
            manager.proxy_handles.keys().copied().collect::<Vec<_>>(),
            vec![Uuid::from_u128(2), Uuid::from_u128(3)],
        );

        let error = timeout(TIMEOUT, manager.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("test cleanup failure"), "{message}");
        assert!(
            message.contains(&Uuid::from_u128(2).to_string()),
            "{message}"
        );
        assert!(manager.proxy_tasks.is_empty());

        for finished in cleanup {
            finished.await.unwrap();
        }
    }
}

#[tokio::test]
async fn control_only_waits_until_eof() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(socket.into()).unwrap()),
    );
    peer.set_nonblocking(true).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
    let mut run = Box::pin(manager.run());

    // A connected client keeps the manager available for initialization
    assert!(timeout(Duration::from_millis(20), &mut run).await.is_err());

    let client = async {
        peer.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    };
    timeout(TIMEOUT, async {
        let (result, ()) = tokio::join!(&mut run, client);
        result.unwrap();
    })
    .await
    .unwrap();
    drop(run);
    manager.shutdown().await.unwrap();
}

#[tokio::test]
async fn last_vm_completion_closes_connected_control() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(socket.into()).unwrap()),
    );
    manager.initialized = true;
    let (stop_tx, stop_rx) = oneshot::channel();
    manager.proxy_tasks.spawn(Uuid::now_v7(), async move {
        stop_rx.await.unwrap();

        Ok(())
    });
    let mut run = Box::pin(manager.run());

    // Keep the initialized manager alive until its final VM finishes
    tokio::select! {
        biased;
        result = &mut run => panic!("manager stopped before its VM: {result:?}"),
        () = async {} => {}
    }

    stop_tx.send(()).unwrap();
    timeout(TIMEOUT, &mut run).await.unwrap().unwrap();
    drop(run);
    assert!(manager.proxy_tasks.is_empty());
    assert!(manager.control.is_none());

    peer.set_nonblocking(true).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
    assert_eq!(
        timeout(TIMEOUT, peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
async fn control_disconnect_keeps_active_vm_supervised() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(socket.into()).unwrap()),
    );
    manager.initialized = true;
    let (stop_tx, stop_rx) = oneshot::channel();
    manager.proxy_tasks.spawn(Uuid::now_v7(), async move {
        stop_rx.await.unwrap();

        Ok(())
    });
    drop(peer);

    // Make control completion ready before polling the manager's event loop
    let control = manager.control.as_ref().unwrap();
    timeout(TIMEOUT, async {
        while !control.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut run = Box::pin(manager.run());

    tokio::select! {
        biased;
        result = &mut run => panic!("manager stopped with a live VM: {result:?}"),
        () = async {} => {}
    }

    stop_tx.send(()).unwrap();
    timeout(TIMEOUT, &mut run).await.unwrap().unwrap();
    drop(run);
    assert!(manager.control.is_none());
    assert!(manager.proxy_tasks.is_empty());
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
async fn multi_vm_batch_requires_explicit_target_after_vm_completion() {
    let mut manager = Manager::new("unused".into(), "unused".into(), None);
    manager.initialized = true;
    let finished_id = Uuid::now_v7();
    let live_id = Uuid::now_v7();
    let (finished_commands_tx, _) = mpsc::channel(1);
    manager.proxy_handles.insert(
        finished_id,
        ProxyHandle {
            commands: finished_commands_tx,
        },
    );
    let (finished_tx, finished_rx) = oneshot::channel();
    manager.proxy_tasks.spawn(finished_id, async move {
        finished_tx.send(()).unwrap();

        Ok(())
    });
    finished_rx.await.unwrap();

    let (commands_tx, mut commands_rx) = mpsc::channel(1);
    manager.proxy_handles.insert(
        live_id,
        ProxyHandle {
            commands: commands_tx,
        },
    );
    manager.proxy_tasks.spawn(live_id, async move {
        let Some(Command::PolicyGet { reply }) = commands_rx.recv().await else {
            panic!("expected a policy request");
        };

        reply.send(Policy::default()).unwrap();
        assert!(commands_rx.recv().await.is_none());

        Ok(())
    });
    let (reply_tx, reply_rx) = oneshot::channel();

    // Completed tasks do not change whether a multi-VM batch requires an explicit target
    assert!(manager.proxy_handle(None).is_err());

    timeout(
        TIMEOUT,
        manager.dispatch(Call {
            request: Request::GetPolicy {
                vm_id: Some(live_id),
            },
            reply: reply_tx,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        reply_rx.await.unwrap(),
        Ok(Reply::Policy(policy)) if policy == Policy::default()
    ));

    // Observe the completed VM through the same path as the run loop
    let completed = timeout(TIMEOUT, manager.proxy_tasks.join_next())
        .await
        .unwrap()
        .unwrap();
    manager.reap_task(completed).unwrap();
    assert_eq!(manager.proxy_handles.len(), 1);
    assert!(manager.proxy_handle(None).is_err());

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_closes_control_with_an_unanswered_request() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(socket.into()).unwrap()),
    );
    peer.set_nonblocking(true).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();

    // Shutdown must finish even though run has not serviced this request
    let request = json!({
        "jsonrpc": "2.0",
        "id": "test",
        "method": "softnet.policy.get",
        "params": null,
    })
    .to_string()
        + "\n";
    peer.write_all(request.as_bytes()).await.unwrap();
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();

    assert_eq!(
        timeout(TIMEOUT, peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn invalid_batches_preserve_sockets_and_allow_retry() {
    let mut manager = Manager::new("unused".into(), "unused".into(), None);
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let (mut stream, mut stream_peer) = UnixStream::pair().unwrap();
    let mut invalid_socket = vm_config(&socket, "02:00:00:00:00:02");
    invalid_socket.vm_fd = stream.as_fd().try_clone_to_owned().unwrap();

    let oversized = (2..=7)
        .map(|index| vm_config(&socket, &format!("02:00:00:00:00:{index:02x}")))
        .collect();
    let batches = [
        Vec::new(),
        oversized,
        vec![
            vm_config(&socket, "02:00:00:00:00:02"),
            vm_config(&socket, "02:00:00:00:00:02"),
        ],
        vec![vm_config(&socket, "02:00:00:00:00:01")],
        vec![invalid_socket],
    ];

    for batch in batches {
        let error = manager.initialize(NetType::Nat, batch).await.unwrap_err();
        assert!(matches!(error, InitializationError::Rejected(_)));
        assert!(!manager.initialized);
        assert!(manager.proxy_tasks.is_empty());
        assert!(manager.proxy_handles.is_empty());

        socket.send(&[2]).unwrap();
        let mut byte = [0];
        assert_eq!(peer.recv(&mut byte).unwrap(), 1);
        assert_eq!(byte, [2]);
    }

    stream.write_all(&[1]).unwrap();
    let mut byte = [0];
    stream_peer.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [1]);

    timeout(TIMEOUT, manager.run()).await.unwrap().unwrap();
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
async fn rejected_initialization_preserves_descriptor_error_context() {
    let mut manager = Manager::new("unused".into(), "unused".into(), None);
    let (socket, _peer) = UnixStream::pair().unwrap();
    let error = manager
        .initialize(NetType::Nat, vec![vm_config(&socket, "02:00:00:00:00:02")])
        .await
        .unwrap_err();
    assert!(matches!(&error, InitializationError::Rejected(_)));

    // Preserve descriptor context in direct formatting and the caller's error chain
    let message = format!("{error:#}");
    assert!(message.contains("failed to prepare VM at index 0"));
    assert!(message.contains("not a Unix datagram socket"));

    let error = anyhow::Error::new(error);
    assert_eq!(format!("{error:#}"), message);
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string().contains("not a Unix datagram socket"))
    );
}

#[tokio::test]
async fn rejected_rpc_initialization_keeps_control_available() {
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(control_socket.into()).unwrap()),
    );
    let (first_socket, _first_peer) = UnixDatagram::pair().unwrap();
    let (second_socket, _second_peer) = UnixDatagram::pair().unwrap();
    let request = json!({
        "jsonrpc": "2.0",
        "id": "test",
        "method": "softnet.initialize",
        "params": {"vms": [
            {"vmMacAddress": "02:00:00:00:00:02"},
            {"vmMacAddress": "02:00:00:00:00:02"},
        ]},
    });
    control_peer
        .send_fds_all(
            format!("{request}\n").as_bytes(),
            &[&first_socket, &second_socket],
        )
        .unwrap();
    control_peer.set_nonblocking(true).unwrap();
    let mut peer = BufReader::new(tokio::net::UnixStream::from_std(control_peer).unwrap());
    let mut run = Box::pin(manager.run());

    // Manager validation rejects the batch while leaving the control connection usable
    let client = async {
        let reply = read_reply(&mut peer).await;
        assert_eq!(reply["error"]["code"], CALL_EXECUTION_FAILED_CODE);
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("already in use")
        );

        let reply = rpc(&mut peer, "softnet.policy.get", json!({})).await;
        assert_eq!(reply["error"]["code"], INVALID_PARAMS_CODE);
        peer.get_mut().shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    };
    timeout(TIMEOUT, async {
        let (result, ()) = tokio::join!(&mut run, client);
        result.unwrap();
    })
    .await
    .unwrap();
    drop(run);

    assert!(!manager.initialized);
    assert!(manager.initialization.is_none());
    assert!(manager.proxy_tasks.is_empty());
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
async fn policy_requests_before_initialization_reject_missing_vms() {
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "unused".into(),
        "unused".into(),
        Some(Control::new(control_socket.into()).unwrap()),
    );
    control_peer.set_nonblocking(true).unwrap();
    let mut peer = BufReader::new(tokio::net::UnixStream::from_std(control_peer).unwrap());

    let client = async {
        for params in [json!({}), json!({"vmId": Uuid::now_v7()})] {
            let reply = rpc(&mut peer, "softnet.policy.get", params).await;
            assert_eq!(reply["error"]["code"], INVALID_PARAMS_CODE);
        }

        peer.get_mut().shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    };
    timeout(TIMEOUT, async {
        let (result, ()) = tokio::join!(manager.run(), client);
        result.unwrap();
    })
    .await
    .unwrap();

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn native_vm_disconnect_ends_run() {
    let mut manager = native_manager(None);
    let (socket, peer) = UnixDatagram::pair().unwrap();

    // A rejected batch leaves the manager available for valid initialization
    manager
        .initialize(
            NetType::Nat,
            vec![
                vm_config(&socket, "02:00:00:00:00:02"),
                vm_config(&socket, "02:00:00:00:00:02"),
            ],
        )
        .await
        .unwrap_err();
    timeout(
        TIMEOUT,
        manager.initialize(NetType::Nat, vec![vm_config(&socket, "02:00:00:00:00:02")]),
    )
    .await
    .unwrap()
    .unwrap();
    drop(socket);
    let mut run = Box::pin(manager.run());

    // The manager supervises the real VM until its peer disconnects
    assert!(timeout(Duration::from_millis(20), &mut run).await.is_err());
    drop(peer);

    timeout(TIMEOUT, &mut run).await.unwrap().unwrap();
    drop(run);
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn native_batch_exposes_ports_for_every_vm() {
    let mut manager = native_manager(None);
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let mut first = vm_config(&socket, "02:00:00:00:00:02");
    first.exposed_ports = vec!["52222:22".parse().unwrap()];
    let mut second = vm_config(&socket, "02:00:00:00:00:03");
    second.exposed_ports = vec!["52223:22".parse().unwrap(), "58080:80".parse().unwrap()];
    drop(socket);

    // Every VM's forwards are added to the shared network before it starts
    timeout(
        TIMEOUT,
        manager.initialize(NetType::Nat, vec![first, second]),
    )
    .await
    .unwrap()
    .unwrap();

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn native_control_disconnect_keeps_vms_running() {
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = native_manager(Some(Control::new(control_socket.into()).unwrap()));
    let (socket, peer) = UnixDatagram::pair().unwrap();
    timeout(
        TIMEOUT,
        manager.initialize(NetType::Nat, vec![vm_config(&socket, "02:00:00:00:00:02")]),
    )
    .await
    .unwrap()
    .unwrap();
    drop(socket);
    let mut run = Box::pin(manager.run());

    // Losing control leaves the existing VM connected and supervised
    drop(control_peer);
    assert!(timeout(Duration::from_millis(20), &mut run).await.is_err());
    assert_eq!(peer.send(&[0]).unwrap(), 1);
    drop(peer);

    timeout(TIMEOUT, &mut run).await.unwrap().unwrap();
    drop(run);
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn native_batch_rpc_shares_dns_and_preserves_independent_policies() {
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = native_manager(Some(Control::new(control_socket.into()).unwrap()));
    let (first_socket, first_peer) = UnixDatagram::pair().unwrap();
    let (second_socket, second_peer) = UnixDatagram::pair().unwrap();

    let request = json!({
        "jsonrpc": "2.0",
        "id": "test",
        "method": "softnet.initialize",
        "params": {
            "vmNetType": "nat",
            "vms": [
                {"vmMacAddress": "02:00:00:00:00:02", "name": "vm1", "allow": ["@host"]},
                {"vmMacAddress": "02:00:00:00:00:03", "name": "vm2"},
            ],
        },
    });
    control_peer
        .send_fds_all(
            format!("{request}\n").as_bytes(),
            &[&first_socket, &second_socket],
        )
        .unwrap();
    control_peer.set_nonblocking(true).unwrap();
    let mut peer = BufReader::new(tokio::net::UnixStream::from_std(control_peer).unwrap());

    let client = async {
        let reply = read_reply(&mut peer).await;
        drop(first_socket);
        drop(second_socket);
        assert!(reply.get("error").is_none(), "{reply}");
        let vms = reply["result"]["vms"].as_array().unwrap();
        assert_eq!(vms.len(), 2);
        let first = vms[0]["vmId"].as_str().unwrap().to_owned();
        let second = vms[1]["vmId"].as_str().unwrap().to_owned();
        assert_ne!(first, second);
        assert_eq!(
            reply["result"],
            json!({"vms": [
                {"vmId": first, "vmMacAddress": "02:00:00:00:00:02"},
                {"vmId": second, "vmMacAddress": "02:00:00:00:00:03"},
            ]})
        );

        // Tart can discover both native reservations through bootptab
        let addresses = timeout(TIMEOUT, async {
            loop {
                let bootptab = std::fs::read_to_string("/etc/bootptab").unwrap_or_default();
                let addresses = [2_u8, 3]
                    .into_iter()
                    .map(|suffix| {
                        let mac = [2, 0, 0, 0, 0, suffix];

                        bootptab.lines().find_map(|line| {
                            let fields: Vec<_> = line.split_whitespace().collect();

                            if fields.len() < 4
                                || line.trim_start().starts_with('#')
                                || fields[1] != "1"
                            {
                                return None;
                            }

                            let bytes = fields[2]
                                .split(':')
                                .map(|part| u8::from_str_radix(part, 16))
                                .collect::<Result<Vec<_>, _>>()
                                .ok()?;

                            if bytes == mac {
                                fields[3].parse().ok()
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Option<Vec<std::net::Ipv4Addr>>>();

                if let Some(addresses) = addresses {
                    break addresses;
                }

                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        // Both VMs have distinct reserved addresses in the same /29 subnet
        assert_ne!(addresses[0], addresses[1]);
        assert_eq!(u32::from(addresses[0]) >> 3, u32::from(addresses[1]) >> 3);

        // Resolve both VM names through each proxy's shared DNS server
        let subnet = ipnet::Ipv4Net::new(addresses[0], crate::network::SUBNET_PREFIX_LEN).unwrap();
        let gateway = subnet.hosts().next().unwrap();

        for (socket, address, suffix) in [
            (&first_peer, addresses[0], 2),
            (&second_peer, addresses[1], 3),
        ] {
            socket.set_nonblocking(true).unwrap();
            let socket = tokio::net::UnixDatagram::from_std(socket.try_clone().unwrap()).unwrap();

            for (name, expected) in [
                ("vm1.internal.", addresses[0]),
                ("vm2.internal.", addresses[1]),
            ] {
                // Send a DNS query as a complete Ethernet frame from this VM
                let mut query = Message::query();
                query.add_query(Query::query(name.parse().unwrap(), RecordType::A));
                let payload = query.to_vec().unwrap();
                let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, suffix], DHCP_SERVER_MAC.0)
                    .ipv4(address.octets(), gateway.octets(), 64)
                    .udp(53000, DNS_PORT);
                let mut frame = Vec::with_capacity(builder.size(payload.len()));
                builder.write(&mut frame, &payload).unwrap();
                socket.send(&frame).await.unwrap();

                // Ignore unrelated native traffic while waiting for this DNS reply
                let mut frame = [0; 2048];

                let response = loop {
                    let len = socket.recv(&mut frame).await.unwrap();
                    let packet = SlicedPacket::from_ethernet(&frame[..len]).unwrap();
                    let Some(TransportSlice::Udp(udp)) = packet.transport else {
                        continue;
                    };

                    if udp.source_port() != DNS_PORT || udp.destination_port() != 53000 {
                        continue;
                    }

                    let response = Message::from_vec(udp.payload()).unwrap();
                    if response.metadata.id == query.metadata.id {
                        break response;
                    }
                };

                // Both proxies must return the correct reservation for either name
                assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                assert_eq!(response.answers.len(), 1);
                assert_eq!(response.answers[0].data, RData::A(A(expected)));
            }
        }

        // Address each VM explicitly and keep policy changes independent
        let reply = rpc(&mut peer, "softnet.policy.get", json!({})).await;
        assert_eq!(reply["error"]["code"], INVALID_PARAMS_CODE);

        for (id, count) in [(&first, 1), (&second, 0)] {
            let reply = rpc(&mut peer, "softnet.policy.get", json!({"vmId": id})).await;
            assert_eq!(reply["result"]["ruleCount"], count);
        }

        let reply = rpc(
            &mut peer,
            "softnet.policy.set",
            json!({"vmId": second, "allow": ["@host"], "block": []}),
        )
        .await;
        assert_eq!(reply["result"]["allow"], json!(["@host"]));

        let reply = rpc(
            &mut peer,
            "softnet.policy.set",
            json!({"vmId": second, "allow": ["invalid"], "block": []}),
        )
        .await;
        assert_eq!(reply["error"]["code"], INVALID_PARAMS_CODE);

        let reply = rpc(&mut peer, "softnet.policy.get", json!({"vmId": first})).await;
        assert_eq!(reply["result"]["ruleCount"], 1);
    };

    timeout(TIMEOUT, async {
        tokio::select! {
            result = manager.run() => panic!("manager stopped with connected VMs: {result:?}"),
            () = client => {}
        }
    })
    .await
    .unwrap();

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    assert_eq!(
        timeout(TIMEOUT, peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    for peer in [first_peer, second_peer] {
        assert!(peer.send(&[0]).is_err());
    }
}

async fn native_guest_address(guest: &tokio::net::UnixDatagram, mac: [u8; 6]) -> Ipv4Addr {
    use dhcproto::v4::{DhcpOption, Message as DhcpMessage, MessageType};
    use dhcproto::{Decodable, Encodable};

    // Discover the guest's dynamic reservation over its packet socket
    let mut discover = DhcpMessage::default();
    discover.set_xid(42).set_chaddr(&mac);
    discover
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));
    let mut frame = Vec::new();
    PacketBuilder::ethernet2(mac, DHCP_SERVER_MAC.0)
        .ipv4([0; 4], [255; 4], 64)
        .udp(68, 67)
        .write(&mut frame, &discover.to_vec().unwrap())
        .unwrap();
    guest.send(&frame).await.unwrap();

    let mut frame = [0; 2048];
    loop {
        let length = guest.recv(&mut frame).await.unwrap();
        if let Ok(packet) = SlicedPacket::from_ethernet(&frame[..length])
            && let Some(TransportSlice::Udp(udp)) = packet.transport
            && (udp.source_port(), udp.destination_port()) == (67, 68)
        {
            let offer = DhcpMessage::from_bytes(udp.payload()).unwrap();
            assert_eq!(offer.xid(), discover.xid());
            assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
            return offer.yiaddr();
        }
    }
}

fn tcp_ack(source: (Ipv4Addr, u16), destination: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(source.0.octets(), destination.0.octets(), 64)
        .tcp(source.1, destination.1, 10, 1024)
        .ack(20)
        .write(&mut packet, payload)
        .unwrap();
    packet
}

fn ethernet_frame(source: [u8; 6], destination: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let header = etherparse::Ethernet2Header {
        source,
        destination,
        ether_type: etherparse::EtherType::IPV4,
    };
    let mut frame = header.to_bytes().to_vec();
    frame.extend_from_slice(packet);
    frame
}

fn wireguard_config(address: Ipv4Addr, peer_status: &Value) -> Value {
    let port = peer_status["listenPort"].as_u64().unwrap();
    json!({
        "address": address, "routes": ["198.18.0.0/24"],
        "peers": [{
            "publicKey": peer_status["publicKey"], "endpoint": format!("127.0.0.1:{port}"),
            "allowedIPs": ["198.18.0.0/24"]
        }]
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn native_wireguard_rpc_routes_traffic_for_the_selected_vm() {
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = native_manager(Some(Control::new(control_socket.into()).unwrap()));
    let (socket, guest) = tokio::net::UnixDatagram::pair().unwrap();
    let (other_socket, _other_guest) = UnixDatagram::pair().unwrap();
    let mut vm = vm_config(&socket, "02:00:00:00:00:02");
    let other_vm = vm_config(&other_socket, "02:00:00:00:00:03");
    let mac = vm.vm_mac_address.bytes();
    vm.block = vec![
        "in 0.0.0.0/0".parse().unwrap(),
        "out 0.0.0.0/0".parse().unwrap(),
    ];
    let vms = timeout(
        TIMEOUT,
        manager.initialize(NetType::Nat, vec![other_vm, vm]),
    )
    .await
    .unwrap()
    .unwrap();
    let vm_id = vms[1].vm_id;
    control_peer.set_nonblocking(true).unwrap();
    let mut peer = BufReader::new(tokio::net::UnixStream::from_std(control_peer).unwrap());

    let client = async {
        let local = (native_guest_address(&guest, mac).await, 50000);
        let overlay = (Ipv4Addr::new(198, 18, 0, 1), local.1);
        let hub = (Ipv4Addr::new(198, 18, 0, 2), 8080);
        let mut remote = WireGuard::new(wireguard::Config {
            address: hub.0,
            route: "198.18.0.0/24".parse().unwrap(),
            mtu: None,
            peer: None,
        })
        .await
        .unwrap();
        let mut config = wireguard_config(overlay.0, &json!(remote.status()));
        config["vmId"] = json!(vm_id);
        let reply = rpc(&mut peer, "softnet.wireguard.set", config.clone()).await;
        assert!(reply.get("error").is_none(), "{reply}");
        let status = &reply["result"];
        let public_key = status["publicKey"].as_str().unwrap();
        let listen_port = u16::try_from(status["listenPort"].as_u64().unwrap()).unwrap();

        // Clearing a different VM must leave this tunnel available
        let other_vm = json!({"vmId": vms[0].vm_id});
        let reply = rpc(&mut peer, "softnet.wireguard.clear", other_vm).await;
        assert_eq!(reply["result"], json!({}));

        let mut remote_config = wireguard::Config::new(hub.0, "198.18.0.0/24", None).unwrap();
        remote_config.peer = Some(
            wireguard::Peer::new(
                public_key.to_owned(),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen_port),
                0,
            )
            .unwrap(),
        );
        remote.apply(remote_config).unwrap();

        // Only the ACK from the reserved guest MAC and IP should reach the peer
        let wrong_mac = [2, 0, 0, 0, 0, 9];
        for (source_mac, source, payload) in [
            (wrong_mac, local, b"wrong MAC".as_slice()),
            (mac, overlay, b"wrong IP"),
            (mac, local, b"outbound"),
        ] {
            let packet = tcp_ack(source, hub, payload);
            guest
                .send(&ethernet_frame(source_mac, DHCP_SERVER_MAC.0, &packet))
                .await
                .unwrap();
        }
        let mut buffer = [0; 2048];
        let length = remote.receive_ipv4(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], tcp_ack(overlay, hub, b"outbound"));

        // A rejected key and a change to ordinary policy must preserve the live tunnel
        let mut invalid = config.clone();
        invalid["peers"][0]["publicKey"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        invalid["address"] = json!("198.18.0.99");
        let reply = rpc(&mut peer, "softnet.wireguard.set", invalid).await;
        assert_eq!(reply["error"]["code"], CALL_EXECUTION_FAILED_CODE);
        let reply = rpc(
            &mut peer,
            "softnet.policy.set",
            json!({"vmId": vm_id, "allow": [], "block": ["in 0.0.0.0/0"]}),
        )
        .await;
        assert!(reply.get("error").is_none(), "{reply}");

        remote.send_ipv4(&tcp_ack(hub, overlay, b"inbound")).await;
        loop {
            let length = guest.recv(&mut buffer).await.unwrap();
            if let Ok(packet) = SlicedPacket::from_ethernet(&buffer[..length])
                && let Some(TransportSlice::Tcp(tcp)) = packet.transport
                && tcp.destination_port() == local.1
            {
                let expected = tcp_ack(hub, local, b"inbound");
                assert_eq!(
                    &buffer[..length],
                    ethernet_frame(DHCP_SERVER_MAC.0, mac, &expected)
                );
                break;
            }
        }

        // Clear releases the port before replying, and the next set creates a new key
        let reply = rpc(&mut peer, "softnet.wireguard.clear", json!({"vmId": vm_id})).await;
        assert_eq!(reply["result"], json!({}));
        let _old_port = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listen_port)).unwrap();
        let reply = rpc(&mut peer, "softnet.wireguard.set", config).await;
        assert_ne!(reply["result"]["publicKey"].as_str().unwrap(), public_key);
    };

    timeout(TIMEOUT, async {
        tokio::select! {
            result = manager.run() => panic!("manager stopped with connected VM: {result:?}"),
            () = client => {}
        }
    })
    .await
    .unwrap();
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn native_shutdown_waits_for_initialization_and_cleanup() {
    let mut manager = native_manager(None);
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let vms = vec![vm_config(&socket, "02:00:00:00:00:02")];
    drop(socket);

    let (control_calls_tx, control_calls_rx) = mpsc::channel(1);
    manager.control_calls_rx = control_calls_rx;
    let (reply_tx, reply_rx) = oneshot::channel();
    control_calls_tx
        .send(Call {
            request: Request::Initialize {
                vm_net_type: NetType::Nat,
                vms,
            },
            reply: reply_tx,
        })
        .await
        .unwrap();

    // The signal task runs when initialization yields to its blocking worker
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let signal = tokio::spawn(async move {
        shutdown_tx.send(()).unwrap();
    });
    timeout(TIMEOUT, async {
        tokio::select! {
            biased;
            result = manager.run() => panic!("manager stopped before cancellation: {result:?}"),
            result = shutdown_rx => result.unwrap(),
        }
    })
    .await
    .unwrap();
    signal.await.unwrap();
    drop(reply_rx);

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    assert!(manager.proxy_tasks.is_empty());
    assert!(peer.send(&[0]).is_err());
}

#[tokio::test]
#[serial_test::serial]
async fn native_privilege_failure_cleans_up_the_entire_batch() {
    let group = uzers::get_group_by_gid(uzers::get_current_gid()).unwrap();
    let mut manager = Manager::new(
        "softnet-test-nonexistent-user".into(),
        group.name().to_string_lossy().into_owned(),
        None,
    );
    let mut peers = Vec::new();
    let mut vms = Vec::new();

    for mac in ["02:00:00:00:00:02", "02:00:00:00:00:03"] {
        let (socket, peer) = UnixDatagram::pair().unwrap();
        vms.push(vm_config(&socket, mac));
        peers.push(peer);
    }

    let error = timeout(TIMEOUT, manager.initialize(NetType::Nat, vms))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(&error, InitializationError::ActivationFailed(_)));
    assert!(format!("{error:#}").contains("failed to drop privileges"));
    assert!(!manager.initialized);
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    assert!(manager.proxy_tasks.is_empty());

    for peer in peers {
        assert!(peer.send(&[0]).is_err());
    }
}

#[tokio::test]
#[serial_test::serial]
async fn native_initialization_failure_flushes_its_rpc_reply() {
    let group = uzers::get_group_by_gid(uzers::get_current_gid()).unwrap();
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        "softnet-test-nonexistent-user".into(),
        group.name().to_string_lossy().into_owned(),
        Some(Control::new(control_socket.into()).unwrap()),
    );
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let request = json!({
        "jsonrpc": "2.0",
        "id": "test",
        "method": "softnet.initialize",
        "params": {"vms": [{"vmMacAddress": "02:00:00:00:00:02"}]},
    });
    control_peer
        .send_fds_all(format!("{request}\n").as_bytes(), &[&socket])
        .unwrap();
    control_peer.set_nonblocking(true).unwrap();
    let mut control_peer = BufReader::new(tokio::net::UnixStream::from_std(control_peer).unwrap());

    let client = async {
        let reply = read_reply(&mut control_peer).await;
        drop(socket);
        assert_eq!(reply["error"]["code"], CALL_EXECUTION_FAILED_CODE);
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("failed to drop privileges")
        );
        assert_eq!(control_peer.read(&mut [0]).await.unwrap(), 0);
    };
    timeout(TIMEOUT, async {
        let (result, ()) = tokio::join!(manager.run(), client);
        assert!(result.is_err());
    })
    .await
    .unwrap();

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    assert!(peer.send(&[0]).is_err());
}

#[tokio::test]
#[serial_test::serial]
async fn native_initialize_drops_credentials_and_rejects_reinitialization() {
    // Isolate the real credential transition so other tests retain their privileges
    if std::env::var_os("SOFTNET_TEST_PRIVILEGE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "manager::tests::native_initialize_drops_credentials_and_rejects_reinitialization",
                "--nocapture",
            ])
            .env("SOFTNET_TEST_PRIVILEGE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        return;
    }

    let user = uzers::get_user_by_name("nobody").unwrap();
    let group = uzers::get_group_by_gid(user.primary_group_id()).unwrap();
    let (control_socket, control_peer) = UnixStream::pair().unwrap();
    let mut manager = Manager::new(
        user.name().to_str().unwrap().into(),
        group.name().to_str().unwrap().into(),
        Some(Control::new(control_socket.into()).unwrap()),
    );
    let (socket, vm_peer) = UnixDatagram::pair().unwrap();
    let request = json!({
        "jsonrpc": "2.0",
        "id": "test",
        "method": "softnet.initialize",
        "params": {"vms": [{"vmMacAddress": "02:00:00:00:00:02", "allow": ["@host"]}]},
    });
    control_peer
        .send_fds_all(format!("{request}\n").as_bytes(), &[&socket])
        .unwrap();
    control_peer.set_nonblocking(true).unwrap();
    let mut control_peer = BufReader::new(tokio::net::UnixStream::from_std(control_peer).unwrap());

    // A successful initialization reply arrives before the final VM disconnects
    let client = async move {
        let reply = read_reply(&mut control_peer).await;
        drop(socket);
        assert_eq!(reply["result"]["vms"].as_array().unwrap().len(), 1);
        assert_eq!(uzers::get_current_uid(), user.uid());
        assert_eq!(uzers::get_current_gid(), group.gid());

        // An omitted vmId selects the only VM in the batch
        let reply = rpc(&mut control_peer, "softnet.policy.get", json!({})).await;
        assert_eq!(
            reply["result"],
            json!({"allow": ["@host"], "block": [], "ruleCount": 1})
        );
        let reply = rpc(&mut control_peer, "softnet.wireguard.clear", json!({})).await;
        assert_eq!(reply["result"], json!({}));

        drop(vm_peer);
        assert_eq!(control_peer.read(&mut [0]).await.unwrap(), 0);
    };
    timeout(TIMEOUT, async {
        let (result, ()) = tokio::join!(manager.run(), client);
        result.unwrap();
    })
    .await
    .unwrap();
    assert!(manager.initialized);

    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let error = manager
        .initialize(NetType::Nat, vec![vm_config(&socket, "02:00:00:00:00:03")])
        .await
        .unwrap_err();
    assert!(matches!(error, InitializationError::Rejected(_)));
    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
}
