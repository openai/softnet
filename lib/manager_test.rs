use super::{Call, InitializationError, Manager, ProxyHandle, Reply, Request, VmConfig};
use crate::NetType;
use crate::control::Control;
use crate::proxy::{Command, Policy};
use jsonrpsee_types::error::{CALL_EXECUTION_FAILED_CODE, INVALID_PARAMS_CODE};
use serde_json::{Value, json};
use std::io::{Read, Write};
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
async fn single_vm_batch_uses_its_default_policy_target() {
    let mut manager = Manager::new("unused".into(), "unused".into(), None);
    let id = Uuid::now_v7();
    manager.initialized = true;
    manager.default_vm_id = Some(id);
    let (commands_tx, mut commands_rx) = mpsc::channel(1);
    manager.proxy_handles.insert(
        id,
        ProxyHandle {
            commands: commands_tx,
        },
    );
    manager.proxy_tasks.spawn(id, async move {
        let Some(Command::PolicyGet { reply }) = commands_rx.recv().await else {
            panic!("expected a policy request");
        };

        reply.send(Policy::default()).unwrap();
        assert!(commands_rx.recv().await.is_none());

        Ok(())
    });
    let (reply_tx, reply_rx) = oneshot::channel();

    // An omitted VM ID resolves to the single VM selected at initialization
    timeout(
        TIMEOUT,
        manager.dispatch(Call {
            request: Request::GetPolicy { vm_id: None },
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

    timeout(TIMEOUT, manager.shutdown()).await.unwrap().unwrap();
    assert!(manager.proxy_handle(None).is_err());
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
async fn native_batch_rpc_preserves_order_and_independent_policies() {
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
                {"vmMacAddress": "02:00:00:00:00:02", "allow": ["@host"]},
                {"vmMacAddress": "02:00:00:00:00:03"},
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
        "params": {"vms": [{"vmMacAddress": "02:00:00:00:00:02"}]},
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
