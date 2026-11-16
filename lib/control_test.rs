use super::Control;
use crate::control_transport::Frame;
use crate::manager::{Call, InitializedVm, Reply, Request};
use crate::network::{MAX_VMS, NetType};
use crate::proxy::Policy;
use crate::wireguard::Peer;
use jsonrpsee_types::error::{
    INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, METHOD_NOT_FOUND_CODE, PARSE_ERROR_CODE,
};
use serde_json::{Value, json};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixDatagram, UnixStream as StdUnixStream};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use unix_ancillary::AsyncUnixStreamExt;
use uuid::Uuid;

fn start_control(socket: UnixStream) -> (JoinHandle<()>, mpsc::Receiver<Call>) {
    let control = Control::new(socket.into_std().unwrap().into()).unwrap();
    let (control_calls_tx, control_calls_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        timeout(Duration::from_secs(5), control.run(control_calls_tx))
            .await
            .unwrap()
            .unwrap();
    });

    (task, control_calls_rx)
}

fn request(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

async fn read_reply(peer: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    assert_ne!(peer.read_line(&mut line).await.unwrap(), 0);

    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn serves_calls_in_order_and_flushes_the_final_reply() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (control, mut control_calls_rx) = start_control(socket);
    let mut peer = BufReader::new(peer);
    let mut first = request("softnet.policy.get", Value::Null);
    first["id"] = json!("x".repeat(257));
    let second = request(
        "softnet.policy.set",
        json!({"allow": ["@host"], "block": []}),
    );

    // Pipeline two requests, but dispatch the second only after acknowledging the first
    peer.get_mut()
        .write_all(format!("{first}\n{second}\n").as_bytes())
        .await
        .unwrap();
    let call = control_calls_rx.recv().await.unwrap();
    assert!(matches!(call.request, Request::GetPolicy { vm_id: None }));
    assert!(control_calls_rx.is_empty() && !control_calls_rx.is_closed());
    call.reply
        .send(Ok(Reply::Policy(Policy::default())))
        .unwrap();

    let call = control_calls_rx.recv().await.unwrap();
    assert!(
        matches!(call.request, Request::SetPolicy { vm_id: None, allow, block }
        if allow == vec!["@host".parse().unwrap()] && block.is_empty())
    );
    call.reply
        .send(Ok(Reply::Policy(Policy::default())))
        .unwrap();
    control_calls_rx.close();

    // Closing the backend still flushes both replies with their original IDs
    for frame in [first, second] {
        assert_eq!(
            read_reply(&mut peer).await,
            json!({
                "jsonrpc": "2.0",
                "id": frame["id"],
                "result": {"allow": [], "block": [], "ruleCount": 0},
            })
        );
    }
    control.await.unwrap();
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn rejects_invalid_requests_without_dispatching_them() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (control, control_calls_rx) = start_control(socket);
    let mut peer = BufReader::new(peer);
    let mut extra = request("softnet.policy.get", Value::Null);
    extra["id"] = json!("x".repeat(257));
    extra["extra"] = json!(true);

    // Malformed JSON is answered without dispatching a call
    peer.get_mut().write_all(b"{\n").await.unwrap();
    let reply = read_reply(&mut peer).await;
    assert_eq!(reply["id"], Value::Null);
    assert_eq!(reply["error"]["code"], PARSE_ERROR_CODE);

    // Each rejected request leaves the connection usable and preserves its ID
    for (frame, code) in [
        (
            json!({"jsonrpc": "2.0", "method": "x"}),
            INVALID_REQUEST_CODE,
        ),
        (extra, INVALID_REQUEST_CODE),
        (request("unknown", Value::Null), METHOD_NOT_FOUND_CODE),
        (
            request("softnet.wireguard.set", json!({})),
            INVALID_PARAMS_CODE,
        ),
        (
            request(
                "softnet.wireguard.set",
                json!([null, "10.77.0.2", ["10.77.0.0/24"], []]),
            ),
            INVALID_PARAMS_CODE,
        ),
        (
            request(
                "softnet.wireguard.set",
                json!({
                    "address": "10.77.0.2", "routes": ["10.77.0.0/24"],
                    "peers": [], "unrecognized": true,
                }),
            ),
            INVALID_PARAMS_CODE,
        ),
        (
            request(
                "softnet.wireguard.set",
                json!({
                    "vmId": 5, "address": "10.77.0.2",
                    "routes": ["10.77.0.0/24"], "peers": [],
                }),
            ),
            INVALID_PARAMS_CODE,
        ),
        (
            request(
                "softnet.initialize",
                json!({"vms": [{"vmMacAddress": "02:00:00:00:00:02"}]}),
            ),
            INVALID_PARAMS_CODE,
        ),
        (
            request("softnet.policy.get", json!({"vmId": "invalid"})),
            INVALID_PARAMS_CODE,
        ),
        (
            request(
                "softnet.policy.set",
                json!({"allow": vec!["@host"; 4097], "block": []}),
            ),
            INVALID_PARAMS_CODE,
        ),
    ] {
        peer.get_mut()
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let reply = read_reply(&mut peer).await;
        assert_eq!(reply["id"], frame["id"]);
        assert_eq!(reply["error"]["code"], code);
        assert!(control_calls_rx.is_empty() && !control_calls_rx.is_closed());
    }
    drop(control_calls_rx);
    control.await.unwrap();
}

#[test]
fn parses_flat_wireguard_params_with_optional_vm_id() {
    let vm_id = Uuid::from_u128(1);
    for (selector, expected) in [
        (None, None),
        (Some(Value::Null), None),
        (Some(json!(vm_id)), Some(vm_id)),
    ] {
        let mut params = json!({"address": "10.77.0.2", "routes": ["10.77.0.0/24"], "peers": []});
        if let Some(selector) = selector {
            params["vmId"] = selector;
        }

        let frame = Frame {
            line: Ok(request("softnet.wireguard.set", params).to_string()),
            fds: vec![],
        };
        let (_, request) = Control::parse(frame).unwrap();
        let Request::SetWireGuard { vm_id, params } = request else {
            panic!("expected a WireGuard set request");
        };
        assert_eq!(vm_id, expected);
        assert_eq!(params.route, "10.77.0.0/24".parse().unwrap());
        assert!(params.peer.is_none());
    }
}

#[test]
fn validates_wireguard_set_params() {
    let public_key = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
    let endpoint = "192.0.2.1:30000";
    let desired = json!({
        "address": "10.77.1.2",
        "peers": [{
            "publicKey": public_key,
            "endpoint": endpoint,
            "allowedIPs": ["10.77.0.0/16"],
            "persistentKeepaliveSeconds": 15
        }],
        "routes": ["10.77.0.0/16"]
    });
    let parse_config = |params| {
        let frame = Frame {
            line: Ok(request("softnet.wireguard.set", params).to_string()),
            fds: vec![],
        };
        let (_, request) = Control::parse(frame)?;
        let Request::SetWireGuard { params, .. } = request else {
            panic!("expected a WireGuard set request");
        };

        Ok::<_, Value>(params)
    };
    let config = parse_config(desired.clone()).unwrap();
    config.validate("192.168.64.0/24".parse().unwrap()).unwrap();
    assert_eq!(
        config.peer,
        Some(Peer::new(public_key.to_owned(), endpoint.parse().unwrap(), 15).unwrap())
    );

    for (case, field, value) in [
        ("null address", "address", json!(null)),
        ("loopback address", "address", json!("127.0.0.1")),
        ("empty routes", "routes", json!([])),
        (
            "multiple routes",
            "routes",
            json!(["10.77.0.0/16", "10.78.0.0/16"]),
        ),
        ("route to local address", "routes", json!(["10.77.1.2/32"])),
        ("leading-zero prefix", "routes", json!(["10.77.0.0/016"])),
        ("route with host bits", "routes", json!(["10.77.1.0/16"])),
        ("allowedIPs mismatch", "routes", json!(["10.77.2.0/24"])),
        (
            "multiple peers",
            "peers",
            json!([desired["peers"][0], desired["peers"][0]]),
        ),
    ] {
        let mut invalid = desired.clone();
        invalid[field] = value;
        assert!(parse_config(invalid).is_err(), "{case}");
    }

    let mut missing_routes = desired;
    missing_routes.as_object_mut().unwrap().remove("routes");
    assert!(parse_config(missing_routes).is_err(), "missing routes");
}

#[tokio::test]
async fn initializes_ordered_vms_and_closes_unused_descriptors() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (control, mut control_calls_rx) = start_control(socket);
    let mut peer = BufReader::new(peer);
    let (first, first_peer) = UnixDatagram::pair().unwrap();
    let (second, second_peer) = UnixDatagram::pair().unwrap();
    let initialize = request(
        "softnet.initialize",
        json!({"vms": [
            {"vmMacAddress": "02:00:00:00:00:02", "allow": ["@host"]},
            {"vmMacAddress": "02:00:00:00:00:03", "block": ["@host"], "expose": ["8080:80"]},
        ]}),
    );
    peer.get_ref()
        .send_fds_all(format!("{initialize}\n").as_bytes(), &[&first, &second])
        .await
        .unwrap();

    // Identify each received socket independently of the descriptor numbers
    assert_eq!(first_peer.send(b"a").unwrap(), 1);
    assert_eq!(second_peer.send(b"b").unwrap(), 1);
    let call = control_calls_rx.recv().await.unwrap();
    let Request::Initialize { vm_net_type, vms } = call.request else {
        panic!("expected initialization");
    };
    assert_eq!(vm_net_type, NetType::Nat);
    assert_eq!(vms.len(), 2);

    // Close sender copies after Darwin has installed the complete rights batch
    drop(first);
    drop(second);

    let [first, second]: [_; 2] = vms.try_into().unwrap();
    assert_eq!(first.vm_mac_address.to_string(), "02:00:00:00:00:02");
    assert_eq!(second.vm_mac_address.to_string(), "02:00:00:00:00:03");
    assert_eq!(first.allow, vec!["@host".parse().unwrap()]);
    assert!(first.block.is_empty());
    assert_eq!(second.block, vec!["@host".parse().unwrap()]);
    assert_eq!(second.exposed_ports.len(), 1);

    let first_fd = UnixDatagram::from(first.vm_fd);
    let second_fd = UnixDatagram::from(second.vm_fd);
    let mut byte = [0];
    assert_eq!(first_fd.recv(&mut byte).unwrap(), 1);
    assert_eq!(byte, *b"a");
    assert_eq!(second_fd.recv(&mut byte).unwrap(), 1);
    assert_eq!(byte, *b"b");

    // The response keeps VM order
    let vm_ids = [Uuid::from_u128(2), Uuid::from_u128(1)];
    call.reply
        .send(Ok(Reply::Initialized(vec![
            InitializedVm {
                vm_id: vm_ids[0],
                vm_mac_address: "02:00:00:00:00:02".parse().unwrap(),
            },
            InitializedVm {
                vm_id: vm_ids[1],
                vm_mac_address: "02:00:00:00:00:03".parse().unwrap(),
            },
        ])))
        .unwrap();
    assert_eq!(
        read_reply(&mut peer).await["result"],
        json!({"vms": [
            {
                "vmId": vm_ids[0].to_string(),
                "vmMacAddress": "02:00:00:00:00:02",
            },
            {
                "vmId": vm_ids[1].to_string(),
                "vmMacAddress": "02:00:00:00:00:03",
            },
        ]})
    );

    // Policy methods ignore attached descriptors and close every received copy
    for (method, params) in [
        ("softnet.policy.get", Value::Null),
        (
            "softnet.policy.set",
            json!({"allow": ["@host"], "block": []}),
        ),
    ] {
        let frame = request(method, params);
        peer.get_ref()
            .send_fds_all(format!("{frame}\n").as_bytes(), &[&first_fd, &second_fd])
            .await
            .unwrap();

        let call = control_calls_rx.recv().await.unwrap();
        assert!(matches!(
            (&call.request, method),
            (Request::GetPolicy { .. }, "softnet.policy.get")
                | (Request::SetPolicy { .. }, "softnet.policy.set")
        ));
        call.reply
            .send(Ok(Reply::Policy(Policy::default())))
            .unwrap();
        assert_eq!(
            read_reply(&mut peer).await["result"],
            json!({"allow": [], "block": [], "ruleCount": 0})
        );
    }

    drop(first_fd);
    drop(second_fd);
    assert!(first_peer.send(&[0]).is_err());
    assert!(second_peer.send(&[0]).is_err());
    assert!(control_calls_rx.is_empty() && !control_calls_rx.is_closed());
    drop(control_calls_rx);
    control.await.unwrap();
}

#[test]
fn rejects_invalid_initialization_and_closes_every_descriptor() {
    let valid_vm = json!({"vmMacAddress": "02:00:00:00:00:02"});
    let valid = json!({"vms": [valid_vm.clone()]});

    // Invalid batch shapes and VM fields must fail before manager dispatch
    let cases = [
        (json!({"vms": []}), 0),
        (
            json!({"vms": vec![valid_vm.clone(); MAX_VMS + 1]}),
            MAX_VMS + 1,
        ),
        (valid.clone(), 0),
        (valid.clone(), 2),
        (
            json!({"vmNetType": "bridged", "vms": [valid_vm.clone()]}),
            1,
        ),
        (json!({"vms": [valid_vm.clone()], "extra": true}), 1),
        (json!({"vms": [{"vmMacAddress": "bad"}]}), 1),
        (
            json!({"vms": [{"vmMacAddress": "02:00:00:00:00:02", "vmNetType": "host"}]}),
            1,
        ),
        (
            json!({"vms": [{"vmMacAddress": "02:00:00:00:00:02", "extra": true}]}),
            1,
        ),
        (
            json!({"vms": [{"vmMacAddress": "02:00:00:00:00:02", "allow": ["bad rule"]}]}),
            1,
        ),
        (
            json!({"vms": [{"vmMacAddress": "02:00:00:00:00:02", "allow": vec!["@host"; 4097]}]}),
            1,
        ),
        (
            json!({"vms": [valid_vm, {"vmMacAddress": "02:00:00:00:00:03", "expose": ["bad"]}]}),
            2,
        ),
    ];

    for (params, descriptor_count) in cases {
        let (descriptor, mut descriptor_peer) = StdUnixStream::pair().unwrap();
        let fds = (0..descriptor_count)
            .map(|_| OwnedFd::from(descriptor.try_clone().unwrap()))
            .collect();
        drop(descriptor);

        let frame = Frame {
            line: Ok(request("softnet.initialize", params.clone()).to_string()),
            fds,
        };
        let error = Control::parse(frame).unwrap_err();

        assert_eq!(error["error"]["code"], INVALID_PARAMS_CODE, "{params}");
        assert_eq!(descriptor_peer.read(&mut [0]).unwrap(), 0, "{params}");
    }
}

#[test]
fn accepts_maximum_batch_with_one_shared_network_type() {
    let vms = (0..MAX_VMS)
        .map(|index| json!({"vmMacAddress": format!("02:00:00:00:00:{:02x}", index + 2)}))
        .collect::<Vec<_>>();
    let (descriptor, _descriptor_peer) = StdUnixStream::pair().unwrap();
    let fds = (0..MAX_VMS)
        .map(|_| OwnedFd::from(descriptor.try_clone().unwrap()))
        .collect();
    let frame = Frame {
        line: Ok(request(
            "softnet.initialize",
            json!({"vmNetType": "host", "vms": vms}),
        )
        .to_string()),
        fds,
    };
    let (_, request) = Control::parse(frame).unwrap();
    let Request::Initialize { vm_net_type, vms } = request else {
        panic!("expected initialization");
    };

    assert_eq!(vm_net_type, NetType::Host);
    assert_eq!(vms.len(), MAX_VMS);
}

#[tokio::test]
async fn aborting_a_blocked_reply_closes_the_connection() {
    timeout(Duration::from_secs(1), async {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::SndBuf, &1024).unwrap();
        let (control, mut control_calls_rx) = start_control(socket);
        let get = request("softnet.policy.get", Value::Null);
        peer.write_all(format!("{get}\n").as_bytes()).await.unwrap();
        let payload = "out 203.0.113.0/24";
        let copies = 64 * 1024;
        control_calls_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(Ok(Reply::Policy(Policy {
                allow: vec![payload.parse().unwrap(); copies],
                block: Vec::new(),
                rule_count: 1,
            })))
            .unwrap();

        // Abort after writing starts, while the reply is still blocked
        let mut received = vec![0; 1];
        peer.read_exact(&mut received).await.unwrap();
        control.abort();
        assert!(control.await.unwrap_err().is_cancelled());
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.len() < payload.len() * copies);
        assert!(!received.ends_with(b"\n"));
    })
    .await
    .unwrap();
}
