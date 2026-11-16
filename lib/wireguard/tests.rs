use super::*;
use etherparse::PacketBuilder;
use std::{collections::BTreeSet, net::SocketAddrV4};
use tokio::time::{Duration, sleep, timeout};

const VM: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 77, 1, 2);
const UPDATED_LOCAL: Ipv4Addr = Ipv4Addr::new(10, 77, 1, 3);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 77, 2, 2);

async fn remote() -> WireGuard {
    WireGuard::new(hub_config(None)).await.unwrap()
}

fn hub_config(peer: Option<Peer>) -> Config {
    Config {
        address: PEER,
        route: "10.77.1.0/24".parse().unwrap(),
        peer,
    }
}

fn peer(status: Status) -> Peer {
    Peer {
        public_key: status.public_key,
        endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, status.listen_port),
        persistent_keepalive_seconds: 0,
    }
}

fn config(remote: &WireGuard, address: Ipv4Addr) -> Config {
    Config {
        address,
        route: "10.77.0.0/16".parse().unwrap(),
        peer: Some(peer(remote.status())),
    }
}

fn packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    PacketBuilder::ipv4(source.octets(), destination.octets(), 64)
        .udp(4040, 8080)
        .write(&mut bytes, payload)
        .unwrap();
    bytes
}

async fn send(local: &mut WireGuard, payload: &[u8]) {
    let bytes = packet(VM, PEER, payload);
    let ip = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();
    local.send_vm_ipv4(&ip, VM).await;
}

async fn receive(local: &mut WireGuard, remote: &mut WireGuard, expected: &[u8]) {
    // Drive both ends of the handshake and inspect the first decrypted packet
    timeout(Duration::from_secs(3), async {
        let mut local_buffer = [0; 1500];
        let mut remote_buffer = [0; 1500];

        tokio::select! {
            result = local.receive_ipv4(&mut local_buffer) => {
                panic!("unexpected incoming IPv4 packet at sender: {result:?}");
            }
            result = remote.receive_ipv4(&mut remote_buffer) => {
                let length = result.unwrap();
                assert_eq!(&remote_buffer[..length], expected);
            }
        }
    })
    .await
    .unwrap();
}

async fn assert_vm_receive(local: &mut WireGuard, expected: Option<&[u8]>) {
    let mut output = [0; 1500];
    let length = timeout(
        Duration::from_secs(3),
        local.receive_vm_ipv4(&mut output, VM),
    )
    .await
    .expect("timed out receiving a WireGuard packet")
    .unwrap();
    assert_eq!(length.map(|length| &output[..length]), expected);
}

#[tokio::test]
async fn hub_prefix_routes_both_directions_and_excludes_the_local_address() {
    let mut hub = remote().await;
    let desired = config(&hub, LOCAL);
    desired
        .validate("192.168.64.0/24".parse().unwrap())
        .unwrap();
    let mut spoke = WireGuard::new(desired).await.unwrap();
    hub.apply(hub_config(Some(peer(spoke.status())))).unwrap();

    // A broad prefix must not forward the VM's own address to the hub
    let to_self = packet(VM, LOCAL, b"local destination");
    let ip = Ipv4Packet::new_checked(to_self.as_slice()).unwrap();
    assert!(spoke.reserves(LOCAL));
    spoke.send_vm_ipv4(&ip, VM).await;
    send(&mut spoke, b"outbound").await;
    receive(&mut spoke, &mut hub, &packet(LOCAL, PEER, b"outbound")).await;

    // Drop authenticated sources outside the prefix and the local address inside it
    hub.send_ipv4(&packet(VM, LOCAL, b"outside prefix")).await;
    hub.send_ipv4(&packet(LOCAL, LOCAL, b"spoofed local address"))
        .await;

    // A packet for another tunnel address ends this receive without a deliverable packet
    hub.send_ipv4(&packet(PEER, UPDATED_LOCAL, b"wrong destination"))
        .await;
    assert_vm_receive(&mut spoke, None).await;

    hub.send_ipv4(&packet(PEER, LOCAL, b"inbound")).await;
    assert_vm_receive(&mut spoke, Some(&packet(PEER, VM, b"inbound"))).await;
}

#[tokio::test]
async fn receive_services_keepalive_timers_without_incoming_packets() {
    let remote = remote().await;
    let mut desired = config(&remote, LOCAL);
    desired.peer.as_mut().unwrap().persistent_keepalive_seconds = 1;
    let mut local = WireGuard::new(desired).await.unwrap();
    let mut output = [0; 1500];
    let mut datagram = [0; 1500];

    // An idle peer needs a timer-driven handshake even when no IPv4 packet is queued
    let (length, source) = timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = local.receive_ipv4(&mut output) => {
                panic!("timer service must not return an IPv4 packet: {result:?}");
            }
            result = remote.socket.recv_from(&mut datagram) => result.unwrap(),
        }
    })
    .await
    .unwrap();

    assert_eq!(source.port(), local.status().listen_port);
    assert_eq!(length, 148);
    assert_eq!(&datagram[..4], &1u32.to_le_bytes());
}

#[tokio::test]
async fn receive_cancellation_does_not_starve_keepalive_timers() {
    let remote = remote().await;
    let mut desired = config(&remote, LOCAL);
    desired.peer.as_mut().unwrap().persistent_keepalive_seconds = 1;
    let mut local = WireGuard::new(desired).await.unwrap();
    let mut output = [0; 1500];
    let mut datagram = [0; 1500];
    let mut cancellations = 0;

    // Simulate the proxy repeatedly selecting another ready branch before a timer interval elapses
    let length = timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                result = local.receive_ipv4(&mut output) => {
                    panic!("timer service must not return an IPv4 packet: {result:?}");
                }
                result = remote.socket.recv_from(&mut datagram) => {
                    return result.unwrap().0;
                }
                _ = sleep(Duration::from_millis(20)) => cancellations += 1,
            }
        }
    })
    .await
    .unwrap();

    assert!(cancellations > 0);
    assert_eq!(length, 148);
    assert_eq!(&datagram[..4], &1u32.to_le_bytes());
}

#[tokio::test]
async fn queued_packets_survive_receive_cancellation() {
    let mut remote = remote().await;
    let mut local = WireGuard::new(config(&remote, LOCAL)).await.unwrap();
    remote
        .apply(hub_config(Some(peer(local.status()))))
        .unwrap();
    let mut pending = BTreeSet::new();

    // Queue more packets than Tokio can send in one cooperative scheduling budget
    for index in 0..256u16 {
        let payload = index.to_be_bytes();
        send(&mut local, &payload).await;
        pending.insert(packet(LOCAL, PEER, &payload));
    }

    let mut local_buffer = [0; 1500];
    let mut remote_buffer = [0; 1500];

    // Wait for the handshake response before cancelling the local receive operation
    timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = remote.receive_ipv4(&mut remote_buffer) => {
                panic!("unexpected remote packet before handshake response: {result:?}");
            }
            result = local.socket.readable() => result.unwrap(),
        }
    })
    .await
    .unwrap();

    tokio::select! {
        biased;
        result = local.receive_ipv4(&mut local_buffer) => {
            panic!("unexpected local packet: {result:?}");
        }
        _ = std::future::ready(()) => {}
    }

    // Resuming reception must deliver every queued payload without another handshake
    let result = timeout(Duration::from_secs(3), async {
        while !pending.is_empty() {
            tokio::select! {
                result = local.receive_ipv4(&mut local_buffer) => {
                    panic!("unexpected local packet: {result:?}");
                }
                result = remote.receive_ipv4(&mut remote_buffer) => {
                    let length = result.unwrap();
                    assert!(pending.remove(&remote_buffer[..length]));
                }
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "{} queued packets were not delivered",
        pending.len()
    );
}

#[tokio::test]
async fn receive_skips_oversized_packets_before_delivering_a_fitting_packet() {
    let mut remote = remote().await;
    let mut local = WireGuard::new(config(&remote, LOCAL)).await.unwrap();
    remote
        .apply(hub_config(Some(peer(local.status()))))
        .unwrap();
    send(&mut local, b"establish session").await;
    receive(
        &mut local,
        &mut remote,
        &packet(LOCAL, PEER, b"establish session"),
    )
    .await;

    // Oversized authenticated traffic is consumed internally without ending the receive operation
    send(&mut local, &[7; 128]).await;
    send(&mut local, b"fits").await;
    let mut output = [0; 64];
    let length = timeout(Duration::from_secs(3), remote.receive_ipv4(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&output[..length], packet(LOCAL, PEER, b"fits"));
}

#[tokio::test]
async fn rejected_transport_updates_preserve_routes_translation_and_pending_packets() {
    let mut remote = remote().await;
    let mut local = WireGuard::new(config(&remote, LOCAL)).await.unwrap();
    let status = local.status();
    remote
        .apply(hub_config(Some(peer(status.clone()))))
        .unwrap();

    for invalid_key in ["invalid".to_owned(), STANDARD.encode([0; 32])] {
        let mut invalid = config(&remote, UPDATED_LOCAL);
        invalid.route = "10.77.2.0/24".parse().unwrap();
        invalid.peer.as_mut().unwrap().public_key = invalid_key;

        // Exercise transport rejection after the outer configuration checks have succeeded
        invalid
            .validate("192.168.64.0/24".parse().unwrap())
            .unwrap();
        send(&mut local, b"before rejected update").await;
        assert!(local.apply(invalid).is_err());
        assert_eq!(local.status(), status);
        assert!(local.reserves(Ipv4Addr::new(10, 77, 99, 1)));
        assert!(!local.reserves(Ipv4Addr::new(10, 78, 1, 1)));
        receive(
            &mut local,
            &mut remote,
            &packet(LOCAL, PEER, b"before rejected update"),
        )
        .await;

        // Both translation directions must retain the accepted local address
        send(&mut local, b"after rejected update").await;
        receive(
            &mut local,
            &mut remote,
            &packet(LOCAL, PEER, b"after rejected update"),
        )
        .await;
        remote.send_ipv4(&packet(PEER, LOCAL, b"reply")).await;
        assert_vm_receive(&mut local, Some(&packet(PEER, VM, b"reply"))).await;

        remote
            .send_ipv4(&packet(PEER, UPDATED_LOCAL, b"reply"))
            .await;
        assert_vm_receive(&mut local, None).await;
    }
}

#[tokio::test]
async fn withdrawn_peers_keep_destinations_reserved_without_queuing_packets() {
    let mut remote = remote().await;
    let mut local = WireGuard::new(config(&remote, LOCAL)).await.unwrap();
    remote
        .apply(hub_config(Some(peer(local.status()))))
        .unwrap();
    let mut withdrawn = config(&remote, LOCAL);
    withdrawn.peer = None;
    local.apply(withdrawn).unwrap();

    // The route remains reserved even when no peer can deliver traffic
    assert!(local.reserves(PEER));
    assert!(local.reserves(Ipv4Addr::new(10, 77, 99, 1)));
    assert!(!local.reserves(Ipv4Addr::new(10, 78, 1, 1)));
    send(&mut local, b"while withdrawn").await;

    // Re-admitting a peer must release only traffic sent after the update
    local.apply(config(&remote, LOCAL)).unwrap();
    send(&mut local, b"after admission").await;
    receive(
        &mut local,
        &mut remote,
        &packet(LOCAL, PEER, b"after admission"),
    )
    .await;
}

#[tokio::test]
async fn replacing_a_peer_revokes_its_established_session() {
    let mut old = remote().await;
    let mut new = remote().await;
    let mut local = WireGuard::new(config(&old, LOCAL)).await.unwrap();
    let status = local.status();
    for hub in [&mut old, &mut new] {
        hub.apply(hub_config(Some(peer(status.clone())))).unwrap();
    }

    let original = packet(PEER, LOCAL, b"original peer");
    old.send_ipv4(&original).await;
    receive(&mut old, &mut local, &original).await;
    local.apply(config(&new, LOCAL)).unwrap();
    assert_eq!(local.status(), status);

    // The first plaintext delivered after reassignment must come from the new peer
    old.send_ipv4(&packet(PEER, LOCAL, b"revoked peer")).await;
    let replacement = packet(PEER, LOCAL, b"replacement peer");
    new.send_ipv4(&replacement).await;
    receive(&mut new, &mut local, &replacement).await;
}

#[tokio::test]
async fn local_address_updates_discard_pending_plaintext() {
    let mut remote = remote().await;
    let mut local = WireGuard::new(config(&remote, LOCAL)).await.unwrap();
    let status = local.status();

    // Admit both sources so the remote cannot hide stale plaintext by rejecting its old source
    remote
        .apply(hub_config(Some(peer(status.clone()))))
        .unwrap();
    send(&mut local, b"old address").await;
    local.apply(config(&remote, UPDATED_LOCAL)).unwrap();
    assert_eq!(local.status(), status);
    send(&mut local, b"new address").await;
    receive(
        &mut local,
        &mut remote,
        &packet(UPDATED_LOCAL, PEER, b"new address"),
    )
    .await;

    // Replies must use the newly installed address before translation to the guest
    remote.send_ipv4(&packet(PEER, LOCAL, b"reply")).await;
    assert_vm_receive(&mut local, None).await;

    remote
        .send_ipv4(&packet(PEER, UPDATED_LOCAL, b"reply"))
        .await;
    assert_vm_receive(&mut local, Some(&packet(PEER, VM, b"reply"))).await;
}

#[tokio::test]
async fn identical_update_preserves_pending_handshake_and_local_socket() {
    let mut remote = remote().await;
    let mut local = WireGuard::new(config(&remote, LOCAL)).await.unwrap();
    let status = local.status();
    remote
        .apply(hub_config(Some(peer(status.clone()))))
        .unwrap();
    send(&mut local, b"queued before retry").await;
    local.apply(config(&remote, LOCAL)).unwrap();
    assert_eq!(local.status(), status);
    receive(
        &mut local,
        &mut remote,
        &packet(LOCAL, PEER, b"queued before retry"),
    )
    .await;
}
