# Softnet

Softnet is a software networking for [Tart](https://github.com/cirruslabs/tart) which provides better network isolation and alleviates DHCP shortage on production systems.

It is essentially a userspace packet filter which restricts the VM networking and prevents a class of security issues, such as ARP spoofing. By default, the VM will only be able to:

* send traffic from its own MAC-address
* send traffic from the IP-address assigned to it by the DHCP
* send traffic to globally routable IPv4 addresses
* send traffic to gateway IP of the vmnet bridge (this would normally be \"bridge100\" interface)
* receive any incoming traffic

In addition, Softnet tunes macOS built-in DHCP server to decrease its lease time from the default 86,400 seconds (one day) to 600 seconds (10 minutes). This is especially important when you use Tart to clone and run a lot of ephemeral VMs over a period of one day.

Please check out [this blog post](https://medium.com/cirruslabs/isolating-network-between-tarts-macos-virtual-machines-9a4ae3dcf7be) for backstory.

## Working model

Softnet solves two problems:

1. VM network isolation
    * [`VZNATNetworkDeviceAttachment`](https://developer.apple.com/documentation/virtualization/vznatnetworkdeviceattachment) (the default networking in Tart) enables [vmnet's bridge isolation](https://developer.apple.com/documentation/vmnet/vmnet_enable_isolation_key) by default and prevents cross-VM traffic, however it's still possible for any VM to spoof the host's ARP-table and capture other VMs traffic by using tools that enable conducting the [ARP spoofing attacks](https://en.wikipedia.org/wiki/ARP_spoofing) (e.g. [arpspoof](https://www.monkey.org/~dugsong/dsniff/), [arpoison](http://www.arpoison.net/) and so on)
2. DHCP exhaustion
    * macOS built-in DHCP-server allocates a `/24` subnet with 86400 seconds lease time by default, which only allows for ~253 VMs a day (or 1 VM every ~6 minutes) to be spawned without causing a denial-of-service, which is pretty limiting for CI services like Cirrus CI

Up to five VMs in one Softnet process share a [`vmnet` network](https://developer.apple.com/documentation/vmnet/vmnet_network_create(_:_:)) with a private `/29` subnet selected to avoid overlap with existing host interface subnets. Softnet reserves an IP-address for each VM's MAC-address, delivers it through its own DHCP-server, and uses the reserved address for packet filtering.

### Stateful flow authorization

Stateful `in`/`out` rules use a bounded authorization cache that records the
direction and exact transport tuple of policy-approved flows, allowing matching
return traffic without treating it as a new flow and thus requiring a separate
policy entry. It is not a complete TCP connection tracker: endpoint transport
stacks remain responsible for validating sequence numbers, receive windows,
resets, and application-level traffic.

This cache deliberately favors security, bounded resource use, and a simple
implementation over availability. Only policy-authorized initiator traffic
renews an entry; return traffic does not. Softnet does not maintain fairness
quotas, eviction heuristics, or complete TCP lifecycle state.

A packet admitted by a stateful rule is denied when Softnet cannot represent its
flow, including when the cache is full. High flow churn, long idle connections,
or ambiguous retransmissions may therefore interrupt networking and require the
affected VM to reconnect.

For TCP, a bare TCP SYN on an existing tuple is deliberately returned to policy
because Softnet cannot distinguish a retransmission from tuple reuse without
tracking TCP sequence state. If authorized, it may replace the tuple's previous
cache lifetime; this can reduce availability but cannot grant traffic that
policy did not permit.

For ICMP, stateful flow authorization supports only echo requests and replies.

## Installing

Softnet requires macOS 26 or newer; building also requires the macOS 26 SDK or newer.

For proper functioning, Softnet binary requires two things:

* a [SUID-bit](https://en.wikipedia.org/wiki/Setuid#SUID) to be set on the binary or a [passwordless sudo](https://serverfault.com/questions/160581/how-to-setup-passwordless-sudo-on-linux) to be configured, which effectively gives the binary `root` privileges
  * these privileges are needed to create [`vmnet.framework`](https://developer.apple.com/documentation/vmnet) interface and perform DHCP-related system tweaks
  * the privileges will be dropped automatically to that of the calling user (or those represented by the `--user` and `--group` command-line arguments) once all of the initialization is completed
* the binary to be available in `PATH`
  * so that the Tart will be able to find it

## Running

Softnet is started and managed automatically by Tart if `--net-softnet` flag is provided when calling `tart run`.

Pass a connected Unix stream socket as `--control-fd` to enable a newline-delimited [JSON-RPC 2.0](https://www.jsonrpc.org/specification) control channel. The control socket is duplex and must be separate from the sockets carrying VM packets.

Every request must include a non-null string or non-negative integer `id`; notifications are rejected so requests always have an acknowledgment. A request frame may not exceed 1 MiB.

### VM initialization

Softnet can start with just `--control-fd` and create VMs through RPC.

`softnet.initialize` accepts `vmNetType` (`"nat"` or `"host"`, default `"nat"`) and a `vms` array containing one to five VMs. Each VM requires a distinct `vmMacAddress` and accepts optional `allow`, `block`, and `expose` arrays, which default to empty. Rules and exposed TCP ports use the same syntax as the corresponding CLI arguments.

Each VM may specify a unique single-label DNS `name`. Softnet answers queries for `<name>.internal` with that VM's reserved IPv4 address. It serves the shared authoritative `internal.` zone over UDP only, bypassing allow/block rules for these DNS queries. Other DNS queries use the system's DNS server.

Attach exactly one VM socket descriptor per entry through `SCM_RIGHTS` to the first byte of the request frame, in the same order as `vms`. Keep the sender's descriptors open until the initialization response arrives.

A successful response contains a `vms` array in request order; each entry includes a UUID string `vmId` and the corresponding `vmMacAddress`. Initialization drops privileges before responding.

With two attached VM socket descriptors, a request and response look like this (each occupies one line; VM IDs are illustrative):

```json
{"jsonrpc":"2.0","id":"42","method":"softnet.initialize","params":{"vmNetType":"nat","vms":[{"vmMacAddress":"02:00:00:00:00:02","name":"vm1","allow":["@host"]},{"vmMacAddress":"02:00:00:00:00:03","name":"vm2"}]}}
{"jsonrpc":"2.0","id":"42","result":{"vms":[{"vmId":"019a1b2c-3d4e-7000-8000-000000000001","vmMacAddress":"02:00:00:00:00:02"},{"vmId":"019a1b2c-3d4e-7000-8000-000000000002","vmMacAddress":"02:00:00:00:00:03"}]}}
```

Each Softnet process initializes once with the complete VM list; VMs cannot be added later. Initialization is all-or-nothing: no VM begins forwarding until every VM is configured and privileges have been dropped successfully. Validation errors reject the entire batch and allow retry; native setup or privilege dropping failures clean up the entire batch and terminate Softnet without returning partial success.

Softnet exits when the last VM disconnects, even if the control socket remains open.

The `--vm-fd` and `--vm-mac-address` arguments still initialize a single VM.

### Dynamic network policy

Softnet can update the running VM's IPv4 policy without restarting the VM.

The supported methods are `softnet.policy.get` and `softnet.policy.set`. Both accept an optional `vmId`, which can be omitted only when the process was initialized with exactly one VM. Multi-VM batches always require `vmId`, even after all but one VM disconnects. A complete policy update looks like this (each request and response occupies one line):

```json
{"jsonrpc":"2.0","id":"42","method":"softnet.policy.set","params":{"vmId":"019a1b2c-3d4e-7000-8000-000000000001","allow":["@host","10.0.0.0/8"],"block":["0.0.0.0/0"]}}
{"jsonrpc":"2.0","id":"42","result":{"allow":["10.0.0.0/8","@host"],"block":["0.0.0.0/0"],"ruleCount":3}}
```

Policy updates are atomic: all rules are parsed and a new prefix map is built before the active policy changes. Longest-prefix matching and block precedence for identical rules are preserved. Rules are normalized and deduplicated. A policy update may contain at most 4096 combined allow/block rules.

When the normalized allow or block policy changes, Softnet clears the flow table so the new policy applies to established flows immediately. This may interrupt active connections. Repeating the same normalized policy is a no-op and preserves the flow table.

Use `block=["0.0.0.0/0"]` with specific allow rules for a default-deny egress policy. Closing the control socket leaves the last accepted policy active.
