use super::{Action, Target};
use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use prefix_trie::{Prefix, PrefixMap};
use serde::Deserialize;
use serde_json::{Value, json};
use smoltcp::wire::Ipv4Address;
use std::io::{self, ErrorKind, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PENDING_RESPONSE_BYTES: usize = 4 * MAX_REQUEST_BYTES;
const MAX_TARGETS: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_SERVICE_BYTES: usize = MAX_REQUEST_BYTES;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const REVISION_CONFLICT: i64 = -32001;
const BRIDGE_ISOLATION_CONFLICT: i64 = -32002;

pub(super) struct Policy {
    pub(super) rules: PrefixMap<Ipv4Net, Action>,
    allow: Vec<Target>,
    block: Vec<Target>,
    desired_revision: Option<String>,
    bridge_isolation: bool,
    gateway_ip: Ipv4Address,
}

impl Policy {
    pub(super) fn new(gateway_ip: Ipv4Address, allow: Vec<Target>, block: Vec<Target>) -> Self {
        let bridge_isolation = !allow.contains(&Target::Prefix(Ipv4Net::zero()));
        let allow = normalize_targets(allow);
        let block = normalize_targets(block);
        let rules = build_rules(gateway_ip, &allow, &block);

        Policy {
            rules,
            allow,
            block,
            desired_revision: None,
            bridge_isolation,
            gateway_ip,
        }
    }

    fn set(
        &mut self,
        allow: Vec<String>,
        block: Vec<String>,
        desired_revision: String,
    ) -> std::result::Result<(), RpcError> {
        if desired_revision.is_empty() || desired_revision.len() > MAX_IDENTIFIER_BYTES {
            return Err(RpcError::new(
                INVALID_PARAMS,
                format!("desiredRevision must be between 1 and {MAX_IDENTIFIER_BYTES} bytes"),
            ));
        }

        if allow.len() + block.len() > MAX_TARGETS {
            return Err(RpcError::new(
                INVALID_PARAMS,
                format!("allow and block may contain at most {MAX_TARGETS} targets combined"),
            ));
        }

        let allow = parse_targets(allow)?;
        let block = parse_targets(block)?;
        let bridge_isolation = !allow.contains(&Target::Prefix(Ipv4Net::zero()));
        let rules = build_rules(self.gateway_ip, &allow, &block);

        if self.desired_revision.as_deref() == Some(desired_revision.as_str()) {
            if self.allow == allow && self.block == block {
                return Ok(());
            }

            return Err(RpcError::new(
                REVISION_CONFLICT,
                "desiredRevision was already applied with a different policy",
            ));
        }

        if bridge_isolation != self.bridge_isolation {
            return Err(RpcError::new(
                BRIDGE_ISOLATION_CONFLICT,
                "bridge isolation cannot be changed while Softnet is running",
            ));
        }

        // Build and validate everything above before updating any active state. The packet
        // filter observes either the old PrefixMap or the complete new one.
        self.rules = rules;
        self.allow = allow;
        self.block = block;
        self.desired_revision = Some(desired_revision);

        Ok(())
    }

    fn result(&self) -> Value {
        json!({
            "allow": self.allow.iter().map(target_string).collect::<Vec<_>>(),
            "block": self.block.iter().map(target_string).collect::<Vec<_>>(),
            "desiredRevision": self.desired_revision,
            "ruleCount": self.rules.len(),
            "bridgeIsolation": self.bridge_isolation,
        })
    }
}

fn parse_targets(targets: Vec<String>) -> std::result::Result<Vec<Target>, RpcError> {
    let mut parsed = Vec::with_capacity(targets.len());

    for target in targets {
        let parsed_target = target.parse().map_err(|_| {
            RpcError::new(
                INVALID_PARAMS,
                format!("invalid target {target:?}: expected an IPv4 CIDR or @host"),
            )
        })?;
        parsed.push(parsed_target);
    }

    Ok(normalize_targets(parsed))
}

fn normalize_targets(targets: Vec<Target>) -> Vec<Target> {
    let mut targets = targets
        .into_iter()
        .map(|target| match target {
            Target::Prefix(prefix) => Target::Prefix(prefix.trunc()),
            Target::Host => Target::Host,
        })
        .collect::<Vec<_>>();

    targets.sort_by_key(target_string);
    targets.dedup();
    targets
}

fn target_string(target: &Target) -> String {
    match target {
        Target::Prefix(prefix) => prefix.to_string(),
        Target::Host => "@host".to_string(),
    }
}

fn build_rules(
    gateway_ip: Ipv4Address,
    allow: &[Target],
    block: &[Target],
) -> PrefixMap<Ipv4Net, Action> {
    let mut rules = PrefixMap::new();

    for target in allow {
        let prefix = match target {
            Target::Prefix(prefix) => *prefix,
            Target::Host => gateway_ip.into(),
        };

        rules.insert(prefix, Action::Allow);
    }

    // SECURITY: blocking rules must always take precedence over allowing rules when prefixes
    // are identical, including @host and an explicit prefix for the gateway address.
    for target in block {
        let prefix = match target {
            Target::Prefix(prefix) => *prefix,
            Target::Host => gateway_ip.into(),
        };

        rules.insert(prefix, Action::Block);
    }

    rules
}

pub(super) struct Control {
    stream: UnixStream,
    input: Vec<u8>,
    output: Vec<u8>,
    output_offset: usize,
    discarding_input: bool,
}

impl Control {
    pub(super) fn new(control_fd: RawFd) -> Result<Self> {
        let control_fd = duplicate_control_fd(control_fd)?;

        // SAFETY: duplicate_control_fd returns an open Unix stream descriptor that it owns.
        let stream = unsafe { UnixStream::from_raw_fd(control_fd) };
        stream.set_nonblocking(true)?;

        Ok(Control {
            stream,
            input: Vec::new(),
            output: Vec::new(),
            output_offset: 0,
            discarding_input: false,
        })
    }

    pub(super) fn service(&mut self, policy: &mut Policy) -> Result<bool> {
        if !self.flush()? {
            return Ok(false);
        }

        let mut buf = [0; 8192];
        let mut bytes_read = 0;

        while bytes_read < MAX_SERVICE_BYTES {
            match self.stream.read(&mut buf) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    bytes_read += n;
                    self.input.extend_from_slice(&buf[..n]);
                    self.process_input(policy)?;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(false);
                }
                Err(err) => return Err(err).context("failed to read the control socket"),
            }
        }

        self.flush()
    }

    fn process_input(&mut self, policy: &mut Policy) -> Result<()> {
        loop {
            if self.discarding_input {
                if let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') {
                    self.input.drain(..=newline);
                    self.discarding_input = false;
                    continue;
                }

                self.input.clear();
                return Ok(());
            }

            let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') else {
                if self.input.len() > MAX_REQUEST_BYTES {
                    self.input.clear();
                    self.discarding_input = true;
                    self.enqueue(error_response(
                        Value::Null,
                        PARSE_ERROR,
                        "request exceeds the maximum frame size",
                    ))?;
                }

                return Ok(());
            };

            let line = self.input.drain(..=newline).collect::<Vec<_>>();

            if newline > MAX_REQUEST_BYTES {
                self.enqueue(error_response(
                    Value::Null,
                    PARSE_ERROR,
                    "request exceeds the maximum frame size",
                ))?;
                continue;
            }

            self.enqueue(handle_request(policy, &line[..newline]))?;
        }
    }

    fn enqueue(&mut self, response: Value) -> Result<()> {
        if self.output_offset != 0 {
            self.output.drain(..self.output_offset);
            self.output_offset = 0;
        }

        let mut response =
            serde_json::to_vec(&response).context("failed to encode RPC response")?;
        response.push(b'\n');

        if self.output.len() + response.len() > MAX_PENDING_RESPONSE_BYTES {
            bail!("control response queue exceeded {MAX_PENDING_RESPONSE_BYTES} bytes");
        }

        self.output.extend(response);
        Ok(())
    }

    fn flush(&mut self) -> Result<bool> {
        while self.output_offset < self.output.len() {
            match self.stream.write(&self.output[self.output_offset..]) {
                Ok(0) => return Ok(false),
                Ok(n) => self.output_offset += n,
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(true),
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(false);
                }
                Err(err) => return Err(err).context("failed to write the control socket"),
            }
        }

        self.output.clear();
        self.output_offset = 0;

        Ok(true)
    }
}

impl AsRawFd for Control {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetParams {
    allow: Vec<String>,
    block: Vec<String>,
    desired_revision: String,
}

fn handle_request(policy: &mut Policy, line: &[u8]) -> Value {
    let value = match serde_json::from_slice::<Value>(line) {
        Ok(value) => value,
        Err(_) => {
            return error_response(Value::Null, PARSE_ERROR, "invalid JSON-RPC frame");
        }
    };

    let raw_id = value.get("id").cloned();
    let id_is_valid = raw_id.as_ref().is_some_and(valid_id);
    let response_id = raw_id.clone().unwrap_or(Value::Null);

    let request = match serde_json::from_value::<Request>(value) {
        Ok(request) if id_is_valid && request.jsonrpc == "2.0" => request,
        _ => {
            return error_response(
                if id_is_valid {
                    response_id
                } else {
                    Value::Null
                },
                INVALID_REQUEST,
                "invalid JSON-RPC request",
            );
        }
    };

    let id = request.id.unwrap_or(Value::Null);

    let result = match request.method.as_str() {
        "softnet.policy.get" => {
            if !empty_params(&request.params) {
                Err(RpcError::new(
                    INVALID_PARAMS,
                    "softnet.policy.get does not accept parameters",
                ))
            } else {
                Ok(policy.result())
            }
        }
        "softnet.policy.set" => {
            let params = serde_json::from_value::<SetParams>(request.params).map_err(|_| {
                RpcError::new(
                    INVALID_PARAMS,
                    "softnet.policy.set requires allow, block, and desiredRevision",
                )
            });

            params.and_then(|params| {
                policy.set(params.allow, params.block, params.desired_revision)?;
                Ok(policy.result())
            })
        }
        _ => Err(RpcError::new(METHOD_NOT_FOUND, "method not found")),
    };

    match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => error_response(id, error.code, error.message),
    }
}

fn valid_id(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(value) => value.len() <= MAX_IDENTIFIER_BYTES,
        Value::Number(value) => value.is_i64() || value.is_u64(),
        _ => false,
    }
}

fn empty_params(value: &Value) -> bool {
    value.is_null() || value.as_object().is_some_and(|object| object.is_empty())
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
        }
    }
}

fn duplicate_control_fd(control_fd: RawFd) -> Result<RawFd> {
    if control_fd < 0 {
        bail!("invalid control file descriptor {control_fd}: value must be non-negative");
    }

    // SAFETY: fcntl duplicates the descriptor without transferring ownership of control_fd.
    let duplicated_fd = unsafe { libc::fcntl(control_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated_fd == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to duplicate control file descriptor {control_fd}"));
    }

    if let Err(error) = validate_control_fd(duplicated_fd) {
        // SAFETY: duplicated_fd is an open descriptor owned by this function.
        unsafe { libc::close(duplicated_fd) };
        return Err(error);
    }

    Ok(duplicated_fd)
}

fn validate_control_fd(control_fd: RawFd) -> Result<()> {
    let mut socket_type = 0;
    let mut socket_type_len = size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: socket_type and socket_type_len are valid writable buffers of the sizes given.
    if unsafe {
        libc::getsockopt(
            control_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    } == -1
    {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("control file descriptor {control_fd} is not a socket"));
    }

    if socket_type != libc::SOCK_STREAM {
        bail!("control file descriptor {control_fd} is not a Unix stream socket");
    }

    let mut address: libc::sockaddr_storage = unsafe { zeroed() };
    let mut address_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    // SAFETY: address and address_len are valid writable buffers of the sizes given.
    if unsafe {
        libc::getsockname(
            control_fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_len,
        )
    } == -1
    {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!("failed to inspect the address family of control file descriptor {control_fd}")
        });
    }

    // macOS returns a zero-length address for unnamed UNIX-domain sockets, including socketpair
    // descriptors. Other socket families return their address family when getsockname succeeds.
    if address_len != 0 && address.ss_family as libc::c_int != libc::AF_UNIX {
        bail!("control file descriptor {control_fd} is not a Unix socket");
    }

    let mut peer_address: libc::sockaddr_storage = unsafe { zeroed() };
    let mut peer_address_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    // SAFETY: peer_address and peer_address_len are valid writable buffers of the sizes given.
    if unsafe {
        libc::getpeername(
            control_fd,
            (&mut peer_address as *mut libc::sockaddr_storage).cast(),
            &mut peer_address_len,
        )
    } == -1
    {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!("control file descriptor {control_fd} is not a connected Unix stream socket")
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BRIDGE_ISOLATION_CONFLICT, Control, INVALID_PARAMS, INVALID_REQUEST, MAX_REQUEST_BYTES,
        MAX_TARGETS, METHOD_NOT_FOUND, PARSE_ERROR, Policy, REVISION_CONFLICT, handle_request,
    };
    use crate::proxy::{Action, Target};
    use ipnet::Ipv4Net;
    use serde_json::{Value, json};
    use smoltcp::wire::Ipv4Address;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::str::FromStr;
    use std::time::Duration;

    fn policy(allow: &[&str], block: &[&str]) -> Policy {
        Policy::new(
            Ipv4Address::new(192, 168, 64, 1),
            allow.iter().map(|target| target.parse().unwrap()).collect(),
            block.iter().map(|target| target.parse().unwrap()).collect(),
        )
    }

    fn request(policy: &mut Policy, value: Value) -> Value {
        handle_request(policy, &serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn get_reports_initial_policy() {
        let mut policy = policy(&["@host"], &["0.0.0.0/0"]);

        let response = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": 1, "method": "softnet.policy.get", "params": {}}),
        );
        assert_eq!(response["result"]["allow"], json!(["@host"]));
        assert_eq!(response["result"]["block"], json!(["0.0.0.0/0"]));
        assert!(response["result"]["desiredRevision"].is_null());
        assert_eq!(response["result"]["ruleCount"], 2);
        assert_eq!(response["result"]["bridgeIsolation"], true);
    }

    #[test]
    fn set_applies_complete_policy_and_preserves_block_precedence() {
        let mut policy = policy(&[], &[]);

        let response = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": "set",
                "method": "softnet.policy.set",
                "params": {
                    "allow": ["@host", "10.0.0.0/8", "10.0.0.0/8"],
                    "block": ["192.168.64.1/32", "10.0.0.0/8"],
                    "desiredRevision": "vm-uid:42"
                }
            }),
        );

        assert_eq!(response["result"]["allow"], json!(["10.0.0.0/8", "@host"]));
        assert_eq!(
            response["result"]["block"],
            json!(["10.0.0.0/8", "192.168.64.1/32"])
        );
        assert_eq!(response["result"]["desiredRevision"], "vm-uid:42");
        assert_eq!(response["result"]["ruleCount"], 2);

        assert_eq!(
            policy.rules.get(&Ipv4Net::from_str("10.0.0.0/8").unwrap()),
            Some(&Action::Block)
        );
        assert_eq!(
            policy
                .rules
                .get(&Ipv4Net::from_str("192.168.64.1/32").unwrap()),
            Some(&Action::Block)
        );
    }

    #[test]
    fn same_revision_is_idempotent_after_normalization_and_conflicts_on_change() {
        let mut policy = policy(&[], &[]);

        let first = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "softnet.policy.set",
                "params": {"allow": ["@host", "10.1.2.3/8"], "block": [], "desiredRevision": "7"}
            }),
        );
        let retry = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "softnet.policy.set",
                "params": {"allow": ["10.0.0.0/8", "@host", "@host"], "block": [], "desiredRevision": "7"}
            }),
        );
        assert_eq!(first["result"], retry["result"]);
        assert_eq!(first["result"]["allow"], json!(["10.0.0.0/8", "@host"]));

        let before = policy.result();
        let conflict = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "softnet.policy.set",
                "params": {"allow": ["192.168.0.0/16"], "block": [], "desiredRevision": "7"}
            }),
        );
        assert_eq!(conflict["error"]["code"], REVISION_CONFLICT);
        assert_eq!(policy.result(), before);
    }

    #[test]
    fn invalid_targets_limits_and_bridge_isolation_changes_leave_policy_unchanged() {
        let mut policy = policy(&["@host"], &["0.0.0.0/0"]);
        let before = policy.result();

        let invalid = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "softnet.policy.set",
                "params": {"allow": ["2001:db8::/32"], "block": [], "desiredRevision": "8"}
            }),
        );
        assert_eq!(invalid["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);

        let targets = vec!["10.0.0.0/8"; MAX_TARGETS + 1];
        let too_many = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "softnet.policy.set",
                "params": {"allow": targets, "block": [], "desiredRevision": "9"}
            }),
        );
        assert_eq!(too_many["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);

        let isolation = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "softnet.policy.set",
                "params": {"allow": ["0.0.0.0/0"], "block": ["0.0.0.0/0"], "desiredRevision": "10"}
            }),
        );
        assert_eq!(isolation["error"]["code"], BRIDGE_ISOLATION_CONFLICT);
        assert_eq!(policy.result(), before);
    }

    #[test]
    fn validates_json_rpc_envelope_method_and_parameters() {
        let mut policy = policy(&[], &[]);

        let parse = handle_request(&mut policy, b"not-json");
        assert_eq!(parse["error"]["code"], PARSE_ERROR);
        assert!(parse["id"].is_null());

        let invalid = request(
            &mut policy,
            json!({"jsonrpc": "1.0", "id": {}, "method": "softnet.policy.get"}),
        );
        assert_eq!(invalid["error"]["code"], INVALID_REQUEST);
        assert!(invalid["id"].is_null());

        let method = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": 1, "method": "softnet.policy.patch"}),
        );
        assert_eq!(method["error"]["code"], METHOD_NOT_FOUND);

        let params = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": 2, "method": "softnet.policy.get", "params": {"unexpected": true}}),
        );
        assert_eq!(params["error"]["code"], INVALID_PARAMS);

        let before = policy.result();
        let missing = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "softnet.policy.set",
                "params": {"allow": [], "block": []}
            }),
        );
        assert_eq!(missing["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);

        let missing_id = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "method": "softnet.policy.set",
                "params": {"allow": ["@host"], "block": [], "desiredRevision": "12"}
            }),
        );
        assert_eq!(missing_id["error"]["code"], INVALID_REQUEST);
        assert!(missing_id["id"].is_null());
        assert_eq!(policy.result(), before);

        let null_id = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": null,
                "method": "softnet.policy.set",
                "params": {"allow": ["@host"], "block": [], "desiredRevision": "13"}
            }),
        );
        assert_eq!(null_id["error"]["code"], INVALID_REQUEST);
        assert!(null_id["id"].is_null());
        assert_eq!(policy.result(), before);
    }

    #[test]
    fn newline_delimited_control_socket_handles_multiple_requests_and_eof() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut control = Control::new(server.as_raw_fd()).unwrap();
        let mut policy = policy(&[], &[]);

        client
            .write_all(
                concat!(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.get\"}\n",
                    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"@host\"],\"block\":[\"0.0.0.0/0\"],\"desiredRevision\":\"11\"}}\n"
                )
                .as_bytes(),
            )
            .unwrap();

        assert!(control.service(&mut policy).unwrap());
        let mut response = [0; 2048];
        let n = client.read(&mut response).unwrap();
        let lines = std::str::from_utf8(&response[..n])
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[1]["id"], 2);
        assert_eq!(lines[1]["result"]["desiredRevision"], "11");
        assert_eq!(policy.allow, vec![Target::Host]);

        let before = policy.result();
        drop(client);
        assert!(!control.service(&mut policy).unwrap());
        assert_eq!(policy.result(), before);
    }

    #[test]
    fn oversized_frame_is_discarded_and_following_frame_is_processed() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut control = Control::new(server.as_raw_fd()).unwrap();
        let mut policy = policy(&[], &[]);

        control.input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        control.process_input(&mut policy).unwrap();
        assert!(control.discarding_input);

        control.input.extend_from_slice(
            b"still-too-long\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.get\"}\n",
        );
        control.process_input(&mut policy).unwrap();
        assert!(!control.discarding_input);

        let responses = std::str::from_utf8(&control.output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[1]["id"], 2);
    }

    #[test]
    fn fragmented_frame_does_not_apply_until_the_newline_arrives() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut control = Control::new(server.as_raw_fd()).unwrap();
        let mut policy = policy(&[], &[]);
        let before = policy.result();

        client
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"@host\"],",
            )
            .unwrap();
        assert!(control.service(&mut policy).unwrap());
        assert_eq!(policy.result(), before);
        assert!(control.output.is_empty());

        client
            .write_all(b"\"block\":[],\"desiredRevision\":\"14\"}}\n")
            .unwrap();
        assert!(control.service(&mut policy).unwrap());

        let mut response = [0; 1024];
        let n = client.read(&mut response).unwrap();
        let response = serde_json::from_slice::<Value>(&response[..n - 1]).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["desiredRevision"], "14");
        assert_eq!(policy.allow, vec![Target::Host]);
    }

    #[test]
    fn response_backpressure_keeps_the_pending_queue_bounded() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut control = Control::new(server.as_raw_fd()).unwrap();
        let response = json!({"jsonrpc": "2.0", "id": 1, "result": "x".repeat(MAX_REQUEST_BYTES)});
        let mut bounded = false;

        for _ in 0..8 {
            match control.enqueue(response.clone()) {
                Ok(()) => assert!(control.flush().unwrap()),
                Err(error) => {
                    assert!(
                        error
                            .to_string()
                            .contains("control response queue exceeded")
                    );
                    bounded = true;
                    break;
                }
            }
        }

        assert!(bounded);
        assert!(control.output.len() - control.output_offset <= 4 * MAX_REQUEST_BYTES);
    }

    #[test]
    fn validates_control_descriptor_without_taking_ownership() {
        let file = File::open("/dev/null").unwrap();
        let error = Control::new(file.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("is not a socket"));
        assert!(file.metadata().is_ok());

        let (datagram, _) = UnixDatagram::pair().unwrap();
        let error = Control::new(datagram.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("not a Unix stream socket"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let error = Control::new(listener.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("not a Unix socket"));

        let (stream, _peer) = UnixStream::pair().unwrap();
        let control = Control::new(stream.as_raw_fd()).unwrap();
        drop(control);
        assert!(unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) != -1 });
    }
}
