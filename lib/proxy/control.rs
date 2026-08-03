use super::{Rule, Rules};
use anyhow::{Context, Result, bail};
use jsonrpsee_types::{
    ErrorObjectOwned, Id, Request, Response, ResponsePayload,
    error::{
        INVALID_PARAMS_CODE as INVALID_PARAMS, INVALID_REQUEST_CODE as INVALID_REQUEST,
        METHOD_NOT_FOUND_CODE as METHOD_NOT_FOUND, PARSE_ERROR_CODE as PARSE_ERROR,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use smoltcp::wire::Ipv4Address;
use std::io::{self, ErrorKind, Read, Write};
use std::mem::{size_of, zeroed};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PENDING_RESPONSE_BYTES: usize = 4 * MAX_REQUEST_BYTES;
const MAX_RULES: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_SERVICE_BYTES: usize = MAX_REQUEST_BYTES;

pub(super) struct Policy {
    allow: Vec<Rule>,
    block: Vec<Rule>,
    gateway_ip: Ipv4Address,
}

struct PolicyUpdate {
    rules: Rules,
    allow: Vec<Rule>,
    block: Vec<Rule>,
}

impl Policy {
    pub(super) fn new(gateway_ip: Ipv4Address, allow: Vec<Rule>, block: Vec<Rule>) -> Self {
        let allow = normalize_rules(allow);
        let block = normalize_rules(block);

        Policy {
            allow,
            block,
            gateway_ip,
        }
    }

    fn set(
        &self,
        allow: Vec<String>,
        block: Vec<String>,
    ) -> std::result::Result<PolicyUpdate, ErrorObjectOwned> {
        if allow.len() + block.len() > MAX_RULES {
            return Err(rpc_error(
                INVALID_PARAMS,
                format!("allow and block may contain at most {MAX_RULES} rules combined"),
            ));
        }

        let allow = parse_rules(allow)?;
        let block = parse_rules(block)?;
        let rules = Rules::new(self.gateway_ip, &allow, &block);

        Ok(PolicyUpdate {
            rules,
            allow,
            block,
        })
    }

    fn apply(&mut self, update: PolicyUpdate) -> Option<Rules> {
        // Build and validate everything before updating any active state. The packet filter
        // observes either the old rule set or the complete new one.
        let changed = self.allow != update.allow || self.block != update.block;

        self.allow = update.allow;
        self.block = update.block;

        changed.then_some(update.rules)
    }

    fn result(&self, rule_count: usize) -> Value {
        policy_result(&self.allow, &self.block, rule_count)
    }
}

impl PolicyUpdate {
    fn result(&self) -> Value {
        policy_result(&self.allow, &self.block, self.rules.len())
    }
}

fn policy_result(allow: &[Rule], block: &[Rule], rule_count: usize) -> Value {
    json!({
        "allow": allow.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "block": block.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "ruleCount": rule_count,
    })
}

fn parse_rules(rules: Vec<String>) -> std::result::Result<Vec<Rule>, ErrorObjectOwned> {
    let mut parsed = Vec::with_capacity(rules.len());

    for rule in rules {
        let parsed_rule = rule.parse().map_err(|_| {
            rpc_error(
                INVALID_PARAMS,
                format!("invalid rule {rule:?}: expected TARGET, \"in TARGET\", or \"out TARGET\""),
            )
        })?;
        parsed.push(parsed_rule);
    }

    Ok(normalize_rules(parsed))
}

pub(super) fn normalize_rules(mut rules: Vec<Rule>) -> Vec<Rule> {
    rules.iter_mut().for_each(|rule| *rule = rule.normalized());
    rules.sort_by_key(ToString::to_string);
    rules.dedup();
    rules
}

pub(super) struct Control {
    policy: Policy,
    stream: UnixStream,
    input: Vec<u8>,
    output: Vec<u8>,
    output_offset: usize,
    discarding_input: bool,
    input_closed: bool,
    policy_changed: bool,
}

impl Control {
    pub(super) fn new(
        control_fd: RawFd,
        gateway_ip: Ipv4Address,
        allow: Vec<Rule>,
        block: Vec<Rule>,
    ) -> Result<Self> {
        let control_fd = duplicate_control_fd(control_fd)?;

        // SAFETY: duplicate_control_fd returns an open Unix stream descriptor that it owns.
        let stream = unsafe { UnixStream::from_raw_fd(control_fd) };
        stream.set_nonblocking(true)?;

        Ok(Control {
            policy: Policy::new(gateway_ip, allow, block),
            stream,
            input: Vec::new(),
            output: Vec::new(),
            output_offset: 0,
            discarding_input: false,
            input_closed: false,
            policy_changed: false,
        })
    }

    pub(super) fn service(&mut self, rules: &mut Rules) -> Result<bool> {
        if !self.flush()? {
            return Ok(false);
        }

        if !self.output.is_empty() {
            return Ok(true);
        }

        if !self.process_input(rules)? {
            return Ok(false);
        }

        if !self.output.is_empty() {
            return Ok(true);
        }

        if self.input_closed {
            return Ok(false);
        }

        let mut buf = [0; 8192];
        let mut bytes_read = 0;

        while bytes_read < MAX_SERVICE_BYTES {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    self.input_closed = true;
                    break;
                }
                Ok(n) => {
                    bytes_read += n;
                    self.input.extend_from_slice(&buf[..n]);
                    if !self.process_input(rules)? {
                        return Ok(false);
                    }

                    if !self.output.is_empty() {
                        return Ok(true);
                    }
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

        Ok(!self.input_closed)
    }

    pub(super) fn shutdown(&self) -> Result<()> {
        self.stream
            .shutdown(Shutdown::Both)
            .context("failed to shut down the control socket")
    }

    /// Returns whether the policy changed and clears the change flag.
    pub(super) fn policy_changed(&mut self) -> bool {
        std::mem::take(&mut self.policy_changed)
    }

    fn process_input(&mut self, rules: &mut Rules) -> Result<bool> {
        loop {
            if self.discarding_input {
                if let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') {
                    self.input.drain(..=newline);
                    self.discarding_input = false;
                    continue;
                }

                self.input.clear();
                return Ok(true);
            }

            let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') else {
                if self.input.len() > MAX_REQUEST_BYTES {
                    self.input.clear();
                    self.discarding_input = true;
                    self.enqueue(error_response(
                        Id::Null,
                        PARSE_ERROR,
                        "request exceeds the maximum frame size",
                    ))?;

                    return self.flush();
                }

                return Ok(true);
            };

            let line = self.input.drain(..=newline).collect::<Vec<_>>();

            if newline > MAX_REQUEST_BYTES {
                self.enqueue(error_response(
                    Id::Null,
                    PARSE_ERROR,
                    "request exceeds the maximum frame size",
                ))?;

                if !self.flush()? {
                    return Ok(false);
                }

                if !self.output.is_empty() {
                    return Ok(true);
                }

                continue;
            }

            let (response, update) = handle_request(&self.policy, rules, &line[..newline]);
            self.enqueue(response)?;

            if let Some(update) = update
                && let Some(updated_rules) = self.policy.apply(update)
            {
                *rules = updated_rules;
                self.policy_changed = true;
            }

            if !self.flush()? {
                return Ok(false);
            }

            if !self.output.is_empty() {
                return Ok(true);
            }
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetParams {
    allow: Vec<String>,
    block: Vec<String>,
}

fn handle_request(policy: &Policy, rules: &Rules, line: &[u8]) -> (Value, Option<PolicyUpdate>) {
    let value = match serde_json::from_slice::<Value>(line) {
        Ok(value) => value,
        Err(_) => {
            return (
                error_response(Id::Null, PARSE_ERROR, "invalid JSON-RPC frame"),
                None,
            );
        }
    };

    let strict_envelope = value.as_object().is_some_and(|object| {
        object
            .keys()
            .all(|key| matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
    });
    let response_id = value.get("id").map_or(Id::Null, response_id);

    let request = match serde_json::from_slice::<Request<'_>>(line) {
        Ok(request) if strict_envelope && valid_id(&request.id) => request,
        _ => {
            return (
                error_response(response_id, INVALID_REQUEST, "invalid JSON-RPC request"),
                None,
            );
        }
    };

    let mut update = None;
    let result = match request.method_name() {
        "softnet.policy.get" => {
            if !request.params().parse::<Value>().is_ok_and(empty_params) {
                Err(rpc_error(
                    INVALID_PARAMS,
                    "softnet.policy.get does not accept parameters",
                ))
            } else {
                Ok(policy.result(rules.len()))
            }
        }
        "softnet.policy.set" => {
            let params = request.params();
            let params = params.parse::<SetParams>().map_err(|_| {
                rpc_error(
                    INVALID_PARAMS,
                    "softnet.policy.set requires allow and block",
                )
            });

            params.and_then(|params| {
                let next = policy.set(params.allow, params.block)?;
                let result = next.result();
                update = Some(next);
                Ok(result)
            })
        }
        _ => Err(rpc_error(METHOD_NOT_FOUND, "method not found")),
    };

    (response(request.id(), result), update)
}

fn response_id(value: &Value) -> Id<'_> {
    match value {
        Value::String(value) if value.len() <= MAX_IDENTIFIER_BYTES => Id::Str(value.into()),
        Value::Number(value) => value.as_u64().map_or(Id::Null, Id::Number),
        _ => Id::Null,
    }
}

fn valid_id(id: &Id<'_>) -> bool {
    matches!(id, Id::Number(_))
        || matches!(id, Id::Str(value) if value.len() <= MAX_IDENTIFIER_BYTES)
}

fn empty_params(value: Value) -> bool {
    value.is_null() || value.as_object().is_some_and(|object| object.is_empty())
}

fn response(id: Id<'_>, result: std::result::Result<Value, ErrorObjectOwned>) -> Value {
    let payload = result.map_or_else(ResponsePayload::error, ResponsePayload::success);
    serde_json::to_value(Response::new(payload, id)).expect("JSON-RPC response is serializable")
}

fn error_response(id: Id<'_>, code: i32, message: impl Into<String>) -> Value {
    response(id, Err(rpc_error(code, message)))
}

fn rpc_error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, message, None::<()>)
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
        Control, INVALID_PARAMS, INVALID_REQUEST, MAX_PENDING_RESPONSE_BYTES, MAX_REQUEST_BYTES,
        MAX_RULES, METHOD_NOT_FOUND, PARSE_ERROR, Policy, handle_request,
    };
    use crate::proxy::{Direction, PolicyDecision, Rule, Rules};
    use serde_json::{Value, json};
    use smoltcp::wire::Ipv4Address;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::time::Duration;

    struct TestPolicy {
        state: Policy,
        rules: Rules,
    }

    impl TestPolicy {
        fn result(&self) -> Value {
            self.state.result(self.rules.len())
        }
    }

    impl std::ops::Deref for TestPolicy {
        type Target = Policy;

        fn deref(&self) -> &Self::Target {
            &self.state
        }
    }

    fn rules(rules: &[&str]) -> Vec<Rule> {
        rules.iter().map(|rule| rule.parse().unwrap()).collect()
    }

    fn policy(allow: &[&str], block: &[&str]) -> TestPolicy {
        let gateway_ip = Ipv4Address::new(192, 168, 64, 1);
        let allow = rules(allow);
        let block = rules(block);

        TestPolicy {
            rules: Rules::new(gateway_ip, &allow, &block),
            state: Policy::new(gateway_ip, allow, block),
        }
    }

    fn control(control_fd: RawFd) -> anyhow::Result<Control> {
        Control::new(
            control_fd,
            Ipv4Address::new(192, 168, 64, 1),
            Vec::new(),
            Vec::new(),
        )
    }

    fn request(policy: &mut TestPolicy, value: Value) -> Value {
        raw_request(policy, &serde_json::to_vec(&value).unwrap())
    }

    fn raw_request(policy: &mut TestPolicy, line: &[u8]) -> Value {
        let (response, update) = handle_request(&policy.state, &policy.rules, line);
        if let Some(update) = update
            && let Some(rules) = policy.state.apply(update)
        {
            policy.rules = rules;
        }

        response
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
        assert_eq!(response["result"]["ruleCount"], 2);
        assert_eq!(response["result"].as_object().unwrap().len(), 3);
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
                    "block": ["192.168.64.1/32", "10.0.0.0/8"]
                }
            }),
        );

        assert_eq!(response["result"]["allow"], json!(["10.0.0.0/8", "@host"]));
        assert_eq!(
            response["result"]["block"],
            json!(["10.0.0.0/8", "192.168.64.1/32"])
        );
        assert_eq!(response["result"]["ruleCount"], 2);

        assert_eq!(
            policy
                .rules
                .policy_decision(Ipv4Address::new(10, 0, 0, 1), Direction::Out),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            policy
                .rules
                .policy_decision(Ipv4Address::new(192, 168, 64, 1), Direction::Out),
            Some(PolicyDecision::Block)
        );
    }

    #[test]
    fn set_normalizes_rules() {
        let mut policy = policy(&[], &[]);

        let first = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "softnet.policy.set",
                "params": {"allow": ["@host", "10.1.2.3/8"], "block": []}
            }),
        );
        let retry = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "softnet.policy.set",
                "params": {"allow": ["10.0.0.0/8", "@host", "@host"], "block": []}
            }),
        );
        assert_eq!(first["result"], retry["result"]);
        assert_eq!(first["result"]["allow"], json!(["10.0.0.0/8", "@host"]));
    }

    #[test]
    fn set_supports_directional_rules_and_counts_logical_rules() {
        let mut policy = policy(&[], &[]);

        let response = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "softnet.policy.set",
                "params": {
                    "allow": ["in 10.1.2.3/8", "out 10.0.0.0/8"],
                    "block": ["in 10.0.0.0/8"]
                }
            }),
        );

        assert_eq!(
            response["result"]["allow"],
            json!(["in 10.0.0.0/8", "out 10.0.0.0/8"])
        );
        assert_eq!(response["result"]["block"], json!(["in 10.0.0.0/8"]));
        assert_eq!(response["result"]["ruleCount"], 2);
        let target = Ipv4Address::new(10, 1, 2, 3);
        assert_eq!(
            policy.rules.policy_decision(target, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            policy.rules.policy_decision(target, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn invalid_rules_and_limits_leave_policy_unchanged() {
        let mut policy = policy(&["@host"], &["0.0.0.0/0"]);
        let before = policy.result();

        let invalid = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "softnet.policy.set",
                "params": {"allow": ["2001:db8::/32"], "block": []}
            }),
        );
        assert_eq!(invalid["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);

        let rules = vec!["10.0.0.0/8"; MAX_RULES + 1];
        let too_many = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "softnet.policy.set",
                "params": {"allow": rules, "block": []}
            }),
        );
        assert_eq!(too_many["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);
    }

    #[test]
    fn validates_json_rpc_envelope_method_and_parameters() {
        let mut policy = policy(&[], &[]);

        let parse = raw_request(&mut policy, b"not-json");
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
                "params": {"allow": []}
            }),
        );
        assert_eq!(missing["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);

        let missing_id = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "method": "softnet.policy.set",
                "params": {"allow": ["@host"], "block": []}
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
                "params": {"allow": ["@host"], "block": []}
            }),
        );
        assert_eq!(null_id["error"]["code"], INVALID_REQUEST);
        assert!(null_id["id"].is_null());
        assert_eq!(policy.result(), before);

        let negative_id = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": -1, "method": "softnet.policy.get"}),
        );
        assert_eq!(negative_id["error"]["code"], INVALID_REQUEST);
        assert!(negative_id["id"].is_null());

        let fractional_id = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": 1.5, "method": "softnet.policy.get"}),
        );
        assert_eq!(fractional_id["error"]["code"], INVALID_REQUEST);
        assert!(fractional_id["id"].is_null());

        let oversized_id = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": "x".repeat(257), "method": "softnet.policy.get"}),
        );
        assert_eq!(oversized_id["error"]["code"], INVALID_REQUEST);
        assert!(oversized_id["id"].is_null());

        let maximum_id = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": u64::MAX, "method": "softnet.policy.get"}),
        );
        assert_eq!(maximum_id["id"], u64::MAX);
        assert!(maximum_id.get("result").is_some());

        let unexpected_field = request(
            &mut policy,
            json!({"jsonrpc": "2.0", "id": 4, "method": "softnet.policy.get", "unexpected": true}),
        );
        assert_eq!(unexpected_field["error"]["code"], INVALID_REQUEST);
        assert_eq!(unexpected_field["id"], 4);

        let duplicate_field = raw_request(
            &mut policy,
            br#"{"jsonrpc":"2.0","id":6,"method":"softnet.policy.get","method":"softnet.policy.set"}"#,
        );
        assert_eq!(duplicate_field["error"]["code"], INVALID_REQUEST);
        assert_eq!(duplicate_field["id"], 6);

        let unexpected_param = request(
            &mut policy,
            json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "softnet.policy.set",
                "params": {"allow": [], "block": [], "unexpected": true}
            }),
        );
        assert_eq!(unexpected_param["error"]["code"], INVALID_PARAMS);
        assert_eq!(policy.result(), before);
    }

    #[test]
    fn newline_delimited_control_socket_handles_multiple_requests_and_eof() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();

        client
            .write_all(
                concat!(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.get\"}\n",
                    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"@host\"],\"block\":[\"0.0.0.0/0\"]}}\n"
                )
                .as_bytes(),
            )
            .unwrap();

        assert!(control.service(&mut rules).unwrap());
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
        assert_eq!(lines[1]["result"]["allow"], json!(["@host"]));
        assert_eq!(control.policy.allow, vec!["@host".parse().unwrap()]);

        let before = control.policy.result(rules.len());
        drop(client);
        assert!(!control.service(&mut rules).unwrap());
        assert_eq!(control.policy.result(rules.len()), before);
    }

    #[test]
    fn policy_change_detection_uses_normalized_policy() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();

        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"out 10.1.2.3/8\"],\"block\":[\"in 10.0.0.0/8\",\"out 10.0.0.0/8\"]}}\n")
            .unwrap();
        assert!(control.service(&mut rules).unwrap());
        assert!(control.policy_changed());

        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"out 10.0.0.0/8\"],\"block\":[\"in 10.0.0.0/8\",\"out 10.0.0.0/8\"]}}\n")
            .unwrap();
        assert!(control.service(&mut rules).unwrap());
        assert!(!control.policy_changed());

        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[],\"block\":[\"in 10.0.0.0/8\",\"out 10.0.0.0/8\"]}}\n")
            .unwrap();
        assert!(control.service(&mut rules).unwrap());
        assert!(control.policy_changed());
        assert!(control.policy.allow.is_empty());
    }

    #[test]
    fn write_side_eof_flushes_the_final_policy_response() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();

        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"10.0.0.0/8\"],\"block\":[]}}\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        assert!(!control.service(&mut rules).unwrap());

        let mut response = [0; 1024];
        let n = client.read(&mut response).unwrap();
        let response = serde_json::from_slice::<Value>(&response[..n - 1]).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["allow"], json!(["10.0.0.0/8"]));
        assert!(control.output.is_empty());
    }

    #[test]
    fn oversized_frame_is_discarded_and_following_frame_is_processed() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();

        control.input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        control.process_input(&mut rules).unwrap();
        assert!(control.discarding_input);

        control.input.extend_from_slice(
            b"still-too-long\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.get\"}\n",
        );
        control.process_input(&mut rules).unwrap();
        assert!(!control.discarding_input);

        let mut output = [0; 2048];
        let n = client.read(&mut output).unwrap();
        let responses = std::str::from_utf8(&output[..n])
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
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());

        client
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"@host\"],",
            )
            .unwrap();
        assert!(control.service(&mut rules).unwrap());
        assert_eq!(control.policy.result(rules.len()), before);
        assert!(control.output.is_empty());

        client.write_all(b"\"block\":[]}}\n").unwrap();
        assert!(control.service(&mut rules).unwrap());

        let mut response = [0; 1024];
        let n = client.read(&mut response).unwrap();
        let response = serde_json::from_slice::<Value>(&response[..n - 1]).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["allow"], json!(["@host"]));
        assert_eq!(control.policy.allow, vec!["@host".parse().unwrap()]);
    }

    #[test]
    fn response_backpressure_keeps_the_pending_queue_bounded() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
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
    fn pipelined_policy_responses_stop_before_queue_overflow() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let allow = (0..MAX_RULES)
            .map(|index| format!("10.{}.{}.0/24", index / 256, index % 256))
            .collect::<Vec<_>>();
        let mut input = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "softnet.policy.set",
            "params": {"allow": allow, "block": []}
        }))
        .unwrap();
        input.push(b'\n');

        for id in 1..=100 {
            input.extend_from_slice(
                format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"softnet.policy.get\"}}\n")
                    .as_bytes(),
            );
        }

        control.input = input;
        assert!(control.process_input(&mut rules).unwrap());
        assert_eq!(rules.len(), MAX_RULES);
        assert!(!control.input.is_empty());
        assert!(!control.output.is_empty());
        assert!(control.output.len() - control.output_offset <= MAX_PENDING_RESPONSE_BYTES);
    }

    #[test]
    fn response_queue_overflow_does_not_apply_a_policy_update() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());

        control.output = vec![b'x'; MAX_PENDING_RESPONSE_BYTES];
        control.input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"10.0.0.0/8\"],\"block\":[]}}\n".to_vec();

        let error = control.process_input(&mut rules).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("control response queue exceeded")
        );
        assert_eq!(control.policy.result(rules.len()), before);
    }

    #[test]
    fn response_backpressure_stops_consuming_policy_updates() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());

        control.output = vec![b'x'; MAX_REQUEST_BYTES];
        assert!(control.flush().unwrap());
        assert!(!control.output.is_empty());

        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"10.0.0.0/8\"],\"block\":[]}}\n")
            .unwrap();

        assert!(control.service(&mut rules).unwrap());
        assert_eq!(control.policy.result(rules.len()), before);
        assert!(control.input.is_empty());
    }

    #[test]
    fn validates_control_descriptor_without_taking_ownership() {
        let file = File::open("/dev/null").unwrap();
        let error = control(file.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("is not a socket"));
        assert!(file.metadata().is_ok());

        let (datagram, _) = UnixDatagram::pair().unwrap();
        let error = control(datagram.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("not a Unix stream socket"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let error = control(listener.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("not a Unix socket"));

        let (stream, _peer) = UnixStream::pair().unwrap();
        let control = control(stream.as_raw_fd()).unwrap();
        drop(control);
        assert!(unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) != -1 });
    }

    #[test]
    fn shutdown_signals_eof_while_the_original_descriptor_remains_open() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let control = control(server.as_raw_fd()).unwrap();

        control.shutdown().unwrap();
        drop(control);

        assert!(unsafe { libc::fcntl(server.as_raw_fd(), libc::F_GETFD) != -1 });
        let mut response = [0; 1];
        assert_eq!(client.read(&mut response).unwrap(), 0);
    }
}
