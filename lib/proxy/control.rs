use super::{Rule, Rules};
use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use jsonrpsee_types::{
    ErrorObjectOwned, Id, Request, Response, ResponsePayload,
    error::{
        INVALID_PARAMS_CODE as INVALID_PARAMS, INVALID_REQUEST_CODE as INVALID_REQUEST,
        METHOD_NOT_FOUND_CODE as METHOD_NOT_FOUND, PARSE_ERROR_CODE as PARSE_ERROR,
    },
};
use nix::sys::socket::{Shutdown, shutdown};
use serde::Deserialize;
use serde_json::{Value, json};
use smoltcp::wire::Ipv4Address;
use std::future::poll_fn;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use tokio_util::codec::{Decoder, Encoder, Framed, LinesCodec, LinesCodecError};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PENDING_RESPONSE_BYTES: usize = 4 * MAX_REQUEST_BYTES;
const MAX_RULES: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 256;

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
    stream: Framed<tokio::net::UnixStream, ControlCodec>,
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
            stream: Framed::new(
                tokio::net::UnixStream::from_std(stream)?,
                ControlCodec(LinesCodec::new_with_max_length(MAX_REQUEST_BYTES)),
            ),
        })
    }

    /// Cancellation only interrupts buffered I/O; policy changes finish in the same poll.
    /// Returns None on EOF, or whether the completed request changed the policy.
    pub(super) async fn service(&mut self, rules: &mut Rules) -> Result<Option<bool>> {
        // Flush pending responses before reading; Framed retains partial I/O across cancellation
        self.stream.flush().await?;
        poll_fn(|cx| self.stream.poll_ready_unpin(cx)).await?;

        let Some(frame) = self.stream.next().await.transpose()? else {
            return Ok(None);
        };

        self.respond(frame, rules).map(Some)
    }

    fn respond(
        &mut self,
        frame: Result<String, LinesCodecError>,
        rules: &mut Rules,
    ) -> Result<bool> {
        // Reply to malformed frames without changing the active policy
        let (response, update) = match frame {
            Ok(line) => handle_request(&self.policy, rules, line.as_bytes()),
            Err(error) => (
                error_response(
                    Id::Null,
                    PARSE_ERROR,
                    match error {
                        LinesCodecError::MaxLineLengthExceeded => {
                            "request exceeds the maximum frame size"
                        }
                        LinesCodecError::Io(_) => "invalid JSON-RPC frame",
                    },
                ),
                None,
            ),
        };

        // service() reserved sink capacity; encoding checks the byte limit before any update
        self.stream.start_send_unpin(response)?;

        // Keep the update in this poll with no intervening await
        if let Some(update) = update
            && let Some(updated_rules) = self.policy.apply(update)
        {
            *rules = updated_rules;
            return Ok(true);
        }

        Ok(false)
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        // Shut down the inherited connection even while the original descriptor remains open
        let fd = self.stream.get_ref().as_raw_fd();

        // Shut down writes first because macOS can reject SHUT_RDWR after a peer half-close
        let _ = shutdown(fd, Shutdown::Write);
        let _ = shutdown(fd, Shutdown::Read);
    }
}

struct ControlCodec(LinesCodec);

impl Decoder for ControlCodec {
    type Item = Result<String, LinesCodecError>;
    type Error = io::Error;

    fn decode(&mut self, input: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        // Return malformed frames as RPC errors so later requests can still be processed
        Ok(match self.0.decode(input) {
            Ok(line) => line.map(Ok),
            Err(error) => Some(Err(error)),
        })
    }

    fn decode_eof(&mut self, input: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        let frame = self.decode(input)?;

        // Unlike LinesCodec, discard an unterminated final request without applying it
        if frame.is_none() {
            input.clear();
        }

        Ok(frame)
    }
}

impl Encoder<Value> for ControlCodec {
    type Error = io::Error;

    fn encode(&mut self, response: Value, output: &mut BytesMut) -> io::Result<()> {
        let mut response = serde_json::to_vec(&response).map_err(io::Error::other)?;
        response.push(b'\n');

        // Bound the complete encoded response before appending it
        if output.len() + response.len() > MAX_PENDING_RESPONSE_BYTES {
            return Err(io::Error::other(format!(
                "control response queue exceeded {MAX_PENDING_RESPONSE_BYTES} bytes"
            )));
        }

        output.extend_from_slice(&response);
        Ok(())
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
        Control, ControlCodec, INVALID_PARAMS, INVALID_REQUEST, MAX_PENDING_RESPONSE_BYTES,
        MAX_REQUEST_BYTES, MAX_RULES, METHOD_NOT_FOUND, PARSE_ERROR, Policy, handle_request,
    };
    use crate::proxy::{Direction, PolicyDecision, Rule, Rules};
    use bytes::BytesMut;
    use futures_util::SinkExt;
    use serde_json::{Value, json};
    use smoltcp::wire::Ipv4Address;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::time::Duration;
    use tokio_util::codec::{Decoder, Encoder, LinesCodec};

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

    #[tokio::test(flavor = "current_thread")]
    async fn newline_delimited_control_socket_handles_multiple_requests_and_eof() {
        let (mut client, server) = UnixStream::pair().unwrap();
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
        client.shutdown(Shutdown::Write).unwrap();

        assert_eq!(control.service(&mut rules).await.unwrap(), Some(false));
        assert_eq!(control.service(&mut rules).await.unwrap(), Some(true));
        assert_eq!(control.service(&mut rules).await.unwrap(), None);
        assert_eq!(control.policy.allow, vec!["@host".parse().unwrap()]);
        drop(control);

        let mut output = String::new();
        client.read_to_string(&mut output).unwrap();
        let responses = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["allow"], json!(["@host"]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_change_detection_uses_normalized_policy() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        for (allow, changed) in [("out 10.1.2.3/8", true), ("out 10.0.0.0/8", false)] {
            writeln!(
                client,
                "{}",
                json!({
                    "jsonrpc": "2.0", "id": 1, "method": "softnet.policy.set",
                    "params": {"allow": [allow], "block": ["in 10.0.0.0/8", "out 10.0.0.0/8"]}
                })
            )
            .unwrap();
            assert_eq!(control.service(&mut rules).await.unwrap(), Some(changed));
        }
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[],\"block\":[\"in 10.0.0.0/8\",\"out 10.0.0.0/8\"]}}\n")
            .unwrap();
        assert_eq!(control.service(&mut rules).await.unwrap(), Some(true));
        assert!(control.policy.allow.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_side_eof_flushes_the_final_policy_response() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"10.0.0.0/8\"],\"block\":[]}}\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        assert_eq!(control.service(&mut rules).await.unwrap(), Some(true));
        assert_eq!(control.service(&mut rules).await.unwrap(), None);
        assert!(control.stream.write_buffer().is_empty());
        drop(control);

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        let response = serde_json::from_str::<Value>(&response).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["allow"], json!(["10.0.0.0/8"]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_frame_is_discarded_and_following_frame_is_processed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let mut client = tokio::net::UnixStream::from_std(client).unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let mut input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        input.extend_from_slice(
            b"still-too-long\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.get\"}\n",
        );
        let (output, ()) = tokio::join!(
            async {
                client.write_all(&input).await.unwrap();
                client.shutdown().await.unwrap();
                let mut output = String::new();
                client.read_to_string(&mut output).await.unwrap();
                output
            },
            async {
                assert_eq!(control.service(&mut rules).await.unwrap(), Some(false));
                assert_eq!(control.service(&mut rules).await.unwrap(), Some(false));
                assert_eq!(control.service(&mut rules).await.unwrap(), None);
                drop(control);
            }
        );
        let responses = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[1]["id"], 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fragmented_frame_survives_cancelled_service() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"@host\"],")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), control.service(&mut rules))
                .await
                .is_err()
        );
        assert_eq!(control.policy.result(rules.len()), before);
        assert!(control.stream.write_buffer().is_empty());

        client.write_all(b"\"block\":[]}}\n").unwrap();
        assert_eq!(control.service(&mut rules).await.unwrap(), Some(true));
        control.stream.flush().await.unwrap();
        let mut response = [0; 1024];
        let n = client.read(&mut response).unwrap();
        let response = serde_json::from_slice::<Value>(&response[..n - 1]).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["allow"], json!(["@host"]));
    }

    #[test]
    fn codec_enforces_exact_request_and_response_limits() {
        let mut codec = ControlCodec(LinesCodec::new_with_max_length(MAX_REQUEST_BYTES));
        let mut input = BytesMut::from(vec![b'x'; MAX_REQUEST_BYTES].as_slice());
        input.extend_from_slice(b"\n");
        assert_eq!(
            codec.decode(&mut input).unwrap().unwrap().unwrap().len(),
            MAX_REQUEST_BYTES
        );
        input.resize(MAX_REQUEST_BYTES + 1, b'x');
        assert!(codec.decode(&mut input).unwrap().unwrap().is_err());
        input.extend_from_slice(b"discarded\nvalid\n");
        assert_eq!(codec.decode(&mut input).unwrap().unwrap().unwrap(), "valid");

        let response = json!({"result": "x".repeat(MAX_REQUEST_BYTES)});
        let mut output = BytesMut::new();
        while codec.encode(response.clone(), &mut output).is_ok() {}
        assert!(output.len() <= MAX_PENDING_RESPONSE_BYTES);
        assert!(output.len() >= 3 * MAX_REQUEST_BYTES);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipelined_policy_responses_stop_before_queue_overflow() {
        use tokio::io::AsyncWriteExt;

        let (client, server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let mut client = tokio::net::UnixStream::from_std(client).unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let allow = (0..MAX_RULES)
            .map(|index| format!("10.{}.{}.0/24", index / 256, index % 256))
            .collect::<Vec<_>>();
        let mut input = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 0, "method": "softnet.policy.set",
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
        let (written, processed) = tokio::join!(client.write_all(&input), async {
            let mut processed = 0;
            while let Ok(result) =
                tokio::time::timeout(Duration::from_millis(50), control.service(&mut rules)).await
            {
                assert!(result.unwrap().is_some());
                processed += 1;
                assert!(processed <= 101);
            }
            processed
        });
        written.unwrap();
        assert!((1..101).contains(&processed));
        assert_eq!(rules.len(), MAX_RULES);
        assert!(!control.stream.write_buffer().is_empty());
        assert!(control.stream.write_buffer().len() <= MAX_PENDING_RESPONSE_BYTES);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn response_queue_overflow_does_not_apply_a_policy_update() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());
        control
            .stream
            .write_buffer_mut()
            .resize(MAX_PENDING_RESPONSE_BYTES, b'x');
        let error = control
            .respond(
                Ok("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"10.0.0.0/8\"],\"block\":[]}}".into()),
                &mut rules,
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("control response queue exceeded")
        );
        assert_eq!(control.policy.result(rules.len()), before);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn backpressure_survives_cancellation_and_stops_policy_updates() {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());
        let response = json!({"jsonrpc": "2.0", "id": 0, "result": "x".repeat(MAX_REQUEST_BYTES)});
        control.stream.start_send_unpin(response.clone()).unwrap();
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"10.0.0.0/8\"],\"block\":[]}}\n")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), control.service(&mut rules))
                .await
                .is_err()
        );
        assert_eq!(control.policy.result(rules.len()), before);
        assert!(control.stream.read_buffer().is_empty());
        assert!(!control.stream.write_buffer().is_empty());
        client.set_nonblocking(true).unwrap();
        let mut client = BufReader::new(tokio::net::UnixStream::from_std(client).unwrap());
        let mut line = String::new();
        let (changed, _) = tokio::join!(control.service(&mut rules), client.read_line(&mut line));
        assert_eq!(changed.unwrap(), Some(true));
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap(), response);
        line.clear();
        let (flushed, read) = tokio::join!(control.stream.flush(), client.read_line(&mut line));
        flushed.unwrap();
        read.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unterminated_request_at_eof_does_not_change_policy() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        let before = control.policy.result(rules.len());
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"softnet.policy.set\",\"params\":{\"allow\":[\"@host\"],\"block\":[]}}")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(control.service(&mut rules).await.unwrap(), None);
        assert_eq!(control.policy.result(rules.len()), before);
        assert!(control.stream.write_buffer().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_utf8_frame_does_not_prevent_following_request() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut control = control(server.as_raw_fd()).unwrap();
        let mut rules = Rules::default();
        client
            .write_all(b"\xff\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"softnet.policy.get\"}\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(control.service(&mut rules).await.unwrap(), Some(false));
        assert_eq!(control.service(&mut rules).await.unwrap(), Some(false));
        assert_eq!(control.service(&mut rules).await.unwrap(), None);
        drop(control);
        let mut output = String::new();
        client.read_to_string(&mut output).unwrap();
        let responses = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[1]["id"], 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn validates_control_descriptor_without_taking_ownership() {
        let file = File::open("/dev/null").unwrap();
        let error = control(file.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("is not a socket"));
        assert!(file.metadata().is_ok());
        let (datagram, _) = UnixDatagram::pair().unwrap();
        let error = control(datagram.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("not a Unix stream socket"));
        let internet = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Inet,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::empty(),
            None,
        )
        .unwrap();
        let error = control(internet.as_raw_fd()).err().unwrap();
        assert!(error.to_string().contains("not a Unix socket"));

        let (stream, _peer) = UnixStream::pair().unwrap();
        let control = control(stream.as_raw_fd()).unwrap();
        drop(control);
        assert!(unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) != -1 });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_control_signals_eof_while_the_original_descriptor_remains_open() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let control = control(server.as_raw_fd()).unwrap();
        drop(control);
        assert!(unsafe { libc::fcntl(server.as_raw_fd(), libc::F_GETFD) != -1 });
        let mut response = [0; 1];
        assert_eq!(client.read(&mut response).unwrap(), 0);
    }
}
