use crate::NetType;
use crate::control_transport::{ControlTransport, Frame};
use crate::manager::{Call, CallError, Reply, Request, VmConfig};
use crate::network::MAX_VMS;
use crate::proxy::Rule;
use anyhow::Result;
use hickory_server::proto::rr::Name;
use jsonrpsee_types::{
    ErrorObjectOwned, Id, Request as RpcRequest, Response, ResponsePayload,
    error::{
        CALL_EXECUTION_FAILED_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE,
        METHOD_NOT_FOUND_CODE, PARSE_ERROR_CODE,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::os::fd::OwnedFd;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

const MAX_RULES: usize = 4096;

pub struct Control {
    transport: ControlTransport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InitializeParams {
    // Shared network mode for all VMs: "nat" by default, or "host"
    #[serde(default)]
    vm_net_type: Option<String>,

    // Complete VM batch, ordered to match the attached SCM_RIGHTS descriptors
    vms: Vec<VmParams>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VmParams {
    // Unique MAC address used by this VM
    vm_mac_address: String,

    // Single-label VM name registered in our DNS zone
    name: Option<String>,

    // Initial packet filter allow rules
    #[serde(default)]
    allow: Vec<String>,

    // Initial packet filter block rules
    #[serde(default)]
    block: Vec<String>,

    // TCP port-forwarding mappings in EXTERNAL:INTERNAL form
    #[serde(default)]
    expose: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct GetParams {
    // Target VM UUID; omission is allowed only for a single-VM initialization
    vm_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetParams {
    // Target VM UUID; omission is allowed only for a single-VM initialization
    #[serde(default)]
    vm_id: Option<String>,

    // Complete replacement for the VM's packet filter allow rules
    allow: Vec<String>,

    // Complete replacement for the VM's packet filter block rules
    block: Vec<String>,
}

impl Control {
    pub fn new(control_fd: OwnedFd) -> Result<Self> {
        Ok(Self {
            transport: ControlTransport::new(control_fd)?,
        })
    }

    pub(crate) async fn run(mut self, control_calls_tx: mpsc::Sender<Call>) -> Result<()> {
        loop {
            let frame = tokio::select! {
                frame = self.transport.next() => match frame? {
                    Some(frame) => frame,
                    None => return Ok(()),
                },
                _ = control_calls_tx.closed() => return Ok(()),
            };

            let response = match Self::parse(frame) {
                Ok((id, request)) => {
                    let (reply, result) = oneshot::channel();

                    // The manager no longer accepts requests, so finish the control task
                    if control_calls_tx
                        .send(Call { request, reply })
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }

                    // The manager dropped the reply sender without responding, so finish the control task
                    let Ok(result) = result.await else {
                        return Ok(());
                    };

                    // Translate operation results into the existing wire response
                    let result = match result {
                        Ok(Reply::Initialized(vms)) => {
                            // Preserve request order in the response
                            let vms = vms
                                .into_iter()
                                .map(|vm| {
                                    json!({
                                        "vmId": vm.vm_id.to_string(),
                                        "vmMacAddress": vm.vm_mac_address.to_string(),
                                    })
                                })
                                .collect::<Vec<_>>();

                            Ok(json!({"vms": vms}))
                        }
                        Ok(Reply::Policy(policy)) => Ok(json!({
                            "allow": policy.allow.iter().map(ToString::to_string).collect::<Vec<_>>(),
                            "block": policy.block.iter().map(ToString::to_string).collect::<Vec<_>>(),
                            "ruleCount": policy.rule_count,
                        })),
                        Err(CallError::InvalidParams(error)) => {
                            Err(rpc_error(INVALID_PARAMS_CODE, error.to_string()))
                        }
                        Err(CallError::Failed(error)) => {
                            Err(rpc_error(CALL_EXECUTION_FAILED_CODE, format!("{error:#}")))
                        }
                    };

                    response(id, result)
                }
                Err(response) => response,
            };

            let response_bytes = serde_json::to_vec(&response)?;

            // Prefer the final reply when ready and cancel blocked writes on shutdown
            tokio::select! {
                biased;

                result = self.transport.send(&response_bytes) => result?,
                _ = control_calls_tx.closed() => return Ok(()),
            }
        }
    }

    /// Validates a frame and returns its request or a complete error response
    fn parse(frame: Frame) -> std::result::Result<(Id<'static>, Request), Value> {
        let Frame { line, mut fds } = frame;

        // Use a null response ID for framing errors because the request has not been parsed
        let line =
            line.map_err(|error| error_response(Id::Null, PARSE_ERROR_CODE, error.to_string()))?;

        // Validate the JSON-RPC envelope and keep its ID for the response
        let request = parse_request(&line)?;
        let id = request.id().into_owned();

        // Validate the method, parameters, and descriptors, attaching the request ID to any error
        let parsed =
            parse_method(&request, &mut fds).map_err(|error| response(id.clone(), Err(error)))?;

        Ok((id, parsed))
    }
}

/// Parses the existing strict JSON-RPC envelope without consuming its attached FDs
fn parse_request(line: &str) -> std::result::Result<RpcRequest<'_>, Value> {
    let value: Value = serde_json::from_str(line)
        .map_err(|_| error_response(Id::Null, PARSE_ERROR_CODE, "invalid JSON-RPC frame"))?;
    let strict_envelope = value.as_object().is_some_and(|object| {
        object
            .keys()
            .all(|key| matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
    });

    let valid_id = value
        .get("id")
        .is_some_and(|id| id.is_string() || id.as_u64().is_some());

    match serde_json::from_str::<RpcRequest<'_>>(line) {
        Ok(request) if strict_envelope && valid_id => Ok(request),
        _ => Err(error_response(
            // Recover the request ID for error responses, using null for missing or unsupported IDs
            match value.get("id") {
                Some(Value::String(value)) => Id::Str(value.into()),
                Some(Value::Number(value)) => value.as_u64().map_or(Id::Null, Id::Number),
                _ => Id::Null,
            },
            INVALID_REQUEST_CODE,
            "invalid JSON-RPC request",
        )),
    }
}

fn parse_method(
    request: &RpcRequest<'_>,
    fds: &mut Vec<OwnedFd>,
) -> std::result::Result<Request, ErrorObjectOwned> {
    match request.method_name() {
        "softnet.initialize" => {
            let params = request.params().parse::<InitializeParams>()?;

            parse_initialize(fds, params)
        }
        "softnet.policy.get" => {
            let params = request
                .params()
                .parse::<Value>()
                .and_then(|value| match value {
                    Value::Null => Ok(GetParams::default()),
                    Value::Object(_) => request.params().parse::<GetParams>(),
                    _ => Err(rpc_error(INVALID_PARAMS_CODE, "invalid policy target")),
                })?;

            Ok(Request::GetPolicy {
                vm_id: parse_vm_id(params.vm_id)?,
            })
        }
        "softnet.policy.set" => {
            let params = request.params().parse::<SetParams>()?;
            let vm_id = parse_vm_id(params.vm_id)?;
            let (allow, block) = parse_policy(params.allow, params.block)?;

            Ok(Request::SetPolicy {
                vm_id,
                allow,
                block,
            })
        }
        _ => Err(rpc_error(METHOD_NOT_FOUND_CODE, "method not found")),
    }
}

fn parse_vm_id(vm_id: Option<String>) -> std::result::Result<Option<Uuid>, ErrorObjectOwned> {
    vm_id
        .map(|vm_id| {
            vm_id
                .parse::<Uuid>()
                .map_err(|_| rpc_error(INVALID_PARAMS_CODE, "unknown vmId"))
        })
        .transpose()
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

fn parse_initialize(
    fds: &mut Vec<OwnedFd>,
    params: InitializeParams,
) -> std::result::Result<Request, ErrorObjectOwned> {
    if !(1..=MAX_VMS).contains(&params.vms.len()) {
        return Err(rpc_error(
            INVALID_PARAMS_CODE,
            format!("vms must contain between 1 and {MAX_VMS} entries"),
        ));
    }

    if fds.len() != params.vms.len() {
        return Err(rpc_error(
            INVALID_PARAMS_CODE,
            "softnet.initialize requires exactly one SCM_RIGHTS descriptor per VM",
        ));
    }

    let vm_net_type = match params.vm_net_type.as_deref().unwrap_or("nat") {
        "nat" => NetType::Nat,
        "host" => NetType::Host,
        _ => {
            return Err(rpc_error(
                INVALID_PARAMS_CODE,
                "vmNetType must be nat or host",
            ));
        }
    };

    // Consume descriptors in the same order as their VM configurations
    let vms = params
        .vms
        .into_iter()
        .zip(fds.drain(..))
        .map(|(params, fd)| {
            let vm_mac_address = params
                .vm_mac_address
                .parse()
                .map_err(|_| rpc_error(INVALID_PARAMS_CODE, "invalid vmMacAddress"))?;

            // Parse optional VM names for DNS lookup
            let name = params
                .name
                .map(|name| {
                    Name::from_ascii(name)
                        .map_err(|_| rpc_error(INVALID_PARAMS_CODE, "invalid name"))
                })
                .transpose()?;

            let (allow, block) = parse_policy(params.allow, params.block)?;
            let exposed_ports = params
                .expose
                .into_iter()
                .map(|port| {
                    port.parse().map_err(|_| {
                        rpc_error(INVALID_PARAMS_CODE, "invalid exposed port specification")
                    })
                })
                .collect::<std::result::Result<_, _>>()?;

            Ok(VmConfig {
                vm_fd: fd,
                vm_mac_address,
                name,
                allow,
                block,
                exposed_ports,
            })
        })
        .collect::<std::result::Result<_, ErrorObjectOwned>>()?;

    Ok(Request::Initialize { vm_net_type, vms })
}

fn parse_policy(
    allow: Vec<String>,
    block: Vec<String>,
) -> std::result::Result<(Vec<Rule>, Vec<Rule>), ErrorObjectOwned> {
    if allow.len() + block.len() > MAX_RULES {
        return Err(rpc_error(
            INVALID_PARAMS_CODE,
            format!("allow and block may contain at most {MAX_RULES} rules combined"),
        ));
    }

    let parse = |rules: Vec<String>| {
        rules
            .into_iter()
            .map(|rule| {
                rule.parse()
                    .map_err(|_| rpc_error(INVALID_PARAMS_CODE, format!("invalid rule {rule:?}")))
            })
            .collect::<std::result::Result<_, _>>()
    };

    Ok((parse(allow)?, parse(block)?))
}

#[cfg(test)]
#[path = "control_test.rs"]
mod tests;
