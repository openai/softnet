use crate::control::Control;
use crate::dhcp_server::DHCP_SERVER_MAC;
use crate::dns_server::DnsServer;
use crate::network::{MAX_VMS, NetType, Network, SUBNET_PREFIX_LEN};
use crate::proxy::{Command, ExposedPort, Policy, Proxy, Rule};
use crate::subnet_finder;
use crate::vm::VM;
use anyhow::{Context, Result, ensure};
use futures_util::FutureExt;
use futures_util::future::OptionFuture;
use hickory_server::proto::rr::Name;
use mac_address::MacAddress;
use privdrop::PrivDrop;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::task::JoinMap;
use uuid::Uuid;

pub struct Manager {
    control: Option<JoinHandle<Result<()>>>,
    control_calls_rx: mpsc::Receiver<Call>,
    proxy_handles: BTreeMap<Uuid, ProxyHandle>,
    proxy_tasks: JoinMap<Uuid, Result<()>>,
    initialization: Option<JoinHandle<Result<()>>>,
    user: String,
    group: String,
    initialized: bool,
    default_vm_id: Option<Uuid>,
}

/// One VM's configuration and raw or owned packet socket.
#[derive(Debug)]
pub struct VmConfig<Fd = OwnedFd> {
    pub vm_fd: Fd,
    pub vm_mac_address: MacAddress,
    pub name: Option<Name>,
    pub allow: Vec<Rule>,
    pub block: Vec<Rule>,
    pub exposed_ports: Vec<ExposedPort>,
}

/// An initialized VM in the same order as its request entry.
#[derive(Debug)]
pub struct InitializedVm {
    pub vm_id: Uuid,
    pub vm_mac_address: MacAddress,
}

/// Distinguish invalid parameters, retryable rejection, and fatal activation failure.
#[derive(Debug, thiserror::Error)]
pub enum InitializationError {
    #[error(transparent)]
    InvalidParams(anyhow::Error),

    #[error(transparent)]
    Rejected(anyhow::Error),

    #[error(transparent)]
    ActivationFailed(anyhow::Error),
}

/// Each call carries its own reply channel.
pub(crate) struct Call {
    pub(crate) request: Request,
    pub(crate) reply: oneshot::Sender<std::result::Result<Reply, CallError>>,
}

/// A validated request owns its attached descriptors until execution.
#[derive(Debug)]
pub(crate) enum Request {
    Initialize {
        vm_net_type: NetType,
        vms: Vec<VmConfig>,
    },
    GetPolicy {
        vm_id: Option<Uuid>,
    },
    SetPolicy {
        vm_id: Option<Uuid>,
        allow: Vec<Rule>,
        block: Vec<Rule>,
    },
}

/// Results of manager operations.
#[derive(Debug)]
pub(crate) enum Reply {
    Initialized(Vec<InitializedVm>),
    Policy(Policy),
}

/// Keep invalid parameters distinct from operation failures.
#[derive(Debug)]
pub(crate) enum CallError {
    InvalidParams(anyhow::Error),
    Failed(anyhow::Error),
}

struct ProxyHandle {
    commands: mpsc::Sender<Command>,
}

impl Manager {
    pub fn new(user: String, group: String, control: Option<Control>) -> Self {
        // The control task owns socket I/O and exchanges calls with the manager
        let (control_calls_tx, control_calls_rx) = mpsc::channel(1);
        let control = control.map(|control| tokio::spawn(control.run(control_calls_tx)));

        Self {
            control,
            control_calls_rx,
            proxy_handles: BTreeMap::new(),
            proxy_tasks: JoinMap::new(),
            initialization: None,
            user,
            group,
            initialized: false,
            default_vm_id: None,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        // Keep running for existing VMs or an initial configuration request
        loop {
            tokio::select! {
                Some(result) = self.proxy_tasks.join_next() => {
                    // Proxy task finished
                    self.reap_task(result)?;

                    // Exit after the final proxy, even if control remains connected
                    if self.proxy_tasks.is_empty() {
                        break;
                    }
                },
                Some(result) = OptionFuture::from(self.control.as_mut()) => {
                    // Control task had finished
                    self.control = None;

                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => log::warn!("disabling Softnet control socket: {error:#}"),
                        Err(error) if error.is_cancelled() => {}
                        Err(error) => log::warn!("Softnet control task failed: {error}"),
                    }

                    self.finish_control().await;
                }
                Some(call) = self.control_calls_rx.recv() => {
                    // New control task request
                    self.dispatch(call).await?
                },
                else => {
                    // All proxy tasks and control task have finished
                    break;
                },
            }
        }

        self.finish_control().await;

        Ok(())
    }

    async fn dispatch(&mut self, Call { request, reply }: Call) -> Result<()> {
        let result = match request {
            Request::Initialize { vm_net_type, vms } => {
                match self.initialize(vm_net_type, vms).await {
                    Ok(vms) => Ok(Reply::Initialized(vms)),
                    Err(InitializationError::InvalidParams(error)) => {
                        Err(CallError::InvalidParams(error))
                    }
                    Err(InitializationError::Rejected(error)) => Err(CallError::Failed(error)),
                    Err(InitializationError::ActivationFailed(error)) => {
                        // Give control a chance to send the failure reply before ending this run
                        let _ = reply.send(Err(CallError::Failed(anyhow::anyhow!("{error:#}"))));
                        self.finish_control().await;

                        return Err(error);
                    }
                }
            }
            Request::GetPolicy { vm_id } => match self.proxy_handle(vm_id) {
                Ok(proxy) => proxy
                    .policy_get()
                    .await
                    .map(Reply::Policy)
                    .map_err(CallError::Failed),
                Err(error) => Err(CallError::InvalidParams(error)),
            },
            Request::SetPolicy {
                vm_id,
                allow,
                block,
            } => match self.proxy_handle(vm_id) {
                Ok(proxy) => proxy
                    .policy_set(allow, block)
                    .await
                    .map(Reply::Policy)
                    .map_err(CallError::Failed),
                Err(error) => Err(CallError::InvalidParams(error)),
            },
        };

        let _ = reply.send(result);

        Ok(())
    }

    pub async fn initialize<Fd: AsRawFd + Send + 'static>(
        &mut self,
        vm_net_type: NetType,
        vms: Vec<VmConfig<Fd>>,
    ) -> Result<Vec<InitializedVm>, InitializationError> {
        if self.initialized {
            return Err(InitializationError::Rejected(anyhow::anyhow!(
                "Softnet is already initialized"
            )));
        }

        if vms.is_empty() || vms.len() > MAX_VMS {
            return Err(InitializationError::Rejected(anyhow::anyhow!(
                "initialization requires between 1 and {MAX_VMS} VMs"
            )));
        }

        // Validate MAC addresses before creating any native resources
        let mut mac_addresses = BTreeSet::new();

        for vm in &vms {
            if vm.vm_mac_address.bytes() == DHCP_SERVER_MAC.0 {
                return Err(InitializationError::Rejected(anyhow::anyhow!(
                    "VM MAC address {} is reserved for the DHCP server",
                    vm.vm_mac_address
                )));
            }

            if !mac_addresses.insert(vm.vm_mac_address.bytes()) {
                return Err(InitializationError::Rejected(anyhow::anyhow!(
                    "VM MAC address {} is already in use",
                    vm.vm_mac_address
                )));
            }
        }

        // Find an unused subnet for the gateway and VMs
        let (_, _, subnet) = subnet_finder::find_available_subnet(SUBNET_PREFIX_LEN)
            .context("failed to initialize proxy")
            .map_err(InitializationError::Rejected)?;

        // Reserve the first usable address for the gateway
        let mut hosts = subnet.hosts().skip(1);

        let mut dns_records = Vec::new();
        let mut configured = Vec::with_capacity(vms.len());
        let mut initialized = Vec::with_capacity(vms.len());

        for (index, config) in vms.into_iter().enumerate() {
            let vm = VM::new(config.vm_fd.as_raw_fd())
                .with_context(|| format!("failed to prepare VM at index {index}"))
                .context("failed to initialize proxy")
                .map_err(InitializationError::Rejected)?;
            let vm_ip = hosts
                .next()
                .context("shared VM subnet has no available addresses")
                .context("failed to initialize proxy")
                .map_err(InitializationError::Rejected)?;
            let vm_id = Uuid::now_v7();
            initialized.push(InitializedVm {
                vm_id,
                vm_mac_address: config.vm_mac_address,
            });

            // Collect DNS records for named VMs
            if let Some(vm_name) = config.name.clone() {
                dns_records.push((vm_name, vm_ip));
            }

            configured.push((vm, config, vm_ip, vm_id));
        }

        // Validate and share the DNS zone before preparing VM interfaces
        let dns_server = (!dns_records.is_empty())
            .then(|| DnsServer::new(dns_records).map(Arc::new))
            .transpose()
            .map_err(InitializationError::InvalidParams)?;

        // Register VM tasks before setup so failures are cleaned up through shutdown
        let mut proxy_senders = Vec::with_capacity(initialized.len());
        let mut start_senders = Vec::with_capacity(initialized.len());

        for vm in &initialized {
            let (commands_tx, commands_rx) = mpsc::channel(1);
            let (proxy_tx, proxy_rx) = oneshot::channel();
            let (start_tx, start_rx) = oneshot::channel();
            proxy_senders.push(proxy_tx);
            start_senders.push(start_tx);
            self.proxy_tasks.spawn(vm.vm_id, async move {
                let Ok(proxy) = proxy_rx.await else {
                    return Ok(());
                };

                ProxyHandle::run(proxy, commands_rx, start_rx).await
            });
            self.proxy_handles.insert(
                vm.vm_id,
                ProxyHandle {
                    commands: commands_tx,
                },
            );
        }

        // Retain the native worker so shutdown can join it after cancellation
        self.initialization = Some(tokio::task::spawn_blocking(move || {
            let reservations: Vec<_> = configured
                .iter()
                .map(|(_, config, vm_ip, _)| (config.vm_mac_address, *vm_ip))
                .collect();
            let port_forwardings: Vec<_> = configured
                .iter()
                .flat_map(|(_, config, vm_ip, _)| {
                    config.exposed_ports.iter().map(|port| (*vm_ip, *port))
                })
                .collect();
            let network = Network::new(vm_net_type, subnet, &reservations, &port_forwardings)?;
            let mut proxies = Vec::with_capacity(configured.len());

            // Finish the entire batch before giving a proxy to any VM task
            for (index, (vm, config, vm_ip, vm_id)) in configured.into_iter().enumerate() {
                let proxy = Proxy::new(
                    vm,
                    config.vm_mac_address,
                    vm_ip,
                    &network,
                    config.allow,
                    config.block,
                    dns_server.clone(),
                )
                .with_context(|| format!("failed to initialize VM at index {index} ({vm_id})"))?;

                proxies.push(proxy);
            }

            // Failed transfers release native resources on this blocking worker
            for (proxy, sender) in proxies.into_iter().zip(proxy_senders) {
                ensure!(
                    sender.send(proxy).is_ok(),
                    "VM task stopped during initialization"
                );
            }

            Ok(())
        }));

        self.finish_initialization()
            .await
            .context("failed to initialize proxy")
            .map_err(InitializationError::ActivationFailed)?;

        // Complete the credential transition without another cancellation point
        PrivDrop::default()
            .user(self.user.clone())
            .group(self.group.clone())
            .apply()
            .context("failed to drop privileges")
            .map_err(InitializationError::ActivationFailed)?;
        self.initialized = true;

        // Only a single-VM batch has an implicit policy target
        self.default_vm_id = match initialized.as_slice() {
            [vm] => Some(vm.vm_id),
            _ => None,
        };

        // Start forwarding only after the credential transition succeeds
        for start in start_senders {
            let _ = start.send(());
        }

        Ok(initialized)
    }

    async fn finish_initialization(&mut self) -> Result<()> {
        let Some(initialization) = self.initialization.as_mut() else {
            return Ok(());
        };

        let result = initialization.await;
        self.initialization = None;

        result.context("VM network initialization task failed")?
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        // Interrupt control even if a client has stopped reading its response
        if let Some(control) = &self.control {
            control.abort();
        }

        self.finish_control().await;

        // Close every command channel before joining the proxy tasks
        self.proxy_handles.clear();

        // Join every task before returning the first cleanup failure
        let mut result = self.finish_initialization().await;

        while let Some(task) = self.proxy_tasks.join_next().await {
            result = result.and(self.reap_task(task));
        }

        result
    }

    async fn finish_control(&mut self) {
        // Reject queued calls so their reply waiters and owned descriptors are released
        self.control_calls_rx.close();

        while self.control_calls_rx.recv().await.is_some() {}

        if let Some(control) = &mut self.control {
            match control.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("disabling Softnet control socket: {error:#}"),
                Err(error) if error.is_cancelled() => {}
                Err(error) => log::warn!("Softnet control task failed: {error}"),
            }
        }

        self.control = None;
    }

    fn proxy_handle(&self, id: Option<Uuid>) -> Result<&ProxyHandle> {
        let id = id
            .or(self.default_vm_id)
            .context("vmId is required unless initialized with exactly one VM")?;

        self.proxy_handles
            .get(&id)
            .with_context(|| format!("unknown VM {id}"))
    }

    fn reap_task(
        &mut self,
        (id, result): (Uuid, std::result::Result<Result<()>, JoinError>),
    ) -> Result<()> {
        self.proxy_handles.remove(&id);
        let task = format!("Softnet VM {id}");

        result
            .with_context(|| format!("{task} task failed"))?
            .with_context(|| format!("{task} stopped"))
    }
}

impl ProxyHandle {
    async fn run(
        mut proxy: Proxy,
        commands_rx: mpsc::Receiver<Command>,
        start: oneshot::Receiver<()>,
    ) -> Result<()> {
        let result = AssertUnwindSafe(async {
            // Skip forwarding if initialization fails or is canceled
            if start.await.is_err() {
                return Ok(());
            }

            proxy.run(commands_rx).await
        })
        .catch_unwind()
        .await;

        let cleanup_result = tokio::task::spawn_blocking(move || {
            let result = proxy.finalize();
            drop(proxy);

            result
        })
        .await
        .context("VM proxy cleanup task failed")?;

        match result {
            Ok(result) => result.and(cleanup_result),
            Err(panic) => resume_unwind(panic),
        }
    }

    async fn policy_get(&self) -> Result<Policy> {
        let (reply, result) = oneshot::channel();

        self.request(Command::PolicyGet { reply }, result).await
    }

    async fn policy_set(&self, allow: Vec<Rule>, block: Vec<Rule>) -> Result<Policy> {
        let (reply, result) = oneshot::channel();

        self.request(
            Command::PolicySet {
                allow,
                block,
                reply,
            },
            result,
        )
        .await
    }

    async fn request(&self, command: Command, result: oneshot::Receiver<Policy>) -> Result<Policy> {
        self.commands
            .send(command)
            .await
            .context("VM proxy task stopped before accepting command")?;

        result
            .await
            .context("VM proxy task stopped before acknowledging command")
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod tests;
