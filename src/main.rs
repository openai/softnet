use anyhow::{Context, anyhow};
use clap::Parser;
use log::LevelFilter;
use nix::sys::signal::{SigHandler, Signal, signal};
use oslog::OsLogger;
use privdrop::PrivDrop;
use softnet::NetType;
use softnet::proxy::ExposedPort;
use softnet::proxy::Proxy;
use softnet::proxy::Rule;
use std::borrow::Cow;
use std::env;
use std::os::raw::c_int;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};
use system_configuration::core_foundation::base::TCFType;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::string::CFString;
use system_configuration::preferences::SCPreferences;
use system_configuration::sys::preferences::{SCPreferencesCommitChanges, SCPreferencesSetValue};
use uzers::{get_current_groupname, get_current_username, get_effective_uid};

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        long,
        value_parser = parse_vm_fd,
        help = "FD number to use for communicating with the VM's networking stack"
    )]
    vm_fd: c_int,

    #[clap(
        long,
        value_parser = parse_vm_fd,
        help = "connected Unix stream FD for newline-delimited JSON-RPC policy control"
    )]
    control_fd: Option<c_int>,

    #[clap(long, help = "MAC address to enforce for the VM")]
    vm_mac_address: mac_address::MacAddress,

    #[clap(long, value_enum, help = "type of network to use for the VM", default_value_t=NetType::Nat)]
    vm_net_type: NetType,

    #[clap(
        long,
        help = "set bootpd(8) lease time to this value (in seconds) before starting the VM",
        default_value_t = 600
    )]
    bootpd_lease_time: u32,

    #[clap(long, help = "user name to drop privileges to")]
    user: Option<String>,

    #[clap(long, help = "group name to drop privileges to")]
    group: Option<String>,

    #[clap(
        long,
        value_parser = parse_supported_rule,
        help = "Comma-separated list of rules for allowing traffic.\n\n\
        Rule forms:\n\n\
        * TARGET: stateless rule\n\
        * in|out from TARGET: stateful flows initiated from TARGET (not supported yet)\n\
        * in|out to TARGET: stateful flows initiated toward TARGET (not supported yet)\n\n\
        Stateful rules specify the initiating packet's direction: in enters the VM; out leaves it.\n\n\
        Targets are:\n\n\
        * IPv4 CIDRs\n\
        * @host, which matches the vmnet bridge gateway IP\n\n\
        When used with --block, the longest prefix match wins. If an identical prefix is both \
        allowed and blocked, blocking takes precedence.\n\n\
        --allow=0.0.0.0/0 additionally disables bridge isolation, even when \
        --block=0.0.0.0/0 is specified.\n\n\
        Examples:\n\n\
        * --allow=192.168.0.0/24 — allow stateless traffic with this LAN\n\
        * --allow=\"in from @host\" — allow stateful flows initiated from @host\n\
        * --allow=\"out to 192.168.0.0/24\" — allow stateful flows initiated toward this LAN\n\
        * --allow=\"in from @host,out to 192.168.0.0/24\" — multiple rules may be comma-separated",
        value_name = "comma-separated rules",
        use_value_delimiter = true,
        action = clap::ArgAction::Set
    )]
    allow: Vec<Rule>,

    #[clap(
        long,
        value_parser = parse_supported_rule,
        help = "Comma-separated list of rules for blocking traffic.\n\n\
        Rule forms:\n\n\
        * TARGET: stateless rule\n\
        * in|out from TARGET: stateful flows initiated from TARGET (not supported yet)\n\
        * in|out to TARGET: stateful flows initiated toward TARGET (not supported yet)\n\n\
        Stateful rules specify the initiating packet's direction: in enters the VM; out leaves it.\n\n\
        Targets are:\n\n\
        * IPv4 CIDRs\n\
        * @host, which matches the vmnet bridge gateway IP\n\n\
        When used with --allow, the longest prefix match wins. If an identical prefix is both \
        allowed and blocked, blocking takes precedence.\n\n\
        Examples:\n\n\
        * --block=0.0.0.0/0 — establish a stateless default-deny policy\n\
        * --block=\"in from @host\" — block stateful flows initiated from @host\n\
        * --block=\"out to 66.66.66.0/24\" — block stateful flows initiated toward this CIDR\n\
        * --block=\"in from @host,out to 66.66.66.0/24\" — multiple rules may be comma-separated",
        value_name = "comma-separated rules",
        use_value_delimiter = true,
        action = clap::ArgAction::Set
    )]
    block: Vec<Rule>,

    #[clap(
        long,
        help = "comma-separated list of TCP ports to expose (e.g. --expose 2222:22,8080:80)",
        value_name = "comma-separated port specifications",
        use_value_delimiter = true,
        action = clap::ArgAction::Set
    )]
    expose: Vec<ExposedPort>,

    #[clap(long, hide = true)]
    sudo_escalation_probing: bool,

    #[clap(long, hide = true)]
    sudo_escalation_done: bool,
}

fn main() -> ExitCode {
    // Enable backtraces by default
    if env::var("RUST_BACKTRACE").is_err() {
        unsafe {
            env::set_var("RUST_BACKTRACE", "full");
        }
    }

    // Initialize Sentry
    let _sentry = sentry::init(sentry::ClientOptions {
        release: option_env!("CIRRUS_TAG").map(|tag| Cow::from(format!("softnet@{tag}"))),
        ..Default::default()
    });

    // Enrich future events with Cirrus CI-specific tags
    if let Ok(tags) = env::var("CIRRUS_SENTRY_TAGS") {
        sentry::configure_scope(|scope| {
            for (key, value) in tags.split(',').filter_map(|tag| tag.split_once('=')) {
                scope.set_tag(key, value);
            }
        });
    }

    match try_main() {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            // Print the error into stderr
            let causes: Vec<String> = err.chain().map(|x| x.to_string()).collect();
            eprintln!("{}", causes.join(": "));

            // Capture the error into Sentry
            sentry_anyhow::capture_anyhow(&err);

            ExitCode::FAILURE
        }
    }
}

fn try_main() -> anyhow::Result<()> {
    // Initialize logger
    OsLogger::new("org.cirruslabs.softnet")
        .level_filter(LevelFilter::Info)
        .init()?;

    // The default signal(3)[1] action for SIGINT is to interrupt program,
    // but we want to handle SIGINT ourselves, so we ignore it. The kqueue(2)'s[2]
    // EVFILT_SIGNAL will receive it anyways, because it has lower precedence.
    //
    // [1]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/signal.3.html
    // [2]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html
    unsafe { signal(Signal::SIGINT, SigHandler::SigIgn) }?;

    let args: Args = Args::parse();

    // No need to run anything, just return
    // so that the invoker process knows we
    // can be invoked in Sudo as root
    if args.sudo_escalation_probing {
        return Ok(());
    }

    // Retrieve real (not effective) user and group names
    let current_user_name = get_current_username()
        .ok_or(anyhow!("failed to resolve real user name"))?
        .to_string_lossy()
        .to_string();
    let current_group_name = get_current_groupname()
        .ok_or(anyhow!("failed to resolve real group name"))?
        .to_string_lossy()
        .to_string();

    // Ensure we are running as root
    if get_effective_uid() != 0 {
        if sudo_escalation_works() && !args.sudo_escalation_done {
            let exe = std::env::current_exe().unwrap();
            let args = std::env::args().skip(1);

            let _ = Command::new("sudo")
                .arg("--non-interactive")
                .arg("--preserve-env=SENTRY_DSN,CIRRUS_SENTRY_TAGS")
                .arg(&exe)
                .args(args)
                .arg("--sudo-escalation-done")
                .arg("--user")
                .arg(current_user_name)
                .arg("--group")
                .arg(current_group_name)
                .exec();
        }

        return Err(anyhow!(
            "root privileges are required to run and passwordless sudo was not available"
        ));
    }

    // Set bootpd(8) min/max lease time while still having the root privileges
    set_bootpd_lease_time(args.bootpd_lease_time);

    // Initialize the proxy while still having the root privileges
    let mut proxy = Proxy::new(
        args.vm_fd as RawFd,
        args.vm_mac_address,
        args.vm_net_type,
        args.allow,
        args.block,
        args.expose,
        args.control_fd.map(|fd| fd as RawFd),
    )
    .context("failed to initialize proxy")?;

    // Drop effective privileges to the user
    // and group which have had invoked us
    PrivDrop::default()
        .user(args.user.unwrap_or(current_user_name))
        .group(args.group.unwrap_or(current_group_name))
        .apply()
        .context("failed to drop privileges")?;

    // Run proxy
    proxy.run()
}

fn parse_vm_fd(value: &str) -> Result<c_int, String> {
    let vm_fd = value
        .parse::<c_int>()
        .map_err(|err| format!("invalid file descriptor: {err}"))?;

    if vm_fd < 0 {
        return Err("file descriptor must be non-negative".to_string());
    }

    Ok(vm_fd)
}

fn parse_supported_rule(value: &str) -> Result<Rule, String> {
    let rule = value.parse::<Rule>().map_err(|error| error.to_string())?;

    match rule {
        Rule::Stateless(_) => Ok(rule),
        Rule::Stateful { .. } => Err("stateful rules are not supported yet".to_string()),
    }
}

fn sudo_escalation_works() -> bool {
    let exe = std::env::current_exe().unwrap();
    let args = std::env::args().skip(1);

    Command::new("sudo")
        .arg("-n")
        .arg(&exe)
        .args(args)
        .arg("--sudo-escalation-probing")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn set_bootpd_lease_time(lease_time: u32) {
    let prefs = SCPreferences::group(
        &CFString::new("softnet"),
        &CFString::new("com.apple.InternetSharing.default.plist"),
    );

    let bootpd_dict = CFDictionary::from_CFType_pairs(&[(
        CFString::new("DHCPLeaseTimeSecs"),
        CFNumber::from(lease_time as i32),
    )]);

    unsafe {
        SCPreferencesSetValue(
            prefs.as_concrete_TypeRef(),
            CFString::new("bootpd").as_concrete_TypeRef(),
            bootpd_dict.as_concrete_TypeRef().cast(),
        );

        SCPreferencesCommitChanges(prefs.as_concrete_TypeRef());
    }
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn test_cli_rejects_negative_vm_fd_before_startup() {
        let error = Args::try_parse_from([
            "softnet",
            "--vm-fd=-1",
            "--vm-mac-address=02:00:00:00:00:01",
        ])
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("file descriptor must be non-negative")
        );
    }

    #[test]
    fn test_cli_rejects_negative_control_fd_before_startup() {
        let error = Args::try_parse_from([
            "softnet",
            "--vm-fd=0",
            "--control-fd=-1",
            "--vm-mac-address=02:00:00:00:00:01",
        ])
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("file descriptor must be non-negative")
        );
    }
}
