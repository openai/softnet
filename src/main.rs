use anyhow::{Context, anyhow};
use clap::Parser;
use log::LevelFilter;
use nix::sys::signal::{SigHandler, Signal, signal};
use oslog::OsLogger;
use privdrop::PrivDrop;
use softnet::NetType;
use softnet::proxy::ExposedPort;
use softnet::proxy::Proxy;
use softnet::proxy::Target;
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
        help = "FD number to use for communicating with the VM's networking stack"
    )]
    vm_fd: c_int,

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
        help = "Comma-separated list of CIDRs to allow the traffic to \
        (e.g. --allow=192.168.0.0/24 may be used to allow a LAN access for a VM), \
        plus supported @-aliases. Currently the only supported @-alias is @host, \
        which matches the vmnet bridge gateway IP. \
        When used with --block, the longest prefix match always wins. \
        In case an identical prefix is both --allow'ed and --block'ed, \
        blocking will take precedence. --allow=0.0.0.0/0 is a special case, \
        it additionally disables bridge isolation (even when --block=0.0.0.0/0 is specified).",
        value_name = "comma-separated CIDRs, MAC addresses or @-aliases",
        use_value_delimiter = true,
        action = clap::ArgAction::Set
    )]
    allow: Vec<Target>,

    #[clap(
        long,
        help = "Comma-separated list of CIDRs to block the traffic to \
        (e.g. --block=0.0.0.0/0 may be used to establish a default deny policy \
        that is further relaxed with --allow), plus supported @-aliases. \
        Currently the only supported @-alias is @host, which matches the vmnet bridge gateway IP. \
        When used with --allow, the longest prefix match always wins. \
        In case an identical prefix is both --allow'ed and --block'ed, \
        blocking will take precedence.",
        value_name = "comma-separated CIDRs, MAC addresses or @-aliases",
        use_value_delimiter = true,
        action = clap::ArgAction::Set
    )]
    block: Vec<Target>,

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
