//! `routelith service install|uninstall|run`: the server as a Windows
//! Service (architecture doc §21.3, packaging).
//!
//! The service runs `routelith service run --config <file> --log <file>`
//! as `NT AUTHORITY\LocalService`, starts with Windows, and is restarted
//! by the service manager 30 s after a failure (the count resets after a
//! day without failures), as the MSI sets it up. The MSI installs the same
//! service through Windows Installer; these commands are for a plain copy
//! of the executable. Both register the `Routelith` event source, whose
//! messages are in routelith.exe, for `type = "eventlog"` outputs.
//!
//! On other systems the commands only explain where the service files are.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

/// The service's key name, as used by `sc` and the MSI.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const NAME: &str = "Routelith";

#[derive(Debug, Subcommand)]
pub(crate) enum ServiceAction {
    /// Register the Windows Service and start it (needs Administrator).
    Install(InstallArgs),
    /// Stop and remove the Windows Service (needs Administrator).
    Uninstall,
    /// Entry point for the service manager; not for interactive use
    /// (run `routelith server` instead).
    #[command(hide = true)]
    Run(RunArgs),
}

#[derive(Debug, Args)]
pub(crate) struct InstallArgs {
    /// Configuration file the service reads (made absolute).
    #[arg(short, long)]
    config: PathBuf,
    /// Log file for the server's messages (default: routelith.log next to
    /// the configuration file).
    #[arg(long)]
    log: Option<PathBuf>,
    /// Register the service without starting it.
    #[arg(long)]
    no_start: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(long)]
    log: PathBuf,
}

pub(crate) fn run(action: ServiceAction) -> ExitCode {
    #[cfg(windows)]
    {
        let r = match action {
            ServiceAction::Install(args) => windows::install(&args),
            ServiceAction::Uninstall => windows::uninstall(),
            ServiceAction::Run(args) => return windows::run(args),
        };
        match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("routelith service: {e}");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        eprintln!(
            "routelith service: Windows only. On Linux, run `routelith server` from the \
             systemd unit in packaging/linux/routelith.service."
        );
        ExitCode::from(2)
    }
}

/// The server's exit code as a number, for the service manager.
#[cfg_attr(not(windows), allow(dead_code))]
fn code_number(code: ExitCode) -> u8 {
    (0..=u8::MAX)
        .find(|n| ExitCode::from(*n) == code)
        .unwrap_or(u8::MAX)
}

#[cfg(windows)]
mod windows {
    use std::ffi::{OsStr, OsString};
    use std::fs::OpenOptions;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};
    use std::time::{Duration, Instant};

    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{InstallArgs, NAME, RunArgs, code_number};
    use crate::server::{self, ServerArgs};

    const ACCOUNT: &str = r"NT AUTHORITY\LocalService";
    /// The LocalService SID, so icacls works on non-English Windows too.
    const ACCOUNT_SID: &str = "*S-1-5-19";
    /// Seconds between stats lines in the log (the console default is 60).
    const STATS_EVERY: u64 = 3600;

    pub(super) fn install(args: &InstallArgs) -> io::Result<()> {
        let config = std::path::absolute(&args.config)?;
        let src = std::fs::read_to_string(&config)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", config.display())))?;
        let parsed = rl_core::config::parse(&src);
        let Some(cfg) = parsed.config else {
            return Err(io::Error::other(format!(
                "{} is invalid; check it with `routelith ctl verify`",
                config.display()
            )));
        };
        let log = match &args.log {
            Some(l) => std::path::absolute(l)?,
            None => config.with_file_name("routelith.log"),
        };
        // The service starts in System32, so a relative data_dir would
        // name a different folder there than the one granted here.
        let data_dir = PathBuf::from(&cfg.server.data_dir);
        if !data_dir.is_absolute() {
            return Err(io::Error::other(format!(
                "server.data_dir in {} must be an absolute path for the service, not {}",
                config.display(),
                data_dir.display()
            )));
        }
        // The service account must be able to run the binary, read the
        // configuration and write its data and log. The binary needs its own
        // grant when it lives in a user profile, such as a cargo target dir.
        let exe = std::env::current_exe()?;
        grant(&exe, "RX")?;
        grant(&config, "RX")?;
        std::fs::create_dir_all(&data_dir)?;
        grant(&data_dir, "(OI)(CI)M")?;
        if let Some(dir) = log.parent() {
            std::fs::create_dir_all(dir)?;
        }
        OpenOptions::new().create(true).append(true).open(&log)?;
        grant(&log, "M")?;

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(to_io)?;
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: "Routelith network monitor".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.clone(),
            launch_arguments: vec![
                "service".into(),
                "run".into(),
                "--config".into(),
                config.into_os_string(),
                "--log".into(),
                log.clone().into_os_string(),
            ],
            dependencies: vec![],
            account_name: Some(ACCOUNT.into()),
            account_password: None,
        };
        let service = manager
            .create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .map_err(to_io)?;
        service
            .set_description("Measures network latency and loss; see http://127.0.0.1:8080/")
            .map_err(to_io)?;
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![restart(30), restart(30), restart(30)]),
            })
            .map_err(to_io)?;
        // A server that stops with an error exit code (not only a crash)
        // also counts as a failure.
        service
            .set_failure_actions_on_non_crash_failures(true)
            .map_err(to_io)?;
        // Before the start, so the server_started event already shows as text.
        rl_sys::eventlog::register_source(rl_out::eventlog::SOURCE, &exe)?;
        println!("Installed service {NAME}; it logs to {}", log.display());
        if !args.no_start {
            service.start::<&OsStr>(&[]).map_err(|e| {
                io::Error::other(format!(
                    "installed, but the service did not start: {}. LocalService must be \
                     able to read {} and every file it uses; a copy outside your user \
                     profile (e.g. C:\\Program Files\\Routelith\\bin) avoids this. Check the \
                     log, then run `sc start {NAME}`",
                    to_io(e),
                    exe.display()
                ))
            })?;
            println!("Started service {NAME}");
        }
        Ok(())
    }

    pub(super) fn uninstall() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(to_io)?;
        let service = manager
            .open_service(
                NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(to_io)?;
        // Mark for deletion first: the service manager removes it as soon
        // as it has stopped and no handles remain.
        service.delete().map_err(to_io)?;
        // Reported after the stop, so a registry error cannot leave the
        // service running.
        let source = rl_sys::eventlog::unregister_source(rl_out::eventlog::SOURCE);
        if service.query_status().map_err(to_io)?.current_state != ServiceState::Stopped {
            service.stop().map_err(to_io)?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while service.query_status().map_err(to_io)?.current_state != ServiceState::Stopped {
                if Instant::now() > deadline {
                    return Err(io::Error::other(
                        "the service did not stop within 30 s; it is removed once it stops",
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        source?;
        println!("Removed service {NAME}");
        Ok(())
    }

    pub(super) fn run(args: RunArgs) -> ExitCode {
        // A service has no console: the server's messages go to the log.
        let log = OpenOptions::new().create(true).append(true).open(&args.log);
        match log.map(rl_sys::service::redirect_stderr) {
            Ok(Ok(())) => {}
            Ok(Err(e)) | Err(e) => {
                eprintln!("routelith service: {}: {e}", args.log.display());
                return ExitCode::from(2);
            }
        }
        let config = args.config;
        let body = Box::new(move |stop: rl_sys::service::StopRequest| {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("routelith service: cannot start async runtime: {e}");
                    return 2;
                }
            };
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            std::thread::spawn(move || {
                stop.wait();
                let _ = tx.send(());
            });
            let server_args = ServerArgs {
                config,
                stats_interval: STATS_EVERY,
            };
            let code = rt.block_on(server::serve(server_args, async {
                let _ = rx.await;
            }));
            rt.shutdown_timeout(Duration::from_millis(100));
            code_number(code)
        });
        match rl_sys::service::run(NAME, body) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!(
                    "routelith service: not started by the service manager ({e}); \
                     run `routelith server` instead"
                );
                ExitCode::from(2)
            }
        }
    }

    /// Give the service account `rights` (icacls notation) on `path`.
    fn grant(path: &Path, rights: &str) -> io::Result<()> {
        let status = Command::new("icacls")
            .arg(path)
            .arg("/grant")
            .arg(OsString::from(format!("{ACCOUNT_SID}:{rights}")))
            .arg("/Q")
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "icacls could not grant {ACCOUNT} access to {} ({status})",
                PathBuf::from(path).display()
            )))
        }
    }

    fn to_io(e: windows_service::Error) -> io::Error {
        match e {
            windows_service::Error::Winapi(io) => io,
            other => io::Error::other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::code_number;
    use std::process::ExitCode;

    #[test]
    fn exit_codes_map_to_numbers() {
        assert_eq!(code_number(ExitCode::SUCCESS), 0);
        assert_eq!(code_number(ExitCode::from(2)), 2);
    }
}
