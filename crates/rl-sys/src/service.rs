//! Windows Service glue: run a body under the service control manager, and
//! send standard error to a log file (a service has no console).
//!
//! Installing and removing the service needs no unsafe code and lives in
//! the binary; this module holds what the `windows-service` dispatch macro
//! and `SetStdHandle` need.

use std::fs::File;
use std::io;
use std::os::windows::io::IntoRawHandle;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// Completes when the service manager asks the service to stop (Stop or
/// system shutdown).
#[derive(Debug)]
pub struct StopRequest(mpsc::Receiver<()>);

impl StopRequest {
    /// Block until a stop is requested (or the handler is gone).
    pub fn wait(self) {
        let _ = self.0.recv();
    }
}

/// The service's work: runs until the stop request, returns its exit code
/// (0 for success; anything else is reported as a service-specific code).
pub type Body = Box<dyn FnOnce(StopRequest) -> u8 + Send>;

struct Pending {
    name: String,
    body: Body,
}

/// What `service_main` runs; set once by [`run`] before dispatching.
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Connect to the service control manager as service `name` and run
/// `body`. Blocks until the service has stopped. Fails at once when the
/// process was not started by the service control manager.
pub fn run(name: &str, body: Body) -> io::Result<()> {
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending {
        name: name.to_owned(),
        body,
    });
    service_dispatcher::start(name, ffi_service_main).map_err(to_io)
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    let Some(Pending { name, body }) = PENDING.lock().unwrap_or_else(|e| e.into_inner()).take()
    else {
        return;
    };
    let (stop_tx, stop_rx) = mpsc::channel();
    let stop_tx = Mutex::new(Some(stop_tx));
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Dropping the sender wakes the waiter too; send first so
            // the order does not matter.
            if let Some(tx) = stop_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(&name, handler) else {
        return;
    };
    let report = |state, accept, exit_code, wait_hint| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        });
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
        Duration::ZERO,
    );
    let code = body(StopRequest(stop_rx));
    let exit_code = if code == 0 {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(u32::from(code))
    };
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::ZERO,
    );
}

/// Make `file` the process's standard error, so `eprintln!` output from a
/// service (which has no console) lands in a log. The handle stays open
/// for the life of the process.
pub fn redirect_stderr(file: File) -> io::Result<()> {
    let handle = file.into_raw_handle();
    // SAFETY: `handle` is a valid, open file handle that we own and never
    // close, so it stays valid for every later write to standard error.
    let ok = unsafe {
        windows_sys::Win32::System::Console::SetStdHandle(
            windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
            handle,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn to_io(e: windows_service::Error) -> io::Error {
    match e {
        windows_service::Error::Winapi(io) => io,
        other => io::Error::other(other.to_string()),
    }
}
