//! The Windows Event Log (doc §11.3, F8): write events under an event
//! source, and register or remove that source in the registry.
//!
//! A source is registered under
//! `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<name>`
//! with `EventMessageFile` pointing at the program whose message table
//! turns an event ID and its strings into readable text. Writing works
//! without registration too; Event Viewer then shows the strings with a
//! note that the description was not found.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HANDLE};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    RegisterEventSourceW, ReportEventW,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW,
};

/// How Event Viewer marks an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Information,
    Warning,
    Error,
}

/// An open event source; events written through it go to the log the
/// source is registered for (Application when it is not registered).
#[derive(Debug)]
pub struct EventSource(HANDLE);

// SAFETY: an event log handle is not tied to the thread that opened it;
// ReportEvent may be called with it from any thread.
unsafe impl Send for EventSource {}

impl EventSource {
    /// Open source `name` on this computer.
    pub fn open(name: &str) -> io::Result<Self> {
        let name = wide(OsStr::new(name));
        // SAFETY: `name` is NUL-terminated and outlives the call; a null
        // server name means the local computer.
        let h = unsafe { RegisterEventSourceW(ptr::null(), name.as_ptr()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }

    /// Write one event. `strings` are its insertion strings: `%1` is the
    /// first. Each is cut to 31,839 characters, the most one may hold.
    pub fn report(&self, level: Level, id: u32, strings: &[&str]) -> io::Result<()> {
        const MAX_CHARS: usize = 31_839;
        let wides: Vec<Vec<u16>> = strings
            .iter()
            .map(|s| {
                let mut w: Vec<u16> = s.encode_utf16().take(MAX_CHARS).collect();
                w.push(0);
                w
            })
            .collect();
        let ptrs: Vec<*const u16> = wides.iter().map(|w| w.as_ptr()).collect();
        let count = u16::try_from(ptrs.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many strings"))?;
        let ty = match level {
            Level::Information => EVENTLOG_INFORMATION_TYPE,
            Level::Warning => EVENTLOG_WARNING_TYPE,
            Level::Error => EVENTLOG_ERROR_TYPE,
        };
        // SAFETY: the handle is open (closed only in Drop); `ptrs` holds
        // `count` pointers to NUL-terminated strings in `wides`, which
        // outlive the call; no user SID and no binary data.
        let ok = unsafe {
            ReportEventW(
                self.0,
                ty,
                0,
                id,
                ptr::null_mut(),
                count,
                0,
                ptrs.as_ptr(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for EventSource {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegisterEventSourceW and is
        // deregistered once.
        unsafe { DeregisterEventSource(self.0) };
    }
}

fn key_path(name: &str) -> Vec<u16> {
    wide(OsStr::new(&format!(
        r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{name}"
    )))
}

/// Register source `name` in the Application log, with its messages in
/// `message_file` (a program or DLL with a message table). Needs
/// administrator rights. Registering again updates the path.
pub fn register_source(name: &str, message_file: &Path) -> io::Result<()> {
    let path = key_path(name);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; `key` receives the opened key,
    // which is closed below; no class, no security attributes, and the
    // disposition is not wanted.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    check(rc)?;
    let file = wide(message_file.as_os_str());
    let types: u32 = 7; // error, warning and information
    let result = set_value(key, "EventMessageFile", REG_EXPAND_SZ, &as_bytes(&file))
        .and_then(|()| set_value(key, "TypesSupported", REG_DWORD, &types.to_le_bytes()));
    // SAFETY: `key` was opened above and is closed once.
    unsafe { RegCloseKey(key) };
    result
}

/// Remove source `name`; nothing to do when it is not registered.
pub fn unregister_source(name: &str) -> io::Result<()> {
    let path = key_path(name);
    // SAFETY: `path` is NUL-terminated and outlives the call.
    let rc = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, path.as_ptr()) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(rc)
}

fn set_value(key: HKEY, name: &str, ty: u32, data: &[u8]) -> io::Result<()> {
    let name = wide(OsStr::new(name));
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "value too long"))?;
    // SAFETY: `key` is open with KEY_WRITE; `name` is NUL-terminated and
    // `data` holds `len` bytes, both outliving the call.
    check(unsafe { RegSetValueExW(key, name.as_ptr(), 0, ty, data.as_ptr(), len) })
}

fn check(rc: u32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        // Registry functions return the error code instead of setting it.
        Err(io::Error::from_raw_os_error(rc as i32))
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// A REG_EXPAND_SZ value: the string's UTF-16 bytes, NUL included.
fn as_bytes(w: &[u16]) -> Vec<u8> {
    w.iter().flat_map(|c| c.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unregistered_source_still_writes() {
        let src = EventSource::open("Routelith-rl-sys-test").unwrap();
        src.report(Level::Information, 3000, &["rl-sys test event", "second"])
            .unwrap();
    }
}
