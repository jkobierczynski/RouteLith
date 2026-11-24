//! Login and roles for the UI and API (doc §21.5 F11).
//!
//! With no users, the server works as before: everything readable, nothing
//! to log in to. Once the users file names a user, every API call needs a
//! caller: a session from `POST /api/v1/login` (a cookie, plus a CSRF
//! token for anything that is not a read), HTTP Basic credentials for
//! scripts and Prometheus, or, when `anonymous = true`, nobody at all with
//! the viewer role. The page itself and `/healthz` stay open, so the login
//! form can load and a load balancer can probe.
//!
//! Failed logins are counted per client address and per user name; past
//! [`MAX_FAILURES`] in [`FAILURE_WINDOW`] further tries are refused
//! without checking the password.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

use crate::users::{Role, Users, dummy_hash, verify_password};
use crate::{AppState, error};

/// The session cookie's name.
pub const COOKIE: &str = "rl_session";
/// The header that carries a session's CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";
/// A session ends after this long without a request...
pub const SESSION_IDLE: Duration = Duration::from_secs(8 * 3600);
/// ...and after this long in any case.
pub const SESSION_MAX: Duration = Duration::from_secs(24 * 3600);
/// Failed logins allowed per client address, and per user name, in
/// [`FAILURE_WINDOW`].
pub const MAX_FAILURES: usize = 10;
pub const FAILURE_WINDOW: Duration = Duration::from_secs(300);
/// Sessions kept at most; the least recently used goes first.
const MAX_SESSIONS: usize = 1000;
/// How long checked Basic credentials are remembered, so a scraper does
/// not pay for Argon2 on every request.
const BASIC_CACHE: Duration = Duration::from_secs(300);
const MAX_BASIC_CACHE: usize = 256;
/// How often the users file is looked at for changes.
const USERS_RECHECK: Duration = Duration::from_secs(1);

/// How the server decides who is calling.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub users_file: PathBuf,
    /// Callers with no login read as viewers, once users exist.
    pub anonymous: bool,
    /// The UI is served over TLS: cookies are marked `Secure`.
    pub secure: bool,
}

/// Who made a request, as handlers find it in the request's extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// `None` without a login (no users, or anonymous access).
    pub name: Option<String>,
    pub role: Role,
}

struct Session {
    name: String,
    csrf: String,
    created: Instant,
    seen: Instant,
}

struct Loaded {
    users: Arc<Users>,
    /// Modification time and length when read.
    stamp: Option<(SystemTime, u64)>,
    checked: Instant,
    /// The last load error, so it is logged once.
    error: Option<String>,
}

/// Users, sessions and failed-login counts.
pub struct Auth {
    cfg: AuthConfig,
    loaded: Mutex<Loaded>,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<FailureKey, Vec<Instant>>>,
    /// SHA-256 of `name:password` → name, for Basic credentials.
    basic: Mutex<HashMap<[u8; 32], (String, Instant)>>,
    rng: SystemRandom,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FailureKey {
    Addr(IpAddr),
    Name(String),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("users_file", &self.cfg.users_file)
            .field("anonymous", &self.cfg.anonymous)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn stamp(path: &std::path::Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

impl Auth {
    /// Read the users file now; an unreadable or invalid one is an error,
    /// so the server does not start with a login it cannot check.
    pub fn new(cfg: AuthConfig) -> Result<Auth, String> {
        let stamp = stamp(&cfg.users_file);
        let users = Users::load(&cfg.users_file)?;
        Ok(Auth {
            loaded: Mutex::new(Loaded {
                users: Arc::new(users),
                stamp,
                checked: Instant::now(),
                error: None,
            }),
            cfg,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            basic: Mutex::new(HashMap::new()),
            rng: SystemRandom::new(),
        })
    }

    /// No users and no file: everything open, as before logins existed.
    pub fn open() -> Auth {
        Auth {
            cfg: AuthConfig {
                users_file: PathBuf::new(),
                anonymous: true,
                secure: false,
            },
            loaded: Mutex::new(Loaded {
                users: Arc::new(Users::default()),
                stamp: None,
                checked: Instant::now(),
                error: None,
            }),
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            basic: Mutex::new(HashMap::new()),
            rng: SystemRandom::new(),
        }
    }

    pub fn config(&self) -> &AuthConfig {
        &self.cfg
    }

    /// The users, read again when the file changed. A file that turns
    /// invalid keeps the last good list, and says so once.
    pub fn users(&self) -> Arc<Users> {
        let mut l = lock(&self.loaded);
        if self.cfg.users_file.as_os_str().is_empty() || l.checked.elapsed() < USERS_RECHECK {
            return l.users.clone();
        }
        l.checked = Instant::now();
        let now = stamp(&self.cfg.users_file);
        if now == l.stamp {
            return l.users.clone();
        }
        match Users::load(&self.cfg.users_file) {
            Ok(u) => {
                eprintln!(
                    "routelith server: users file {} read again: {} user{}",
                    self.cfg.users_file.display(),
                    u.users.len(),
                    if u.users.len() == 1 { "" } else { "s" }
                );
                l.users = Arc::new(u);
                l.stamp = now;
                l.error = None;
                // Cached Basic credentials may name a changed password.
                lock(&self.basic).clear();
            }
            Err(e) => {
                if l.error.as_deref() != Some(e.as_str()) {
                    eprintln!("routelith server: {e}; keeping the users read before");
                    l.error = Some(e);
                }
                l.stamp = now;
            }
        }
        l.users.clone()
    }

    /// Whether a caller must log in to read.
    pub fn login_required(&self) -> bool {
        !self.cfg.anonymous && !self.users().is_empty()
    }

    fn token(&self) -> String {
        let mut b = [0u8; 32];
        // SystemRandom fails only when the OS has no randomness at all.
        self.rng.fill(&mut b).expect("system randomness");
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn failed_recently(&self, key: &FailureKey) -> bool {
        let mut f = lock(&self.failures);
        let Some(v) = f.get_mut(key) else {
            return false;
        };
        v.retain(|t| t.elapsed() < FAILURE_WINDOW);
        v.len() >= MAX_FAILURES
    }

    fn count_failure(&self, keys: &[FailureKey]) {
        let mut f = lock(&self.failures);
        // Forget old entries now and then, so the map cannot grow forever.
        if f.len() > 10_000 {
            f.retain(|_, v| {
                v.retain(|t| t.elapsed() < FAILURE_WINDOW);
                !v.is_empty()
            });
        }
        for k in keys {
            f.entry(k.clone()).or_default().push(Instant::now());
        }
    }

    fn clear_failures(&self, name: &str) {
        lock(&self.failures).remove(&FailureKey::Name(name.to_string()));
    }

    /// Check a name and password, counting a failure.
    async fn check_password(
        self: &Arc<Self>,
        addr: IpAddr,
        name: &str,
        password: &str,
    ) -> Result<Role, Refused> {
        let keys = [FailureKey::Addr(addr), FailureKey::Name(name.to_string())];
        if keys.iter().any(|k| self.failed_recently(k)) {
            return Err(Refused::Throttled);
        }
        let user = self.users().get(name).cloned();
        let (hash, role) = match &user {
            Some(u) => (u.password.clone(), Some(u.role)),
            None => (dummy_hash().to_string(), None),
        };
        let password = password.to_string();
        // Argon2 takes tens of milliseconds: off the async threads.
        let ok = tokio::task::spawn_blocking(move || verify_password(&hash, &password))
            .await
            .unwrap_or(false);
        match (ok, role) {
            (true, Some(role)) => {
                self.clear_failures(name);
                Ok(role)
            }
            _ => {
                self.count_failure(&keys);
                Err(Refused::Wrong)
            }
        }
    }

    fn new_session(&self, name: &str) -> (String, String) {
        let (token, csrf) = (self.token(), self.token());
        let mut s = lock(&self.sessions);
        s.retain(|_, v| v.seen.elapsed() < SESSION_IDLE && v.created.elapsed() < SESSION_MAX);
        if s.len() >= MAX_SESSIONS {
            if let Some(oldest) = s.iter().min_by_key(|(_, v)| v.seen).map(|(k, _)| k.clone()) {
                s.remove(&oldest);
            }
        }
        let now = Instant::now();
        s.insert(
            token.clone(),
            Session {
                name: name.to_string(),
                csrf: csrf.clone(),
                created: now,
                seen: now,
            },
        );
        (token, csrf)
    }

    /// The session behind `token`, still valid and of a user who still
    /// exists: (name, role, csrf).
    fn session(&self, token: &str) -> Option<(String, Role, String)> {
        let (name, csrf) = {
            let mut s = lock(&self.sessions);
            let v = s.get_mut(token)?;
            if v.seen.elapsed() >= SESSION_IDLE || v.created.elapsed() >= SESSION_MAX {
                s.remove(token);
                return None;
            }
            v.seen = Instant::now();
            (v.name.clone(), v.csrf.clone())
        };
        match self.users().get(&name) {
            Some(u) => Some((name, u.role, csrf)),
            None => {
                // Removed from the file: the session goes with it.
                lock(&self.sessions).remove(token);
                None
            }
        }
    }

    fn end_session(&self, token: &str) {
        lock(&self.sessions).remove(token);
    }

    async fn check_basic(
        self: &Arc<Self>,
        addr: IpAddr,
        name: &str,
        password: &str,
    ) -> Result<Role, Refused> {
        let key: [u8; 32] = digest(&SHA256, format!("{name}:{password}").as_bytes())
            .as_ref()
            .try_into()
            .unwrap_or([0; 32]);
        let cached = lock(&self.basic)
            .get(&key)
            .filter(|(_, t)| t.elapsed() < BASIC_CACHE)
            .map(|(n, _)| n.clone());
        if let Some(n) = cached {
            if let Some(u) = self.users().get(&n) {
                return Ok(u.role);
            }
        }
        let role = self.check_password(addr, name, password).await?;
        let mut b = lock(&self.basic);
        if b.len() >= MAX_BASIC_CACHE {
            b.clear();
        }
        b.insert(key, (name.to_string(), Instant::now()));
        Ok(role)
    }

    fn cookie(&self, value: &str, max_age: u64) -> HeaderValue {
        let secure = if self.cfg.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
        ))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
    }
}

/// Why a name and password were not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    Wrong,
    /// Too many failures lately; not checked.
    Throttled,
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        match self {
            Refused::Wrong => error(StatusCode::UNAUTHORIZED, "wrong user name or password"),
            Refused::Throttled => {
                let mut r = error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many failed logins; try again in a few minutes",
                );
                r.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from(FAILURE_WINDOW.as_secs()),
                );
                r
            }
        }
    }
}

/// The session token from the request's cookies.
fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

/// Name and password from `Authorization: Basic`.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, b64) = v.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = String::from_utf8(base64_decode(b64.trim())?).ok()?;
    let (n, p) = raw.split_once(':')?;
    Some((n.to_string(), p.to_string()))
}

/// Standard base64 with padding, as Basic credentials use.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.as_bytes();
    if s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (i, chunk) in s.chunks(4).enumerate() {
        let last = i == s.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// Equal without telling, through timing, where they first differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// A request that could change something comes from this site: its
/// `Origin`, when sent, names the host it was sent to.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin
        .split_once("://")
        .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(host))
}

fn peer(req: &Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip())
}

fn is_read(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Middleware for everything but the page, its files and `/healthz`:
/// find the caller, refuse when there is none, and check the CSRF token
/// of a session's writes.
pub(crate) async fn guard(
    State(s): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth = &s.auth;
    let users = auth.users();
    let caller = if users.is_empty() {
        // No users: open, as before logins existed.
        Some(Caller {
            name: None,
            role: Role::Viewer,
        })
    } else if let Some(token) = session_token(req.headers()) {
        match auth.session(&token) {
            Some((name, role, csrf)) => {
                if !is_read(req.method()) {
                    let sent = req
                        .headers()
                        .get(CSRF_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if !same(sent, &csrf) || !same_origin(req.headers()) {
                        return error(StatusCode::FORBIDDEN, "missing or wrong CSRF token");
                    }
                }
                Some(Caller {
                    name: Some(name),
                    role,
                })
            }
            None => None,
        }
    } else if let Some((name, password)) = basic_credentials(req.headers()) {
        match auth.check_basic(peer(&req), &name, &password).await {
            Ok(role) => Some(Caller {
                name: Some(name),
                role,
            }),
            Err(r) => return r.into_response(),
        }
    } else {
        None
    };
    let caller = match caller {
        Some(c) => c,
        None if auth.cfg.anonymous => Caller {
            name: None,
            role: Role::Viewer,
        },
        None => return error(StatusCode::UNAUTHORIZED, "login required"),
    };
    req.extensions_mut().insert(caller);
    next.run(req).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginBody {
    name: String,
    password: String,
}

fn session_json(
    name: Option<&str>,
    role: Option<Role>,
    csrf: Option<&str>,
    required: bool,
) -> Response {
    Json(serde_json::json!({
        "user": name,
        "role": role.map(Role::as_str),
        "csrf": csrf,
        "login_required": required,
        "users": true,
    }))
    .into_response()
}

/// `GET /api/v1/session`: who the browser is logged in as, and whether a
/// login is needed. Always open.
pub(crate) async fn session(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = &s.auth;
    let users = auth.users();
    if users.is_empty() {
        return Json(serde_json::json!({
            "user": null,
            "role": "viewer",
            "csrf": null,
            "login_required": false,
            "users": false,
        }))
        .into_response();
    }
    match session_token(&headers).and_then(|t| auth.session(&t)) {
        Some((name, role, csrf)) => {
            session_json(Some(&name), Some(role), Some(&csrf), auth.login_required())
        }
        None => session_json(
            None,
            auth.cfg.anonymous.then_some(Role::Viewer),
            None,
            auth.login_required(),
        ),
    }
}

/// `POST /api/v1/login` with `{"name", "password"}`: a session cookie and
/// the CSRF token for it.
pub(crate) async fn login(State(s): State<Arc<AppState>>, req: Request) -> Response {
    let auth = s.auth.clone();
    if !same_origin(req.headers()) {
        return error(StatusCode::FORBIDDEN, "login from another site");
    }
    let addr = peer(&req);
    let body = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
    };
    let Ok(b) = serde_json::from_slice::<LoginBody>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "expected JSON with \"name\" and \"password\"",
        );
    };
    if auth.users().is_empty() {
        return error(StatusCode::NOT_FOUND, "there are no users to log in as");
    }
    let role = match auth.check_password(addr, &b.name, &b.password).await {
        Ok(r) => r,
        Err(r) => return r.into_response(),
    };
    let (token, csrf) = auth.new_session(&b.name);
    let mut resp = session_json(
        Some(&b.name),
        Some(role),
        Some(&csrf),
        auth.login_required(),
    );
    resp.headers_mut().insert(
        header::SET_COOKIE,
        auth.cookie(&token, SESSION_MAX.as_secs()),
    );
    resp
}

/// `POST /api/v1/logout`: end the session. Behind [`guard`], so it needs
/// the CSRF token.
pub(crate) async fn logout(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(t) = session_token(&headers) {
        s.auth.end_session(&t);
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, s.auth.cookie("", 0));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_basic_credentials() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("YQ=").is_none());
        assert!(base64_decode("YQ==YQ==").is_none());
        assert!(base64_decode("Y!==").is_none());
    }

    #[test]
    fn origins_must_match_the_host() {
        let mut h = HeaderMap::new();
        assert!(same_origin(&h));
        h.insert(header::HOST, HeaderValue::from_static("mon.lan:8080"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://mon.lan:8080"),
        );
        assert!(same_origin(&h));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!same_origin(&h));
        h.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(!same_origin(&h));
    }

    #[test]
    fn cookies_are_found_among_others() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; rl_session=abc; b=2"),
        );
        assert_eq!(session_token(&h).as_deref(), Some("abc"));
    }
}
