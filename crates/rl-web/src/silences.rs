//! Silences: the configured ones, plus one-off windows that operators add
//! and end from the UI or the API (doc §21.5 F11, §21.6 "a viewer cannot
//! create a silence"). Added ones are kept in `silences.json` in the data
//! directory, with who added them and why, so they survive a restart and
//! leave a record; they are pruned a week after they end.
//!
//! The alert engine and the HTTP side share one [`Silences`]. A silence
//! covers alerts raised while it is in force; one added for an alert that
//! is raised already covers that alert's next raise, not its clear.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rl_core::silence::{Silence, When, civil_from_days, format_time, parse_time};
use serde::{Deserialize, Serialize};

use crate::api::now_ms;
use crate::auth::Caller;
use crate::users::Role;
use crate::{AppState, error};

/// The file in the data directory.
pub const FILE: &str = "silences.json";
/// Added silences are dropped this long after they end.
pub const KEEP_ENDED_MS: i64 = 7 * 86_400_000;
/// The longest window that can be added.
pub const MAX_WINDOW_MS: i64 = 90 * 86_400_000;

/// A silence added at run time, with its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    pub silence: Silence,
    /// Who added it; `None` when the server has no users.
    pub by: Option<String>,
    pub comment: String,
    pub created_ms: i64,
    /// Who ended it early, if anyone.
    pub ended_by: Option<String>,
}

/// The file's form of an added silence.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    name: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    alerts: Vec<String>,
    start: String,
    end: String,
    #[serde(default)]
    by: Option<String>,
    #[serde(default)]
    comment: String,
    created: String,
    #[serde(default)]
    ended_by: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFile {
    silences: Vec<Stored>,
}

/// Configured and added silences.
#[derive(Debug)]
pub struct Silences {
    configured: Vec<Silence>,
    added: Mutex<Vec<Added>>,
    /// `None`: kept in memory only (tests).
    path: Option<PathBuf>,
}

impl Default for Silences {
    fn default() -> Self {
        Silences::configured(Vec::new())
    }
}

/// `2026-12-01T22:00:00.000Z`, which [`parse_time`] reads back exactly.
pub(crate) fn stamp(ms: i64) -> String {
    const DAY: i64 = 86_400_000;
    let (y, m, d) = civil_from_days(ms.div_euclid(DAY));
    let t = ms.rem_euclid(DAY);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        t / 3_600_000,
        t / 60_000 % 60,
        t / 1000 % 60,
        t % 1000
    )
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A silence name: as in the configuration, letters, digits, '.', '_'
/// and '-', starting with a letter or digit, at most 64.
pub fn valid_name(s: &str) -> bool {
    let mut c = s.chars();
    s.len() <= 64
        && c.next().is_some_and(|x| x.is_ascii_alphanumeric())
        && c.all(|x| x.is_ascii_alphanumeric() || matches!(x, '.' | '_' | '-'))
}

impl Silences {
    /// Only the configured silences, in memory.
    pub fn configured(configured: Vec<Silence>) -> Silences {
        Silences {
            configured,
            added: Mutex::new(Vec::new()),
            path: None,
        }
    }

    /// The configured silences and those added before, read from
    /// `data_dir`. A file that cannot be read is an error, so start-up
    /// does not quietly forget a silence someone relies on.
    pub fn load(
        configured: Vec<Silence>,
        data_dir: &Path,
        now_ms: i64,
    ) -> Result<Silences, String> {
        let path = data_dir.join(FILE);
        let file: StoredFile = match std::fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoredFile::default(),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let mut added = Vec::new();
        for s in file.silences {
            let time = |v: &str| {
                parse_time(v).map_err(|e| format!("{}: silence {}: {e}", path.display(), s.name))
            };
            let (start_ms, end_ms, created_ms) =
                (time(&s.start)?, time(&s.end)?, time(&s.created)?);
            if end_ms + KEEP_ENDED_MS < now_ms {
                continue;
            }
            added.push(Added {
                silence: Silence {
                    name: s.name,
                    targets: s.targets,
                    groups: s.groups,
                    alerts: s.alerts,
                    when: When::Once { start_ms, end_ms },
                    line: 0,
                },
                by: s.by,
                comment: s.comment,
                created_ms,
                ended_by: s.ended_by,
            });
        }
        Ok(Silences {
            configured,
            added: Mutex::new(added),
            path: Some(path),
        })
    }

    /// Every silence, configured first.
    pub fn all(&self) -> Vec<Silence> {
        let mut v = self.configured.clone();
        v.extend(lock(&self.added).iter().map(|a| a.silence.clone()));
        v
    }

    pub fn configured_list(&self) -> &[Silence] {
        &self.configured
    }

    pub fn added(&self) -> Vec<Added> {
        lock(&self.added).clone()
    }

    fn save(&self, added: &[Added]) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = StoredFile {
            silences: added
                .iter()
                .map(|a| {
                    let (start_ms, end_ms) = match a.silence.when {
                        When::Once { start_ms, end_ms } => (start_ms, end_ms),
                        When::Every { .. } => (0, 0),
                    };
                    Stored {
                        name: a.silence.name.clone(),
                        targets: a.silence.targets.clone(),
                        groups: a.silence.groups.clone(),
                        alerts: a.silence.alerts.clone(),
                        start: stamp(start_ms),
                        end: stamp(end_ms),
                        by: a.by.clone(),
                        comment: a.comment.clone(),
                        created: stamp(a.created_ms),
                        ended_by: a.ended_by.clone(),
                    }
                })
                .collect(),
        };
        let body = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        };
        write().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot write {}: {e}", path.display())
        })
    }

    /// Add a one-off silence. The name must be new among configured and
    /// added ones (ended added ones included, as their record stays).
    pub fn add(&self, a: Added, now_ms: i64) -> Result<(), AddError> {
        let mut added = lock(&self.added);
        let name = &a.silence.name;
        if self.configured.iter().any(|s| &s.name == name)
            || added.iter().any(|s| &s.silence.name == name)
        {
            return Err(AddError::Exists);
        }
        let mut next = added.clone();
        next.retain(|x| match x.silence.when {
            When::Once { end_ms, .. } => end_ms + KEEP_ENDED_MS >= now_ms,
            When::Every { .. } => true,
        });
        next.push(a);
        self.save(&next).map_err(AddError::Write)?;
        *added = next;
        Ok(())
    }

    /// End an added silence now. Configured ones cannot be ended here.
    pub fn end(&self, name: &str, by: Option<String>, now_ms: i64) -> Result<(), EndError> {
        if self.configured.iter().any(|s| s.name == name) {
            return Err(EndError::Configured);
        }
        let mut added = lock(&self.added);
        let mut next = added.clone();
        let Some(a) = next.iter_mut().find(|a| a.silence.name == name) else {
            return Err(EndError::NotFound);
        };
        match &mut a.silence.when {
            When::Once { start_ms, end_ms } => {
                if *end_ms <= now_ms {
                    return Err(EndError::Over);
                }
                *end_ms = now_ms;
                // One that had not started yet is over before it began.
                *start_ms = (*start_ms).min(now_ms);
            }
            When::Every { .. } => return Err(EndError::Configured),
        }
        a.ended_by = by;
        self.save(&next).map_err(EndError::Write)?;
        *added = next;
        Ok(())
    }
}

/// Why a silence could not be added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddError {
    /// The name is taken.
    Exists,
    Write(String),
}

/// Why a silence could not be ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndError {
    NotFound,
    /// It is in the configuration file.
    Configured,
    /// It has ended already.
    Over,
    Write(String),
}

/// The longest comment kept.
const MAX_COMMENT: usize = 500;
/// The most targets, groups or rules one added silence names.
const MAX_ITEMS: usize = 100;

/// `POST /api/v1/silences`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddBody {
    /// Made up when left out.
    name: Option<String>,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    alerts: Vec<String>,
    /// Unix milliseconds; now when left out.
    start: Option<i64>,
    /// Unix milliseconds; give this or `minutes`.
    end: Option<i64>,
    minutes: Option<i64>,
    /// Why; required, so the record says.
    comment: String,
}

/// Why the caller may not change silences, if so. Operators and admins
/// may, once logged in: without users the server is open to anyone who
/// reaches it, so then no one may.
fn may_silence(c: &Caller) -> Option<Response> {
    if c.name.is_none() {
        return Some(error(
            StatusCode::FORBIDDEN,
            "silences can be added only by a logged-in operator; add users with `routelith ctl user`",
        ));
    }
    if c.role < Role::Operator {
        return Some(error(
            StatusCode::FORBIDDEN,
            "only operators and admins can add or end silences",
        ));
    }
    None
}

/// The first name that is not known, to name it in a message.
fn unknown(names: &[String], known: impl Fn(&str) -> bool) -> Option<&String> {
    names.iter().find(|n| !known(n))
}

fn check_body(s: &AppState, b: &AddBody, now: i64) -> Result<(i64, i64, String), String> {
    if let Some(t) = unknown(&b.targets, |n| s.series.iter().any(|i| i.key.target == n)) {
        return Err(format!("no target {t:?}"));
    }
    if let Some(g) = unknown(&b.groups, |n| s.series.iter().any(|i| i.group == n)) {
        return Err(format!("no group {g:?}"));
    }
    if let Some(r) = unknown(&b.alerts, |n| s.alerts.rules().iter().any(|r| r.name == n)) {
        return Err(format!("no alert rule {r:?}"));
    }
    if [&b.targets, &b.groups, &b.alerts]
        .iter()
        .any(|v| v.len() > MAX_ITEMS)
    {
        return Err(format!(
            "at most {MAX_ITEMS} targets, groups and alert rules"
        ));
    }
    let comment = b.comment.trim();
    if comment.is_empty() || comment.chars().count() > MAX_COMMENT {
        return Err(format!(
            "comment must say why, in 1 to {MAX_COMMENT} characters"
        ));
    }
    if comment.chars().any(char::is_control) {
        return Err("comment must be one line".into());
    }
    let start = b.start.unwrap_or(now);
    let end = match (b.end, b.minutes) {
        (Some(e), None) => e,
        (None, Some(m)) if m > 0 => start.saturating_add(m.saturating_mul(60_000)),
        (None, Some(_)) => return Err("minutes must be at least 1".into()),
        _ => return Err("give either end or minutes".into()),
    };
    if end <= start || end <= now {
        return Err("the silence must end after it starts, and in the future".into());
    }
    if end - start > MAX_WINDOW_MS || start > now + MAX_WINDOW_MS {
        return Err("a silence can last at most 90 days, and start within 90 days".into());
    }
    Ok((start, end, comment.to_string()))
}

/// A silence as the API lists it.
pub(crate) fn silence_json(x: &Silence, a: Option<&Added>, now: i64) -> serde_json::Value {
    let mut v = serde_json::json!({
        "name": x.name,
        "summary": x.summary(),
        "targets": x.targets,
        "groups": x.groups,
        "alerts": x.alerts,
        "active": x.active_at(now),
        "source": if a.is_some() { "ui" } else { "config" },
    });
    if let When::Once { start_ms, end_ms } = x.when {
        v["start"] = start_ms.into();
        v["end"] = end_ms.into();
    }
    if let Some(a) = a {
        v["by"] = a.by.clone().into();
        v["comment"] = a.comment.clone().into();
        v["created"] = a.created_ms.into();
        v["ended_by"] = a.ended_by.clone().into();
    }
    v
}

/// Add a one-off silence.
pub(crate) async fn create(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<AddBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Some(r) = may_silence(&caller) {
        return r;
    }
    let Ok(Json(b)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "send JSON: {targets, groups, alerts, start, end or minutes, comment}",
        );
    };
    let now = now_ms();
    let (start_ms, end_ms, comment) = match check_body(&s, &b, now) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    if let Some(n) = &b.name {
        if !valid_name(n) {
            return error(
                StatusCode::BAD_REQUEST,
                "name: up to 64 letters, digits, '.', '_' or '-', starting with a letter or digit",
            );
        }
    }
    let silences = s.alerts.silences().clone();
    let by = caller.name.clone();
    let named = b.name.clone();
    let made = tokio::task::spawn_blocking(move || {
        // A made-up name gets a number when the second is taken.
        for i in 0..100 {
            let name = match (&named, i) {
                (Some(n), _) => n.clone(),
                (None, 0) => format!("ui-{}", now / 1000),
                (None, i) => format!("ui-{}-{i}", now / 1000),
            };
            let a = Added {
                silence: Silence {
                    name,
                    targets: b.targets.clone(),
                    groups: b.groups.clone(),
                    alerts: b.alerts.clone(),
                    when: When::Once { start_ms, end_ms },
                    line: 0,
                },
                by: by.clone(),
                comment: comment.clone(),
                created_ms: now,
                ended_by: None,
            };
            match silences.add(a.clone(), now) {
                Ok(()) => return Ok(a),
                Err(AddError::Exists) if named.is_none() => continue,
                Err(e) => return Err(e),
            }
        }
        Err(AddError::Exists)
    })
    .await;
    match made {
        Ok(Ok(a)) => {
            eprintln!(
                "routelith server: silence {} added by {} until {}: {}",
                a.silence.name,
                a.by.as_deref().unwrap_or("?"),
                format_time(end_ms),
                a.comment
            );
            (
                StatusCode::CREATED,
                Json(silence_json(&a.silence, Some(&a), now)),
            )
                .into_response()
        }
        Ok(Err(AddError::Exists)) => error(StatusCode::CONFLICT, "a silence of that name exists"),
        Ok(Err(AddError::Write(e))) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// End an added silence now.
pub(crate) async fn end_now(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    UrlPath(name): UrlPath<String>,
) -> Response {
    if let Some(r) = may_silence(&caller) {
        return r;
    }
    let silences = s.alerts.silences().clone();
    let by = caller.name.clone();
    let n = name.clone();
    let ended = tokio::task::spawn_blocking(move || silences.end(&n, by, now_ms())).await;
    match ended {
        Ok(Ok(())) => {
            eprintln!(
                "routelith server: silence {name} ended by {}",
                caller.name.as_deref().unwrap_or("?")
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(EndError::NotFound)) => error(StatusCode::NOT_FOUND, format!("no silence {name:?}")),
        Ok(Err(EndError::Configured)) => error(
            StatusCode::CONFLICT,
            "this silence is in the configuration file; change it there",
        ),
        Ok(Err(EndError::Over)) => error(StatusCode::CONFLICT, "this silence has ended already"),
        Ok(Err(EndError::Write(e))) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_790_000_000_000;
    const H: i64 = 3_600_000;

    fn added(name: &str, start_ms: i64, end_ms: i64) -> Added {
        Added {
            silence: Silence {
                name: name.into(),
                targets: vec!["gw".into()],
                groups: Vec::new(),
                alerts: vec!["down".into()],
                when: When::Once { start_ms, end_ms },
                line: 0,
            },
            by: Some("ann".into()),
            comment: "ISP works".into(),
            created_ms: start_ms,
            ended_by: None,
        }
    }

    #[test]
    fn added_silences_survive_a_restart_and_end_early() {
        let dir = tempfile::tempdir().unwrap();
        let s = Silences::load(Vec::new(), dir.path(), T0).unwrap();
        s.add(added("works", T0, T0 + 2 * H), T0).unwrap();
        assert_eq!(s.add(added("works", T0, T0 + H), T0), Err(AddError::Exists));

        let s = Silences::load(Vec::new(), dir.path(), T0 + H).unwrap();
        let a = s.added();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].by.as_deref(), Some("ann"));
        assert!(a[0].silence.active_at(T0 + H));

        s.end("works", Some("bob".into()), T0 + H).unwrap();
        assert!(!s.all()[0].active_at(T0 + H));
        assert_eq!(s.end("works", None, T0 + H), Err(EndError::Over));
        assert_eq!(s.end("nope", None, T0 + H), Err(EndError::NotFound));
        let s = Silences::load(Vec::new(), dir.path(), T0 + 2 * H).unwrap();
        assert_eq!(s.added()[0].ended_by.as_deref(), Some("bob"));

        // A week after it ended, it is gone.
        let s = Silences::load(Vec::new(), dir.path(), T0 + H + KEEP_ENDED_MS + 1).unwrap();
        assert!(s.added().is_empty());
    }

    #[test]
    fn configured_silences_cannot_be_ended_or_reused() {
        let cfg = added("sunday", T0, T0 + H).silence;
        let s = Silences::configured(vec![cfg]);
        assert_eq!(s.end("sunday", None, T0), Err(EndError::Configured));
        assert!(s.add(added("sunday", T0, T0 + H), T0).is_err());
    }

    #[test]
    fn times_are_kept_to_the_millisecond() {
        for t in [0, T0 + 1, T0 + 59_999] {
            assert_eq!(parse_time(&stamp(t)), Ok(t), "{}", stamp(t));
        }
    }

    #[test]
    fn a_broken_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), "{").unwrap();
        assert!(Silences::load(Vec::new(), dir.path(), T0).is_err());
    }
}
