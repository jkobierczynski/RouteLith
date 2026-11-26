//! The local health snapshot (architecture doc §19, §21.3 E13): the newest
//! sample for `/metrics`, and `GET /api/v1/health` for the target view.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rl_store::{HealthSample, NicDelta};
use serde::Serialize;

use crate::api::RangeQuery;
use crate::{AppState, MetricsWriter, error};

const MINUTE_MS: i64 = 60_000;
const DEFAULT_POINTS: u32 = 800;
const MAX_POINTS: u32 = 5000;

/// Error and drop counters of one interface since it came up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicTotal {
    pub name: String,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

/// The newest snapshot, with the cumulative counters behind it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostHealth {
    pub sample: HealthSample,
    pub nics: Vec<NicTotal>,
}

/// Shared between the health sampler and the HTTP side.
#[derive(Debug, Default)]
pub struct LatestHost(Mutex<Option<HostHealth>>);

impl LatestHost {
    pub fn record(&self, h: HostHealth) {
        if let Ok(mut m) = self.0.lock() {
            *m = Some(h);
        }
    }

    pub fn get(&self) -> Option<HostHealth> {
        self.0.lock().ok().and_then(|m| m.clone())
    }
}

/// Health metrics, with the vantage label.
pub(crate) fn metrics(m: &mut MetricsWriter, vantage: &str, h: &HostHealth) {
    let v = ("vantage", vantage);
    let s = &h.sample;
    m.family(
        "routelith_host_snapshot_timestamp_seconds",
        "gauge",
        "Time of this machine's newest health snapshot (one a minute).",
    );
    m.sample(
        "routelith_host_snapshot_timestamp_seconds",
        &[v],
        s.t as f64 / 1000.0,
    );
    if let Some(cpu) = s.cpu_pct {
        m.family(
            "routelith_host_cpu_busy_ratio",
            "gauge",
            "Share of CPU time busy over the last minute, all CPUs.",
        );
        m.sample(
            "routelith_host_cpu_busy_ratio",
            &[v],
            (cpu / 100.0 * 10_000.0).round() / 10_000.0,
        );
    }
    if let Some(load) = s.load1 {
        m.family("routelith_host_load1", "gauge", "One-minute load average.");
        m.sample("routelith_host_load1", &[v], load);
    }
    for (name, help, rx, tx) in [
        (
            "routelith_host_nic_errors_total",
            "Receive and transmit errors of a network interface since it came up.",
            (|n: &NicTotal| n.rx_errors) as fn(&NicTotal) -> u64,
            (|n: &NicTotal| n.tx_errors) as fn(&NicTotal) -> u64,
        ),
        (
            "routelith_host_nic_drops_total",
            "Packets a network interface dropped since it came up.",
            |n: &NicTotal| n.rx_drops,
            |n: &NicTotal| n.tx_drops,
        ),
    ] {
        if h.nics.is_empty() {
            continue;
        }
        m.family(name, "counter", help);
        for n in &h.nics {
            for (dir, value) in [("rx", rx(n)), ("tx", tx(n))] {
                m.sample(
                    name,
                    &[v, ("interface", &n.name), ("direction", dir)],
                    value as f64,
                );
            }
        }
    }
    for (name, help, addrs) in [
        (
            "routelith_host_gateway_info",
            "A default gateway of this machine (the value is always 1).",
            &s.gateways,
        ),
        (
            "routelith_host_dns_server_info",
            "A DNS server this machine uses (the value is always 1).",
            &s.dns,
        ),
    ] {
        m.family(name, "gauge", help);
        for a in addrs {
            m.sample(name, &[v, ("address", &a.to_string())], 1.0);
        }
    }
}

/// One point of `/api/v1/health`: the samples of one bucket.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct HealthPoint {
    /// Bucket start, Unix milliseconds.
    t: i64,
    /// Samples in the bucket.
    n: u32,
    /// Highest CPU busy percentage of the bucket's minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pct: Option<f64>,
    /// Highest load average.
    #[serde(skip_serializing_if = "Option::is_none")]
    load1: Option<f64>,
    /// NIC errors and drops summed over the bucket; left out when no
    /// sample in it could read the counters.
    #[serde(skip_serializing_if = "Option::is_none")]
    nic_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nic_drops: Option<u64>,
    /// Interfaces with errors or drops in the bucket.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nics: Vec<NicDelta>,
}

/// Gateways and DNS servers from `t` on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NetworkState {
    t: i64,
    gateways: Vec<IpAddr>,
    dns: Vec<IpAddr>,
}

/// Samples into buckets of `width` from `from`, and every change of
/// gateways or DNS servers at full resolution. The first network state is
/// the one at the start of the range.
pub(crate) fn summarise(
    samples: &[HealthSample],
    from: i64,
    width: i64,
) -> (Vec<HealthPoint>, Vec<NetworkState>) {
    let mut points: Vec<HealthPoint> = Vec::new();
    let mut nics: BTreeMap<String, NicDelta> = BTreeMap::new();
    let mut network: Vec<NetworkState> = Vec::new();
    let flush = |points: &mut Vec<HealthPoint>, nics: &mut BTreeMap<String, NicDelta>| {
        if let Some(p) = points.last_mut() {
            p.nics = std::mem::take(nics).into_values().collect();
        }
    };
    for s in samples {
        let t = from + (s.t - from).div_euclid(width) * width;
        if points.last().is_none_or(|p| p.t != t) {
            flush(&mut points, &mut nics);
            points.push(HealthPoint {
                t,
                n: 0,
                cpu_pct: None,
                load1: None,
                nic_errors: None,
                nic_drops: None,
                nics: Vec::new(),
            });
        }
        let Some(p) = points.last_mut() else {
            continue;
        };
        p.n += 1;
        p.cpu_pct = max_opt(p.cpu_pct, s.cpu_pct);
        p.load1 = max_opt(p.load1, s.load1);
        let add = |sum: Option<u64>, v: Option<u64>| match (sum, v) {
            (Some(a), Some(b)) => Some(a + b),
            (a, b) => a.or(b),
        };
        p.nic_errors = add(p.nic_errors, s.nic_errors);
        p.nic_drops = add(p.nic_drops, s.nic_drops);
        for d in &s.nics {
            let e = nics.entry(d.name.clone()).or_insert_with(|| NicDelta {
                name: d.name.clone(),
                ..NicDelta::default()
            });
            e.errors += d.errors;
            e.drops += d.drops;
        }
        let changed = network
            .last()
            .is_none_or(|n| n.gateways != s.gateways || n.dns != s.dns);
        if changed {
            network.push(NetworkState {
                t: s.t,
                gateways: s.gateways.clone(),
                dns: s.dns.clone(),
            });
        }
    }
    flush(&mut points, &mut nics);
    (points, network)
}

fn max_opt(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// Whose health: the server's own by default, or an agent's.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct VantageQuery {
    vantage: Option<String>,
}

/// `GET /api/v1/health`: a vantage's health snapshots over a range, in
/// whole-minute buckets sized for `points`. Without `vantage`, this
/// machine's; agents send theirs once a minute (§21.7 G10).
pub(crate) async fn history(
    State(s): State<Arc<AppState>>,
    Query(q): Query<RangeQuery>,
    Query(v): Query<VantageQuery>,
) -> Response {
    let (from, to) = match q.resolve() {
        Ok(r) => r,
        Err(r) => return r,
    };
    let points = i64::from(q.points.unwrap_or(DEFAULT_POINTS).clamp(10, MAX_POINTS));
    let minutes = ((to - from) / points + MINUTE_MS - 1) / MINUTE_MS;
    let width = minutes.max(1) * MINUTE_MS;
    let dir = s.data_dir.clone();
    let vantage = v.vantage.unwrap_or_else(|| s.vantage.clone());
    let name = vantage.clone();
    let read =
        tokio::task::spawn_blocking(move || rl_store::read_health(&dir, &vantage, from, to)).await;
    let samples = match read {
        Ok(Ok(v)) => v,
        Ok(Err(rl_store::StoreError::InvalidKey(v))) => {
            return error(StatusCode::BAD_REQUEST, format!("no vantage named {v:?}"));
        }
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (points, network) = summarise(&samples, from, width);
    Json(serde_json::json!({
        "vantage": name,
        "from": from,
        "to": to,
        "width_ms": width,
        "points": points,
        "network": network,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(t: i64, cpu: f64, errors: u64, gw: &str) -> HealthSample {
        HealthSample {
            t,
            interval_ms: MINUTE_MS,
            cpu_pct: Some(cpu),
            nic_errors: Some(errors),
            nic_drops: Some(0),
            nics: if errors > 0 {
                vec![NicDelta {
                    name: "eth0".into(),
                    errors,
                    drops: 0,
                }]
            } else {
                Vec::new()
            },
            gateways: vec![gw.parse().unwrap()],
            dns: vec!["192.0.2.53".parse().unwrap()],
            ..HealthSample::default()
        }
    }

    #[test]
    fn buckets_keep_the_worst_minute_and_every_network_change() {
        let m = MINUTE_MS;
        let samples = [
            sample(m, 10.0, 0, "192.0.2.1"),
            sample(2 * m, 50.0, 2, "192.0.2.1"),
            sample(3 * m, 20.0, 1, "192.0.2.254"),
            sample(4 * m, 5.0, 0, "192.0.2.254"),
        ];
        let (points, network) = summarise(&samples, 0, 3 * m);
        assert_eq!(points.len(), 2);
        assert_eq!((points[0].t, points[0].n), (0, 2));
        assert_eq!(points[0].cpu_pct, Some(50.0));
        assert_eq!(points[0].nic_errors, Some(2));
        assert_eq!(points[0].nics.len(), 1);
        assert_eq!(
            (points[1].t, points[1].n, points[1].nic_errors),
            (3 * m, 2, Some(1))
        );
        // A bucket whose samples could not read the counters has no total;
        // one that read zero has zero.
        let mut unread = sample(m, 10.0, 0, "192.0.2.1");
        unread.nic_errors = None;
        unread.nic_drops = None;
        let (points, _) = summarise(&[unread, sample(4 * m, 5.0, 0, "192.0.2.1")], 0, 3 * m);
        assert_eq!((points[0].nic_errors, points[0].nic_drops), (None, None));
        assert_eq!(points[1].nic_errors, Some(0));
        // The change at 3 min is kept even though it is inside a bucket.
        assert_eq!(network.len(), 2);
        assert_eq!(network[1].t, 3 * m);
        assert_eq!(network[1].gateways[0].to_string(), "192.0.2.254");
    }
}
