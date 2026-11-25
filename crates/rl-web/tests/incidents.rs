//! The NIS2 incident timeline from a scripted event log (doc §21.5 F14).

use std::collections::HashMap;

use rl_store::{Event, EventKind};
use rl_web::incidents::{self, DEFAULT_GAP_MS};

/// 2027-01-01T00:00:00Z.
const JAN: i64 = 1_798_761_600_000;
const FEB: i64 = 1_801_440_000_000;
const MIN: i64 = 60_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 86_400_000;

fn alert(t: i64, kind: EventKind, target: &str, series: u64, rule: &str, since: i64) -> Event {
    let mut e = Event::new(
        t,
        kind,
        "home",
        format!("{target} (v4): {rule} {}", kind.as_str()),
    );
    e.target = Some(target.into());
    e.family = Some("v4".into());
    e.series = Some(series);
    e.rule = Some(rule.into());
    e.since = Some(since);
    e.value = Some(if kind == EventKind::AlertRaised {
        100.0
    } else {
        0.0
    });
    e
}

fn parents() -> HashMap<String, String> {
    [("router", "gw"), ("printer", "router")]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

/// 10 January 08:00 UTC.
const T0: i64 = JAN + 9 * DAY + 8 * HOUR;

fn events() -> Vec<Event> {
    use EventKind::*;
    let mut v = vec![
        // Raised in December, cleared in January: in January's timeline.
        alert(
            JAN - 2 * HOUR,
            AlertRaised,
            "web",
            4,
            "slow",
            JAN - 2 * HOUR - MIN,
        ),
        alert(
            JAN + HOUR,
            AlertCleared,
            "web",
            4,
            "slow",
            JAN - 2 * HOUR - MIN,
        ),
        // The router degrades, its child follows; both recover.
        alert(T0, AlertRaised, "router", 2, "down", T0 - MIN),
        alert(T0 + 2 * MIN, AlertRaised, "printer", 3, "down", T0 + MIN),
        alert(T0 + 10 * MIN, AlertCleared, "router", 2, "down", T0 - MIN),
        alert(T0 + 12 * MIN, AlertCleared, "printer", 3, "down", T0 + MIN),
        // The gateway 8 minutes later: within the gap, the same incident.
        alert(T0 + 20 * MIN, AlertRaised, "gw", 1, "down", T0 + 20 * MIN),
        alert(T0 + 30 * MIN, AlertCleared, "gw", 1, "down", T0 + 20 * MIN),
        // Half an hour later: a new one, still open.
        alert(T0 + 60 * MIN, AlertRaised, "gw", 1, "down", T0 + 59 * MIN),
    ];
    let mut ip = Event::new(
        T0 + 5 * MIN,
        IpChanged,
        "home",
        "router (v4): address changed",
    );
    ip.target = Some("router".into());
    v.push(ip);
    v.push(Event::new(
        T0 + 25 * MIN,
        ServerStopped,
        "home",
        "server stopped",
    ));
    v.push(Event::new(
        T0 + 26 * MIN,
        ServerStarted,
        "home",
        "server started",
    ));
    // Planned work on another target.
    let mut s = alert(T0 + 3 * HOUR, AlertRaised, "web", 4, "slow", T0 + 3 * HOUR);
    s.silenced_by = Some("works".into());
    v.push(s);
    let mut c = alert(T0 + 4 * HOUR, AlertCleared, "web", 4, "slow", T0 + 3 * HOUR);
    c.silenced_by = Some("works".into());
    v.push(c);
    // February: outside the month.
    v.push(alert(FEB + HOUR, AlertRaised, "gw", 1, "slow", FEB + HOUR));
    v.sort_by_key(|e| e.t);
    v
}

#[test]
fn alerts_on_a_target_and_its_children_form_incidents() {
    let mut peaks = Vec::new();
    let list = incidents::build(
        &events(),
        &parents(),
        JAN,
        FEB,
        DEFAULT_GAP_MS,
        |s, a, b| {
            peaks.push((s, a, b));
            Some((100.0, Some(12.5)))
        },
    );
    let ids: Vec<&str> = list.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "web-20261231T2159",
            "gw-20270110T0759",
            "gw-20270110T0859",
            "web-20270110T1100"
        ]
    );

    // From December into January.
    let dec = &list[0];
    assert_eq!(
        (dec.start, dec.end),
        (JAN - 2 * HOUR - MIN, Some(JAN + HOUR))
    );

    let i = &list[1];
    assert_eq!(i.root, "gw");
    assert_eq!(i.targets, ["gw", "printer", "router"]);
    assert_eq!(i.start, T0 - MIN, "the router's first bad round");
    assert_eq!(i.detected, T0, "the first alert raised");
    assert_eq!(i.end, Some(T0 + 30 * MIN), "the gateway's recovery");
    assert!(!i.planned);
    assert_eq!(i.deadlines.early_warning, T0 + 24 * HOUR);
    assert_eq!(i.deadlines.notification, T0 + 72 * HOUR);
    // 13 January 08:00 plus a month: 13 February 08:00.
    assert_eq!(i.deadlines.final_report, FEB + 12 * DAY + 8 * HOUR);
    assert_eq!(i.alerts.len(), 3);
    assert_eq!(i.alerts[0].peak_loss_pct, Some(100.0));
    let kinds: Vec<&str> = i.timeline.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [
            "degradation_began",
            "alert_raised",
            "alert_raised",
            "ip_changed",
            "alert_cleared",
            "alert_cleared",
            "alert_raised",
            "server_stopped",
            "server_started",
            "alert_cleared"
        ]
    );

    let open = &list[2];
    assert!(open.ongoing());
    assert_eq!(open.end, None);
    // While it is open, later alerts below the same root join it.
    assert_eq!(open.alerts.len(), 2);
    let planned = &list[3];
    assert!(planned.planned, "every alert silenced");

    // Peaks are asked per alert, over its span.
    assert!(peaks.contains(&(2, T0 - MIN, T0 + 10 * MIN)));

    // A narrower gap splits the gateway off.
    let list = incidents::build(&events(), &parents(), JAN, FEB, 5 * MIN, |_, _, _| None);
    assert_eq!(list.len(), 5);
}

#[test]
fn deadlines_keep_the_time_of_day_in_short_months() {
    // Detected 28 January 10:00: notification due 31 January 10:00, the
    // final report by 28 February 10:00.
    let d = incidents::deadlines(JAN + 27 * DAY + 10 * HOUR);
    assert_eq!(d.notification, JAN + 30 * DAY + 10 * HOUR);
    assert_eq!(d.final_report, FEB + 27 * DAY + 10 * HOUR);
}

#[test]
fn the_timeline_comes_as_html_json_and_csv() {
    let list = incidents::build(
        &events(),
        &parents(),
        JAN,
        FEB,
        DEFAULT_GAP_MS,
        |_, _, _| None,
    );
    let t = incidents::Timeline {
        month: "2027-01".into(),
        vantage: "home".into(),
        from: JAN,
        to: FEB,
        generated: FEB + DAY,
        gap_ms: DEFAULT_GAP_MS,
        incidents: list,
    };
    let html = incidents::html(&t);
    assert!(html.contains("Incident timeline, 2027-01"));
    assert!(html.contains("gw-20270110T0759"));
    assert!(
        html.contains("Notification due</dt><dd>2027-01-13 08:00 UTC"),
        "{html}"
    );
    assert!(html.contains("planned (silenced)") && html.contains("ongoing"));
    assert!(html.contains("4</b> incidents, 1 still open"));

    let v: serde_json::Value = serde_json::from_str(&incidents::json(&t)).unwrap();
    assert_eq!(
        v["incidents"][1]["deadlines"]["notification"],
        T0 + 72 * HOUR
    );
    assert_eq!(v["incidents"][2]["end"], serde_json::Value::Null);

    let csv = incidents::csv(&t);
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].starts_with("incident,root,incident_start,detected,"));
    // One line per alert: 1 + 3 + 2 + 1 (the open incident takes in
    // February's alert on the gateway too).
    assert_eq!(lines.len(), 1 + 7);
    assert!(lines[2].starts_with(
        "gw-20270110T0759,gw,2027-01-10T07:59:00.000Z,2027-01-10T08:00:00.000Z,2027-01-10T08:30:00.000Z,false,\
         2027-01-11T08:00:00.000Z,2027-01-13T08:00:00.000Z,2027-02-13T08:00:00.000Z,router,v4,down,"
    ), "{}", lines[2]);
}
