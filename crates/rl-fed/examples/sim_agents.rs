//! Simulated agents for the M3 scale test (doc §21.8 "Scale"): enrolls
//! one agent per token, connects each to the server over the real
//! protocol, and streams a synthetic round for every series it is
//! assigned, at the series' step, spread evenly over the step as the
//! scheduler does. Each agent counts the time from sending a round to the
//! server's Ack for it (sent after the round is stored and synced), so a
//! server that falls behind shows as growing Ack delays.
//!
//!   cargo run --release -p rl-fed --example sim_agents -- \
//!     <server host:port> <work dir> <tokens file> <seconds>
//!
//! Prints one line per agent and a summary line; exits 1 if a round was
//! never acknowledged.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rl_fed::client::{self, Identity, Intro, ServerAddr};
use rl_fed::pb::{self, agent_message::Msg as Out, server_message::Msg as In};
use rl_fed::token::Token;

const VERSION: &str = "0.0.0-sim";
const BATCH: usize = 500;

#[derive(Debug, Default)]
struct Report {
    name: String,
    series: usize,
    sent: u64,
    acked: u64,
    /// Send-to-Ack delays, ms.
    delays: Vec<u64>,
    error: Option<String>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [server, dir, tokens, seconds] = args.as_slice() else {
        eprintln!("usage: sim_agents <server host:port> <work dir> <tokens file> <seconds>");
        return ExitCode::from(2);
    };
    let server = ServerAddr::parse(server).expect("server address");
    let dir = PathBuf::from(dir);
    let run_for = Duration::from_secs(seconds.parse().expect("seconds"));
    let tokens: Vec<Token> = std::fs::read_to_string(tokens)
        .expect("tokens file")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| Token::parse(l).expect("token"))
        .collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let reports = rt.block_on(async {
        let mut tasks = Vec::new();
        for (i, token) in tokens.into_iter().enumerate() {
            let server = server.clone();
            let data_dir = dir.join(format!("agent-{i}"));
            tasks.push(tokio::spawn(async move {
                let mut r = Report::default();
                if let Err(e) = agent(&server, &token, &data_dir, i as u64, run_for, &mut r).await {
                    r.error = Some(e);
                }
                r
            }));
        }
        let mut out = Vec::new();
        for t in tasks {
            out.push(t.await.expect("agent task"));
        }
        out
    });
    let mut all: Vec<u64> = Vec::new();
    let (mut sent, mut acked, mut failed) = (0, 0, false);
    for r in &reports {
        let mut d = r.delays.clone();
        d.sort_unstable();
        println!(
            "agent {}: {} series, {} rounds sent, {} acknowledged, ack delay p50 {} ms p99 {} ms max {} ms{}",
            r.name,
            r.series,
            r.sent,
            r.acked,
            pct(&d, 50),
            pct(&d, 99),
            d.last().copied().unwrap_or(0),
            r.error
                .as_ref()
                .map(|e| format!(", error: {e}"))
                .unwrap_or_default()
        );
        failed |= r.error.is_some() || r.acked < r.sent || r.sent == 0;
        sent += r.sent;
        acked += r.acked;
        all.extend(&r.delays);
    }
    all.sort_unstable();
    println!(
        "summary: agents={} series={} sent={sent} acked={acked} ack_p50_ms={} ack_p99_ms={} ack_max_ms={}",
        reports.len(),
        reports.iter().map(|r| r.series).sum::<usize>(),
        pct(&all, 50),
        pct(&all, 99),
        all.last().copied().unwrap_or(0)
    );
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn pct(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() * p).div_ceil(100))
        .saturating_sub(1)
        .min(sorted.len() - 1)]
}

async fn agent(
    server: &ServerAddr,
    token: &Token,
    data_dir: &std::path::Path,
    i: u64,
    run_for: Duration,
    r: &mut Report,
) -> Result<(), String> {
    r.name = client::enroll(server, token, data_dir, VERSION)
        .await
        .map_err(|e| e.to_string())?;
    let id = Identity::load(data_dir).map_err(|e| e.to_string())?;
    let intro = Intro {
        spool_id: ((rl_fed::now_us() as u64) ^ (i << 48)) | 1,
        acked_seq: 0,
        capabilities: vec![],
    };
    let mut s = client::connect(server, &id, VERSION, intro)
        .await
        .map_err(|e| e.to_string())?;

    // The assignment comes first.
    let series: Vec<(u64, Duration, u16)> = loop {
        match s.inbound.message().await.map_err(|e| e.to_string())? {
            Some(pb::ServerMessage {
                msg: Some(In::Config(snap)),
            }) => {
                let mut v = Vec::new();
                for a in &snap.assignments {
                    let spec = rl_fed::assign::spec(a).map_err(|e| e.to_string())?;
                    v.push((a.series_id, spec.schedule.step, spec.schedule.pings));
                }
                let applied = pb::ConfigApplied {
                    version: snap.version.clone(),
                    refused: vec![],
                };
                s.outbound
                    .send(pb::AgentMessage {
                        msg: Some(Out::Applied(applied)),
                    })
                    .await
                    .map_err(|_| "the stream closed")?;
                break v;
            }
            Some(_) => {}
            None => return Err("the server closed the stream".into()),
        }
    };
    r.series = series.len();
    if series.is_empty() {
        return Err("no series assigned".into());
    }

    // Slots: series j of n is due at j/n of its step after the start, and
    // every step after that.
    let start = Instant::now();
    let start_ms = rl_fed::now_ms();
    let n = series.len() as u32;
    let mut next: Vec<Duration> = (0..series.len())
        .map(|j| series[j].1 * j as u32 / n)
        .collect();
    let mut pending: VecDeque<(u64, Instant)> = VecDeque::new();
    let mut seq = 0u64;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut done_sending = false;
    let drain_until = run_for + Duration::from_secs(60);
    loop {
        tokio::select! {
            msg = s.inbound.message() => match msg.map_err(|e| e.to_string())? {
                Some(pb::ServerMessage { msg: Some(In::Ack(a)) }) => {
                    let now = Instant::now();
                    while pending.front().is_some_and(|(q, _)| *q <= a.up_to_seq) {
                        let (_, at) = pending.pop_front().expect("front");
                        r.delays.push(now.duration_since(at).as_millis() as u64);
                        r.acked += 1;
                    }
                }
                Some(pb::ServerMessage { msg: Some(In::Clock(p)) }) => {
                    let t2 = rl_fed::now_us();
                    let reply = pb::ClockReply { t1_us: p.t1_us, t2_us: t2, t3_us: rl_fed::now_us() };
                    s.outbound
                        .send(pb::AgentMessage { msg: Some(Out::Clock(reply)) })
                        .await
                        .map_err(|_| "the stream closed")?;
                }
                Some(_) => {}
                None => return Err("the server closed the stream".into()),
            },
            _ = tick.tick() => {
                let elapsed = start.elapsed();
                if elapsed >= run_for {
                    done_sending = true;
                }
                if done_sending {
                    if pending.is_empty() || elapsed >= drain_until {
                        return Ok(());
                    }
                    continue;
                }
                let mut rounds = Vec::new();
                for (j, &(id, step, pings)) in series.iter().enumerate() {
                    while next[j] <= elapsed {
                        seq += 1;
                        rounds.push(round(seq, id, start_ms + next[j].as_millis() as i64, pings, seq));
                        next[j] += step;
                    }
                }
                let now = Instant::now();
                for chunk in rounds.chunks(BATCH) {
                    for rd in chunk {
                        pending.push_back((rd.seq, now));
                    }
                    r.sent += chunk.len() as u64;
                    let batch = pb::ResultBatch { rounds: chunk.to_vec() };
                    s.outbound
                        .send(pb::AgentMessage { msg: Some(Out::Results(batch)) })
                        .await
                        .map_err(|_| "the stream closed")?;
                }
            }
        }
    }
}

/// A plausible round: every sample answered in 1 to 2 ms.
fn round(seq: u64, series_id: u64, ts_ms: i64, pings: u16, salt: u64) -> pb::Round {
    let mut rtts: Vec<u32> = (0..u64::from(pings))
        .map(|k| 1000 + ((salt.wrapping_mul(2_654_435_761) ^ k.wrapping_mul(40_503)) % 1000) as u32)
        .collect();
    rtts.sort_unstable();
    pb::Round {
        seq,
        series_id,
        ts_ms,
        sent: u32::from(pings),
        rtts_us: rtts,
        ..Default::default()
    }
}
