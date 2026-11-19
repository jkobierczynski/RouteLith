//! Smoke graphs (architecture doc §7.1) drawn as SVG.
//!
//! Each column of the graph is one time bucket: one round when rounds are
//! wider than a pixel, several rounds when the range is long. A bucket's
//! RTT samples (the union of its rounds, reduced to at most [`QUANTILES`]
//! quantiles) are sorted and paired from the outside in, `(s[0], s[k-1])`,
//! `(s[1], s[k-2])`, …; each pair is drawn as a translucent band, so the
//! band is darkest where most samples lie and the outer pairs are lightest.
//! The median is a short line coloured by the bucket's loss, and a bucket
//! that lost every sample is a full-height light red bar.
//!
//! The SVG is written by hand rather than through a plotting library: the
//! output is small, has no font dependency and is byte-for-byte stable,
//! which the golden tests rely on.
#![forbid(unsafe_code)]

mod svg;

use std::fmt::Write as _;

/// At most this many samples per bucket are drawn (as quantiles).
pub const QUANTILES: usize = 20;

/// One round as the renderer needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Round<'a> {
    /// Round start, Unix milliseconds.
    pub ts_ms: i64,
    /// Samples sent.
    pub sent: u16,
    /// RTTs of the replies, ascending, microseconds.
    pub rtts_us: &'a [u32],
}

/// What to draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph<'a> {
    /// Shown at the top left, e.g. `gateway (v4)`.
    pub title: &'a str,
    /// Time range, Unix milliseconds, `from_ms < to_ms`.
    pub from_ms: i64,
    pub to_ms: i64,
    /// Round interval of the series; `None` to infer it from the rounds.
    pub step_ms: Option<i64>,
    /// Image size in pixels; at least [`MIN_WIDTH`](Self::MIN_WIDTH) by
    /// [`MIN_HEIGHT`](Self::MIN_HEIGHT) is drawn (smaller is enlarged).
    pub width: u32,
    pub height: u32,
}

impl Graph<'_> {
    pub const DEFAULT_WIDTH: u32 = 800;
    pub const DEFAULT_HEIGHT: u32 = 300;
    /// Smallest size that leaves room for the plot inside the margins.
    pub const MIN_WIDTH: u32 = 480;
    pub const MIN_HEIGHT: u32 = 160;
}

// Plot area margins.
const LEFT: f64 = 64.0;
/// Room the footer summary needs (about 60 characters at 11 px).
const SUMMARY_WIDTH: f64 = 380.0;
/// Width of the loss legend: label, five swatches and the 100 % swatch.
const LEGEND_WIDTH: f64 = 300.0;
const RIGHT: f64 = 16.0;
const TOP: f64 = 30.0;
const BOTTOM: f64 = 56.0;

/// Loss colour bands of the median line (§7.1): upper bound of the loss
/// ratio and colour.
const LOSS_COLOURS: [(f64, &str, &str); 5] = [
    (0.0, "#1a9641", "0"),
    (0.05, "#2b6cd4", "≤5"),
    (0.10, "#8e44ad", "≤10"),
    (0.20, "#e67e22", "≤20"),
    (1.0, "#d7191c", ">20"),
];
const ALL_LOST: &str = "#f4c2c2";
const SMOKE: &str = "#000000";
/// Total opacity of the smoke where every band overlaps.
const SMOKE_OPACITY: f64 = 0.6;

/// One drawn column.
#[derive(Debug, Clone, PartialEq)]
struct Bucket {
    start_ms: i64,
    sent: u32,
    /// Replies in the bucket.
    received: u32,
    /// Sorted, at most [`QUANTILES`] values, in ms: the smoke bands.
    samples: Vec<f64>,
    /// Median and 90th percentile of all replies (not of `samples`), ms.
    median: Option<f64>,
    p90: Option<f64>,
}

impl Bucket {
    fn loss_ratio(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        let received = self.received.min(self.sent);
        f64::from(self.sent - received) / f64::from(self.sent)
    }
}

/// Buckets of the graph, plus their width in ms.
fn buckets(rounds: &[Round<'_>], g: &Graph<'_>, plot_width: f64) -> (Vec<BucketAcc>, i64) {
    let range = g.to_ms.saturating_sub(g.from_ms).max(1);
    let step = g.step_ms.unwrap_or_else(|| infer_step(rounds)).max(1);
    // Wide enough that buckets are at least a pixel and hold whole rounds.
    #[allow(clippy::cast_possible_truncation)]
    let per_pixel = (range as f64 / plot_width).ceil() as i64;
    let width = (per_pixel.max(1) + step - 1) / step * step;
    let mut out: Vec<BucketAcc> = Vec::new();
    for r in rounds {
        if r.ts_ms < g.from_ms || r.ts_ms > g.to_ms {
            continue;
        }
        let start = r.ts_ms.div_euclid(width) * width;
        if out.last().is_none_or(|b| b.start_ms != start) {
            out.push(BucketAcc {
                start_ms: start,
                sent: 0,
                rtts_us: Vec::new(),
            });
        }
        let b = out.last_mut().expect("pushed above");
        b.sent += u32::from(r.sent);
        b.rtts_us.extend_from_slice(r.rtts_us);
    }
    (out, width)
}

/// A bucket being filled.
#[derive(Debug)]
struct BucketAcc {
    start_ms: i64,
    sent: u32,
    rtts_us: Vec<u32>,
}

/// The smallest gap between consecutive rounds, at most 5 minutes: a
/// series with missing rounds may show only long gaps, which must not
/// widen the columns over the rounds that are missing.
fn infer_step(rounds: &[Round<'_>]) -> i64 {
    rounds
        .windows(2)
        .map(|w| w[1].ts_ms - w[0].ts_ms)
        .filter(|&d| d > 0)
        .min()
        .unwrap_or(300_000)
        .min(300_000)
}

/// `samples` (sorted) reduced to `n` evenly spaced quantiles, nearest rank.
fn quantiles(samples: &[u32], n: usize) -> Vec<u32> {
    if samples.len() <= n {
        return samples.to_vec();
    }
    let len = samples.len();
    (0..n)
        .map(|i| {
            // Rank of quantile (i + 0.5) / n, so both ends are inside.
            let rank = ((2 * i + 1) * len) / (2 * n);
            samples[rank.min(len - 1)]
        })
        .collect()
}

/// Median of sorted microsecond values, in ms (mean of the middle two for
/// an even count).
fn median_ms(sorted: &[u32]) -> Option<f64> {
    let n = sorted.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(f64::from(sorted[n / 2]) / 1e3),
        _ => Some((f64::from(sorted[n / 2 - 1]) + f64::from(sorted[n / 2])) / 2e3),
    }
}

/// 90th percentile of sorted microsecond values (nearest rank), in ms.
fn p90_ms(sorted: &[u32]) -> Option<f64> {
    let n = sorted.len();
    (n > 0).then(|| f64::from(sorted[(n * 9).div_ceil(10) - 1]) / 1e3)
}

fn loss_colour(loss: f64) -> &'static str {
    LOSS_COLOURS
        .iter()
        .find(|(max, _, _)| loss <= *max + 1e-9)
        .map_or(LOSS_COLOURS[4].1, |(_, c, _)| c)
}

/// The power of ten at or below `v` (> 0), by repeated multiplication so
/// the result is the same on every platform (no libm).
fn decade(v: f64) -> f64 {
    let mut mag = 1.0;
    while mag > v {
        mag /= 10.0;
    }
    while mag * 10.0 <= v {
        mag *= 10.0;
    }
    mag
}

/// A "nice" tick step (1, 2, 2.5 or 5 × 10ⁿ) for about `ticks` divisions of `max`.
fn nice_step(max: f64, ticks: f64) -> f64 {
    let raw = (max / ticks).max(1e-6);
    let mag = decade(raw);
    let norm = raw / mag;
    let nice = if norm <= 1.0 {
        1.0
    } else if norm <= 2.0 {
        2.0
    } else if norm <= 2.5 {
        2.5
    } else if norm <= 5.0 {
        5.0
    } else {
        10.0
    };
    nice * mag
}

/// Draw the smoke graph of `rounds` (sorted by time) as an SVG document.
pub fn render(rounds: &[Round<'_>], g: &Graph<'_>) -> String {
    let (width, height) = (
        g.width.max(Graph::MIN_WIDTH),
        g.height.max(Graph::MIN_HEIGHT),
    );
    let (w, h) = (f64::from(width), f64::from(height));
    let (pw, ph) = (w - LEFT - RIGHT, h - TOP - BOTTOM);
    let range = g.to_ms.saturating_sub(g.from_ms).max(1) as f64;
    let (accs, bucket_ms) = buckets(rounds, g, pw);
    let buckets: Vec<Bucket> = accs
        .into_iter()
        .map(|b| {
            let mut all = b.rtts_us;
            all.sort_unstable();
            Bucket {
                start_ms: b.start_ms,
                sent: b.sent,
                samples: quantiles(&all, QUANTILES)
                    .into_iter()
                    .map(|us| f64::from(us) / 1e3)
                    .collect(),
                received: u32::try_from(all.len()).unwrap_or(u32::MAX),
                median: median_ms(&all),
                p90: p90_ms(&all),
            }
        })
        .collect();

    // Y range: the highest 90th-percentile sample of any bucket, so a few
    // outliers don't flatten the graph (they are clipped at the top).
    let top = buckets
        .iter()
        .filter_map(|b| b.p90)
        .fold(0.0, f64::max)
        .max(0.1);
    let tick = nice_step(top * 1.1, 4.0);
    let y_max = (top * 1.1 / tick).ceil() * tick;

    let x = |ms: i64| LEFT + (ms.saturating_sub(g.from_ms) as f64 / range) * pw;
    let y = |v: f64| TOP + ph - (v.min(y_max) / y_max) * ph;

    let mut s = svg::Doc::new(width, height);
    s.rect(0.0, 0.0, w, h, "fill=\"#ffffff\"");
    s.text(
        LEFT,
        20.0,
        "start",
        "font-size=\"14\" font-weight=\"bold\"",
        g.title,
    );

    // Grid and Y labels.
    let mut v = 0.0;
    while v <= y_max + tick / 2.0 {
        let yy = y(v);
        s.line(LEFT, yy, LEFT + pw, yy, "stroke=\"#e0e0e0\"");
        s.text(
            LEFT - 6.0,
            yy + 4.0,
            "end",
            "",
            &format!("{} ms", fmt_ms(v, tick)),
        );
        v += tick;
    }
    // X grid and labels.
    let (xstep, label): (i64, fn(i64) -> String) = x_ticks(g.to_ms.saturating_sub(g.from_ms));
    // Checked: times near the ends of i64 must stop the loop, not wrap.
    let mut t = g
        .from_ms
        .div_euclid(xstep)
        .checked_mul(xstep)
        .and_then(|t| t.checked_add(xstep));
    while let Some(tick) = t.filter(|&tick| tick < g.to_ms) {
        let xx = x(tick);
        s.line(xx, TOP, xx, TOP + ph, "stroke=\"#e0e0e0\"");
        s.text(xx, TOP + ph + 16.0, "middle", "", &label(tick));
        t = tick.checked_add(xstep);
    }

    // Columns.
    let mut smoke = String::new();
    let mut lost = String::new();
    let mut medians = String::new();
    for b in &buckets {
        let x0 = x(b.start_ms.max(g.from_ms));
        let x1 = x((b.start_ms + bucket_ms).min(g.to_ms));
        let bw = (x1 - x0).max(0.5).min(pw);
        // A round exactly at `to_ms` starts a bucket on the right border:
        // draw it just inside the plot.
        let x0 = x0.min(LEFT + pw - bw);
        let loss = b.loss_ratio();
        if b.samples.is_empty() {
            if b.sent > 0 {
                svg::rect_into(&mut lost, x0, TOP, bw, ph, "");
            }
            continue;
        }
        let k = b.samples.len();
        let pairs = k / 2;
        if pairs > 0 {
            let alpha = SMOKE_OPACITY / pairs as f64;
            for i in 0..pairs {
                let (lo, hi) = (b.samples[i], b.samples[k - 1 - i]);
                let (y0, y1) = (y(hi), y(lo));
                svg::rect_into(
                    &mut smoke,
                    x0,
                    y0,
                    bw,
                    (y1 - y0).max(0.5),
                    &format!("fill-opacity=\"{alpha:.3}\""),
                );
            }
        }
        if let Some(m) = b.median {
            let ym = y(m);
            let _ = writeln!(
                medians,
                "<line x1=\"{x0:.1}\" y1=\"{ym:.1}\" x2=\"{:.1}\" y2=\"{ym:.1}\" stroke=\"{}\"/>",
                x0 + bw,
                loss_colour(loss)
            );
        }
    }
    s.group(&format!("fill=\"{ALL_LOST}\""), &lost);
    s.group(&format!("fill=\"{SMOKE}\""), &smoke);
    s.group("stroke-width=\"2\"", &medians);
    s.rect(LEFT, TOP, pw, ph, "fill=\"none\" stroke=\"#808080\"");

    // Summary and legend.
    let sent: u64 = buckets.iter().map(|b| u64::from(b.sent)).sum();
    let received: u64 = buckets.iter().map(|b| u64::from(b.received)).sum();
    let meds: Vec<f64> = buckets.iter().filter_map(|b| b.median).collect();
    let summary = if sent == 0 {
        "no data in this range".to_string()
    } else {
        let loss = (sent - received.min(sent)) as f64 / sent as f64 * 100.0;
        let avg = if meds.is_empty() {
            "-".to_string()
        } else {
            format!("{:.2} ms", meds.iter().sum::<f64>() / meds.len() as f64)
        };
        format!("median RTT avg {avg}, loss {loss:.2} %, {sent} pings sent")
    };
    let ly = h - 12.0;
    s.text(LEFT, ly, "start", "", &summary);
    // The legend (LEGEND_WIDTH wide, right-aligned) shares the summary's
    // line when the plot has room for both, else it goes on the line above.
    let ly = if pw >= SUMMARY_WIDTH + LEGEND_WIDTH {
        ly
    } else {
        ly - 14.0
    };
    let mut lx = LEFT + pw - LEGEND_WIDTH;
    s.text(lx, ly, "start", "", "loss %:");
    lx += 46.0;
    for (_, colour, name) in LOSS_COLOURS {
        s.rect(lx, ly - 9.0, 10.0, 10.0, &format!("fill=\"{colour}\""));
        s.text(lx + 13.0, ly, "start", "", name);
        lx += 40.0;
    }
    s.rect(lx, ly - 9.0, 10.0, 10.0, &format!("fill=\"{ALL_LOST}\""));
    s.text(lx + 13.0, ly, "start", "", "100");
    s.text(w - RIGHT, 20.0, "end", "fill=\"#606060\"", &range_label(g));
    s.finish()
}

/// Y label: as many decimals as the tick step needs.
fn fmt_ms(v: f64, tick: f64) -> String {
    let mut decimals = 0;
    let mut scaled = tick;
    while decimals < 6 && (scaled - scaled.round()).abs() > 1e-9 {
        scaled *= 10.0;
        decimals += 1;
    }
    format!("{v:.decimals$}")
}

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;

/// X tick spacing and label format for a range length.
fn x_ticks(range_ms: i64) -> (i64, fn(i64) -> String) {
    if range_ms <= 6 * HOUR_MS {
        (30 * 60_000, hhmm)
    } else if range_ms <= 2 * DAY_MS {
        (3 * HOUR_MS, hhmm)
    } else {
        (DAY_MS, mmdd)
    }
}

fn hhmm(ms: i64) -> String {
    let m = ms.div_euclid(60_000).rem_euclid(24 * 60);
    format!("{:02}:{:02}", m / 60, m % 60)
}

fn mmdd(ms: i64) -> String {
    let (_, m, d) = civil(ms.div_euclid(DAY_MS));
    format!("{m:02}-{d:02}")
}

fn range_label(g: &Graph<'_>) -> String {
    let f = |ms: i64| {
        let (y, m, d) = civil(ms.div_euclid(DAY_MS));
        format!("{y:04}-{m:02}-{d:02} {}", hhmm(ms))
    };
    format!("{} to {} UTC", f(g.from_ms), f(g.to_ms))
}

/// Year, month, day of a day number since 1970-01-01 (H. Hinnant).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_keep_both_ends_inside() {
        let s: Vec<u32> = (0..100).collect();
        let q = quantiles(&s, 20);
        assert_eq!(q.len(), 20);
        assert_eq!((q[0], q[19]), (2, 97));
        assert_eq!(quantiles(&[1, 2, 3], 20), [1, 2, 3]);
    }

    #[test]
    fn loss_colours_follow_the_doc() {
        assert_eq!(loss_colour(0.0), "#1a9641");
        assert_eq!(loss_colour(0.05), "#2b6cd4");
        assert_eq!(loss_colour(0.06), "#8e44ad");
        assert_eq!(loss_colour(0.2), "#e67e22");
        assert_eq!(loss_colour(0.21), "#d7191c");
    }

    #[test]
    fn nice_steps() {
        assert_eq!(nice_step(10.0, 4.0), 2.5);
        assert_eq!(nice_step(1.0, 4.0), 0.25);
        assert_eq!(nice_step(70.0, 4.0), 20.0);
        assert_eq!(fmt_ms(0.75, 0.25), "0.75");
        assert_eq!(fmt_ms(20.0, 5.0), "20");
        assert_eq!(fmt_ms(0.4, 0.2), "0.4");
    }

    #[test]
    fn dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_410), (2025, 11, 18));
        assert_eq!(hhmm(90 * 60_000), "01:30");
    }

    #[test]
    fn buckets_hold_whole_rounds() {
        let rtts = [1000u32];
        let rounds: Vec<Round<'_>> = (0..40)
            .map(|i| Round {
                ts_ms: i * 300_000 + 7_000,
                sent: 1,
                rtts_us: &rtts,
            })
            .collect();
        let g = Graph {
            title: "t",
            from_ms: 0,
            to_ms: 12_000_000,
            step_ms: None,
            width: 800,
            height: 300,
        };
        let (b, width) = buckets(&rounds, &g, 720.0);
        assert_eq!(width, 300_000);
        assert_eq!(b.len(), 40);
        let long = Graph {
            to_ms: 10 * DAY_MS,
            ..g
        };
        assert_eq!(buckets(&rounds, &long, 720.0).1, 1_200_000);
    }

    #[test]
    fn median_and_p90_use_every_reply() {
        // 51 at 1 ms and 49 at 100 ms: the median is 1 ms, although the
        // two middle smoke samples are 1 ms and 100 ms.
        let mut all = vec![1_000u32; 51];
        all.extend([100_000; 49]);
        assert_eq!(median_ms(&all), Some(1.0));
        // 90 at 1 ms and 10 at 100 ms: p90 is 1 ms.
        let mut all = vec![1_000u32; 90];
        all.extend([100_000; 10]);
        assert_eq!(p90_ms(&all), Some(1.0));
        assert_eq!(p90_ms(&[5_000]), Some(5.0));
        assert_eq!(median_ms(&[1_000, 2_000]), Some(1.5));
        assert_eq!(p90_ms(&[]), None);
    }

    fn rects(svg: &str) -> Vec<(f64, f64, f64, f64)> {
        let attr = |t: &str, name: &str| -> f64 {
            let i = t.find(&format!(" {name}=\"")).unwrap() + name.len() + 3;
            t[i..i + t[i..].find('"').unwrap()].parse().unwrap()
        };
        svg.split("<rect")
            .skip(1)
            .map(|t| {
                (
                    attr(t, "x"),
                    attr(t, "y"),
                    attr(t, "width"),
                    attr(t, "height"),
                )
            })
            .collect()
    }

    #[test]
    fn a_round_at_the_end_is_drawn_inside_the_plot() {
        let rtts = [1_000u32, 2_000, 3_000];
        let rounds = [Round {
            ts_ms: 3_600_000,
            sent: 3,
            rtts_us: &rtts,
        }];
        let g = Graph {
            title: "t",
            from_ms: 0,
            to_ms: 3_600_000,
            step_ms: Some(300_000),
            width: 800,
            height: 300,
        };
        let right = 800.0 - RIGHT;
        let svg = render(&rounds, &g);
        // The smoke bands (the background and frame are full size).
        let bands: Vec<_> = rects(&svg).into_iter().filter(|r| r.2 < 100.0).collect();
        assert!(!bands.is_empty());
        for (x, _, w, _) in bands {
            assert!(x >= LEFT && x + w <= right + 0.05, "{x} + {w}");
        }
    }

    #[test]
    fn times_at_the_ends_of_i64_do_not_wrap() {
        for (from_ms, to_ms) in [
            (i64::MAX - 3 * 3_600_000, i64::MAX),
            (i64::MIN, i64::MIN + 3 * 3_600_000),
            (i64::MIN, i64::MAX),
        ] {
            let g = Graph {
                title: "t",
                from_ms,
                to_ms,
                step_ms: Some(300_000),
                width: Graph::DEFAULT_WIDTH,
                height: Graph::DEFAULT_HEIGHT,
            };
            let svg = render(&[], &g);
            assert!(svg.len() < 100_000, "{} bytes", svg.len());
        }
    }

    #[test]
    fn tiny_images_are_enlarged_to_fit_the_plot() {
        let rtts = [1_000u32];
        let rounds = [Round {
            ts_ms: 60_000,
            sent: 1,
            rtts_us: &rtts,
        }];
        let g = Graph {
            title: "t",
            from_ms: 0,
            to_ms: 3_600_000,
            step_ms: Some(300_000),
            width: 80,
            height: 80,
        };
        let svg = render(&rounds, &g);
        assert!(svg.contains(&format!("width=\"{}\"", Graph::MIN_WIDTH)));
        let width = f64::from(Graph::MIN_WIDTH);
        for (x, _, w, h) in rects(&svg) {
            assert!(w > 0.0 && h > 0.0, "{w} x {h}");
            assert!(x >= 0.0 && x + w <= width, "rect at {x}, {w} wide");
        }
        // The legend moved above the summary, whose line it would overlap.
        let summary_y = format!("y=\"{:.1}\"", f64::from(Graph::MIN_HEIGHT) - 12.0);
        let legend = svg.find("loss %:").unwrap();
        let line = &svg[svg[..legend].rfind('<').unwrap()..legend];
        assert!(!line.contains(&summary_y), "{line}");
    }
}
