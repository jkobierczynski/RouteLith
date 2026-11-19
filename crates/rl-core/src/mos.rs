//! Voice quality estimate: the ITU-T G.107 E-model (06/2015), with every
//! parameter at its G.107 default except delay and packet loss, and a G.711
//! codec with packet-loss concealment (architecture doc §19, §21.3 E11).
//!
//! The E-model rates a telephone connection from its impairments:
//!
//! ```text
//! R = Ro − Is − Id − Ie,eff + A
//! ```
//!
//! `Ro − Is` (noise and simultaneous impairments) comes to 93.2 with the
//! defaults, `Id` grows with delay (talker echo, listener echo and plain
//! too-much-delay), and `Ie,eff` grows with packet loss. `R` maps to a
//! mean opinion score between 1 and 4.5 (G.107 Annex B).
//!
//! What a monitoring round gives is a network round-trip time, not a
//! mouth-to-ear delay, so a round's one-way delay is estimated as half the
//! median RTT, plus a jitter buffer sized to the spread of the samples
//! (90th percentile minus minimum), plus one 20 ms G.711 packet.

/// G.711 packetisation: one 20 ms frame per packet.
pub const PACKET_MS: f64 = 20.0;
/// G.711 with packet-loss concealment (G.113 Appendix I).
pub const G711_IE: f64 = 0.0;
pub const G711_BPL: f64 = 25.1;

/// G.107 default parameters (Table 3).
const SLR: f64 = 8.0;
const RLR: f64 = 2.0;
const STMR: f64 = 15.0;
const LSTR: f64 = 18.0;
const DS: f64 = 3.0;
const TELR: f64 = 65.0;
const WEPL: f64 = 110.0;
const QDU: f64 = 1.0;
const NC: f64 = -70.0;
const NFOR: f64 = -64.0;
const PS: f64 = 35.0;
const PR: f64 = 35.0;
const A: f64 = 0.0;

/// The transmission rating factor `R` for a connection whose mean one-way
/// delay is `delay_ms` (taken as `T` and `Ta`, with `Tr = 2T`, as for a
/// connection without separate echo paths), losing `loss_pct` percent of
/// packets at random (`BurstR = 1`), with equipment impairment `ie` and
/// loss robustness `bpl`.
pub fn r_factor(delay_ms: f64, loss_pct: f64, ie: f64, bpl: f64) -> f64 {
    let t = delay_ms.max(0.0);
    let ta = t;
    let tr = 2.0 * t;
    let ppl = loss_pct.clamp(0.0, 100.0);

    // Basic signal-to-noise ratio, Ro (§7.2).
    let olr = SLR + RLR;
    let nos = PS - SLR - DS - 100.0 + 0.004 * (PS - olr - DS - 14.0).powi(2);
    let pre = PR + 10.0 * (1.0 + 10f64.powf((10.0 - LSTR) / 10.0)).log10();
    let nor = RLR - 121.0 + pre + 0.008 * (pre - 35.0).powi(2);
    let nfo = NFOR + RLR;
    let no = 10.0
        * (10f64.powf(NC / 10.0)
            + 10f64.powf(nos / 10.0)
            + 10f64.powf(nor / 10.0)
            + 10f64.powf(nfo / 10.0))
        .log10();
    let ro = 15.0 - 1.5 * (SLR + no);

    // Simultaneous impairments, Is = Iolr + Ist + Iq (§7.3).
    let xolr = olr + 0.2 * (64.0 + no - RLR);
    let iolr = 20.0 * ((1.0 + (xolr / 8.0).powi(8)).powf(1.0 / 8.0) - xolr / 8.0);
    let stmro =
        -10.0 * (10f64.powf(-STMR / 10.0) + (-t / 4.0).exp() * 10f64.powf(-TELR / 10.0)).log10();
    let ist = 12.0 * (1.0 + ((stmro - 13.0) / 6.0).powi(8)).powf(1.0 / 8.0)
        - 28.0 * (1.0 + ((stmro + 1.0) / 19.4).powi(35)).powf(1.0 / 35.0)
        - 13.0 * (1.0 + ((stmro - 3.0) / 33.0).powi(13)).powf(1.0 / 13.0)
        + 29.0;
    let q = 37.0 - 15.0 * QDU.log10();
    let g = 1.07 + 0.258 * q + 0.0602 * q * q;
    let y = (ro - 100.0) / 15.0 + 46.0 / 8.4 - g / 9.0;
    let z = 46.0 / 30.0 - g / 40.0;
    let iq = 15.0 * (1.0 + 10f64.powf(y) + 10f64.powf(z)).log10();
    let is = iolr + ist + iq;

    // Delay impairments, Id = Idte + Idle + Idd (§7.4).
    let terv =
        TELR - 40.0 * ((1.0 + t / 10.0) / (1.0 + t / 150.0)).log10() + 6.0 * (-0.3 * t * t).exp();
    let roe = -1.5 * (no + RLR);
    let re = 80.0 + 2.5 * (terv - 14.0);
    let idte =
        ((roe - re) / 2.0 + ((roe - re).powi(2) / 4.0 + 100.0).sqrt() - 1.0) * (1.0 - (-t).exp());
    let rle = 10.5 * (WEPL + 7.0) * (tr + 1.0).powf(-0.25);
    let idle = (ro - rle) / 2.0 + ((ro - rle).powi(2) / 4.0 + 169.0).sqrt();
    let idd = if ta <= 100.0 {
        0.0
    } else {
        let x = (ta / 100.0).log2();
        25.0 * ((1.0 + x.powi(6)).powf(1.0 / 6.0) - 3.0 * (1.0 + (x / 3.0).powi(6)).powf(1.0 / 6.0)
            + 2.0)
    };
    let id = idte + idle + idd;

    // Equipment impairment with random loss, Ie,eff (§7.5).
    let ie_eff = ie + (95.0 - ie) * ppl / (ppl + bpl);

    ro - is - id - ie_eff + A
}

/// Mean opinion score (conversational quality) for a rating `r`
/// (G.107 Annex B, Equation B-4).
pub fn mos_from_r(r: f64) -> f64 {
    if r <= 0.0 {
        1.0
    } else if r >= 100.0 {
        4.5
    } else {
        1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6
    }
}

/// MOS of one round: the median and spread of its RTTs (microseconds) and
/// its loss ratio (0 to 1). `None` when nothing was received.
pub fn round_mos(min_us: u32, median_us: u32, p90_us: u32, loss: f64) -> Option<f64> {
    if loss >= 1.0 {
        return None;
    }
    let one_way = f64::from(median_us) / 2e3;
    let jitter_buffer = f64::from(p90_us.saturating_sub(min_us)) / 1e3;
    let delay = one_way + jitter_buffer + PACKET_MS;
    Some(mos_from_r(r_factor(delay, loss * 100.0, G711_IE, G711_BPL)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn defaults_give_r_93_2() {
        // G.107 §7.7: the default values give R = 93.2.
        let r = r_factor(0.0, 0.0, 0.0, 1.0);
        assert!(close(r, 93.2, 0.05), "{r}");
        assert!(close(mos_from_r(r), 4.41, 0.01), "{}", mos_from_r(r));
    }

    #[test]
    fn mos_mapping_end_points() {
        assert_eq!(mos_from_r(-5.0), 1.0);
        assert_eq!(mos_from_r(120.0), 4.5);
        // Annex B, Table B.1 boundaries: R 90 / 80 / 70 / 60 / 50.
        for (r, mos) in [
            (90.0, 4.34),
            (80.0, 4.03),
            (70.0, 3.60),
            (60.0, 3.10),
            (50.0, 2.58),
        ] {
            assert!(close(mos_from_r(r), mos, 0.01), "R {r}: {}", mos_from_r(r));
        }
    }

    #[test]
    fn random_loss_uses_bpl() {
        // Ie,eff = Ie + (95 − Ie) · Ppl / (Ppl + Bpl): G.711 with PLC at
        // 2 % loss loses 95 · 2 / 27.1 = 7.01 from the default 93.2.
        let r = r_factor(0.0, 2.0, G711_IE, G711_BPL);
        assert!(close(r, 93.21 - 95.0 * 2.0 / 27.1, 0.01), "{r}");
    }

    #[test]
    fn delay_curve() {
        // Regression values of this implementation (defaults, no loss).
        // Not yet cross-checked against the ITU online E-model calculator,
        // which this project's CI cannot reach.
        for (t, r) in [
            (0.0, 93.21),
            (100.0, 91.08),
            (150.0, 90.19),
            (200.0, 86.67),
            (300.0, 73.93),
            (400.0, 63.82),
        ] {
            let got = r_factor(t, 0.0, 0.0, 1.0);
            assert!(close(got, r, 0.01), "T {t}: {got}");
        }
        // Monotonic: more delay never rates better.
        let mut last = f64::INFINITY;
        for t in (0..1000).step_by(5) {
            let r = r_factor(f64::from(t), 0.0, 0.0, 1.0);
            assert!(r <= last + 1e-9, "T {t}");
            last = r;
        }
    }

    #[test]
    fn a_lost_round_has_no_mos() {
        assert_eq!(round_mos(0, 0, 0, 1.0), None);
        let lan = round_mos(300, 400, 600, 0.0).unwrap();
        assert!(lan > 4.39 && lan <= 4.41, "{lan}");
    }
}
