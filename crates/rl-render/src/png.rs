//! PNG output (architecture doc §7.2, §21.5 F9): the SVG of [`render`]
//! rasterised with resvg, so a PNG (for e-mail and reports) looks like the
//! SVG and the UI. The SVG asks for `sans-serif`; an embedded Liberation
//! Sans (SIL Open Font License, see `fonts/OFL.txt`) answers, so the
//! result does not depend on the fonts of the machine.
//!
//! [`render`]: crate::render

use std::sync::{Arc, OnceLock};

use resvg::{tiny_skia, usvg};

const FONT: &[u8] = include_bytes!("../fonts/LiberationSans-Regular.ttf");
const FAMILY: &str = "Liberation Sans";

/// Largest pixel count a PNG may have (a 4000 × 4000 image), so a request
/// cannot ask for gigabytes.
pub const MAX_PIXELS: u64 = 16_000_000;

fn options() -> &'static usvg::Options<'static> {
    static OPTIONS: OnceLock<usvg::Options<'static>> = OnceLock::new();
    OPTIONS.get_or_init(|| {
        let mut db = usvg::fontdb::Database::new();
        db.load_font_data(FONT.to_vec());
        db.set_sans_serif_family(FAMILY);
        db.set_serif_family(FAMILY);
        db.set_monospace_family(FAMILY);
        usvg::Options {
            font_family: FAMILY.to_string(),
            fontdb: Arc::new(db),
            ..usvg::Options::default()
        }
    })
}

/// Rasterise an SVG document (as [`render`](crate::render) writes it) at
/// `scale` (1 or more; 2 for high-density screens) on a white background.
pub fn svg_to_png(svg: &str, scale: f32) -> Result<Vec<u8>, String> {
    if !(scale.is_finite() && (0.25..=8.0).contains(&scale)) {
        return Err(format!("scale {scale} is outside 0.25 to 8"));
    }
    let tree = usvg::Tree::from_str(svg, options()).map_err(|e| e.to_string())?;
    let size = tree
        .size()
        .to_int_size()
        .scale_by(scale)
        .ok_or("empty image")?;
    if u64::from(size.width()) * u64::from(size.height()) > MAX_PIXELS {
        return Err(format!(
            "{} × {} pixels is more than a PNG may have",
            size.width(),
            size.height()
        ));
    }
    let mut pixmap =
        tiny_skia::Pixmap::new(size.width(), size.height()).ok_or("cannot allocate the image")?;
    pixmap.fill(tiny_skia::Color::WHITE);
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    pixmap.encode_png().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Graph, Round};

    fn decode(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
        let mut reader = png::Decoder::new(std::io::Cursor::new(bytes))
            .read_info()
            .unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(info.color_type, png::ColorType::Rgba);
        buf.truncate(info.buffer_size());
        (info.width, info.height, buf)
    }

    fn graph_svg() -> String {
        let rtts: Vec<Vec<u32>> = (0..36)
            .map(|i| (0..20).map(|j| 10_000 + i * 50 + j * 400).collect())
            .collect();
        let rounds: Vec<Round<'_>> = rtts
            .iter()
            .enumerate()
            .map(|(i, r)| Round {
                ts_ms: 1_800_000_000_000 + i as i64 * 300_000,
                sent: 20,
                rtts_us: r,
            })
            .collect();
        crate::render(
            &rounds,
            &Graph {
                title: "gateway (v4)",
                from_ms: 1_800_000_000_000,
                to_ms: 1_800_000_000_000 + 3 * 3_600_000,
                step_ms: Some(300_000),
                width: Graph::DEFAULT_WIDTH,
                height: Graph::DEFAULT_HEIGHT,
                totals: None,
            },
        )
    }

    #[test]
    fn the_png_has_the_graph_text_and_smoke() {
        let png = svg_to_png(&graph_svg(), 1.0).unwrap();
        let (w, h, px) = decode(&png);
        assert_eq!((w, h), (Graph::DEFAULT_WIDTH, Graph::DEFAULT_HEIGHT));
        let pixels: Vec<&[u8]> = px.chunks(4).collect();
        assert!(pixels.iter().all(|p| p[3] == 255), "opaque");
        // The loss-0 median line is green; smoke is grey; text is dark.
        let green = pixels
            .iter()
            .filter(|p| {
                let [r, g, b] = [p[0], p[1], p[2]].map(i32::from);
                g > 100 && g > r + 50 && g > b + 50
            })
            .count();
        assert!(green > 20, "median lines ({green} px)");
        // Smoke: the same graph without its smoke group, so the border,
        // grid and labels (grey too) are in both and cancel out.
        let svg = graph_svg();
        let start = svg.find("<g fill=\"#000000\">").expect("a smoke group");
        let end = start + svg[start..].find("</g>\n").unwrap() + "</g>\n".len();
        let bare = format!("{}{}", &svg[..start], &svg[end..]);
        let (_, _, without) = decode(&svg_to_png(&bare, 1.0).unwrap());
        let smoke = px
            .chunks(4)
            .zip(without.chunks(4))
            .filter(|(a, b)| a[0] == a[1] && a[1] == a[2] && i32::from(a[0]) + 20 < i32::from(b[0]))
            .count();
        assert!(smoke > 2_000, "smoke ({smoke} px)");
        // Text: the title's top-left corner has dark pixels from glyphs.
        let dark_top = pixels[..(w as usize * 30)]
            .iter()
            .filter(|p| p[0] < 100 && p[1] < 100 && p[2] < 100)
            .count();
        assert!(dark_top > 50, "title text drawn ({dark_top} px)");
    }

    #[test]
    fn scale_doubles_the_size_and_bounds_are_checked() {
        let svg = graph_svg();
        let (w, h, _) = decode(&svg_to_png(&svg, 2.0).unwrap());
        assert_eq!(
            (w, h),
            (2 * Graph::DEFAULT_WIDTH, 2 * Graph::DEFAULT_HEIGHT)
        );
        assert!(svg_to_png(&svg, 0.0).is_err());
        assert!(svg_to_png(&svg, f32::NAN).is_err());
        let big = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"3000\" height=\"3000\"/>";
        assert!(svg_to_png(big, 1.0).is_ok());
        assert!(svg_to_png(big, 2.0).is_err(), "too many pixels");
        assert!(svg_to_png("<svg", 1.0).is_err());
    }

    #[test]
    fn an_800_by_250_graph_renders_quickly() {
        let svg = graph_svg();
        let _ = svg_to_png(&svg, 1.0).unwrap(); // warm the font database
        let started = std::time::Instant::now();
        for _ in 0..5 {
            svg_to_png(&svg, 1.0).unwrap();
        }
        let each = started.elapsed() / 5;
        // §18 asks for 30 ms in a release build; a debug build is slower.
        let limit = if cfg!(debug_assertions) { 1_000 } else { 30 };
        assert!(each.as_millis() < limit, "{each:?} per PNG");
    }
}
