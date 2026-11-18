//! A minimal SVG writer with fixed number formatting.

use std::fmt::Write as _;

#[derive(Debug)]
pub(crate) struct Doc {
    out: String,
}

impl Doc {
    pub(crate) fn new(width: u32, height: u32) -> Self {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" \
             viewBox=\"0 0 {width} {height}\" font-family=\"sans-serif\" font-size=\"11\">"
        );
        Self { out }
    }

    pub(crate) fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, attrs: &str) {
        rect_into(&mut self.out, x, y, w, h, attrs);
    }

    pub(crate) fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, attrs: &str) {
        let _ = writeln!(
            self.out,
            "<line x1=\"{x1:.1}\" y1=\"{y1:.1}\" x2=\"{x2:.1}\" y2=\"{y2:.1}\" {attrs}/>"
        );
    }

    pub(crate) fn text(&mut self, x: f64, y: f64, anchor: &str, attrs: &str, text: &str) {
        let sep = if attrs.is_empty() { "" } else { " " };
        let _ = writeln!(
            self.out,
            "<text x=\"{x:.1}\" y=\"{y:.1}\" text-anchor=\"{anchor}\"{sep}{attrs}>{}</text>",
            escape(text)
        );
    }

    /// A `<g>` around pre-rendered elements; nothing when they are empty.
    pub(crate) fn group(&mut self, attrs: &str, body: &str) {
        if !body.is_empty() {
            let _ = write!(self.out, "<g {attrs}>\n{body}</g>\n");
        }
    }

    pub(crate) fn finish(mut self) -> String {
        self.out.push_str("</svg>\n");
        self.out
    }
}

pub(crate) fn rect_into(out: &mut String, x: f64, y: f64, w: f64, h: f64, attrs: &str) {
    let sep = if attrs.is_empty() { "" } else { " " };
    let _ = writeln!(
        out,
        "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{w:.1}\" height=\"{h:.1}\"{sep}{attrs}/>"
    );
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            // Not allowed in XML 1.0 (surrogates cannot occur in a `str`).
            c if c.is_control() || c == '\u{fffe}' || c == '\u{ffff}' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_escaped() {
        let mut d = Doc::new(10, 10);
        d.text(1.0, 2.0, "start", "", "a<b & \"c\"\u{1b}");
        assert!(d.finish().contains(">a&lt;b &amp; &quot;c&quot;</text>"));
        let mut d = Doc::new(10, 10);
        d.text(1.0, 2.0, "start", "", "x\u{fffe}y\u{ffff}z");
        assert!(d.finish().contains(">xyz</text>"));
    }
}
