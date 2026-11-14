//! Static SVG figures, written without any plotting dependency.
//!
//! Conventions: one y-axis per panel (two measures get two panels); bars at
//! most 24 px wide with a rounded data end and a 2 px surface gap; 2 px
//! lines with ringed markers; a legend whenever there are two or more
//! series; text in ink colours, never the series colour. Each mark carries
//! a `<title>` so a browser shows its value on hover. Colours follow the
//! viewer's light or dark preference.

use std::fmt::Write as _;

/// One mark: a value with an optional interval.
#[derive(Debug, Clone, PartialEq)]
pub struct Value {
    pub y: f64,
    pub low: Option<f64>,
    pub high: Option<f64>,
    /// Shown on hover.
    pub tip: String,
}

/// A named series. `slot` picks the colour and must stay the same for the
/// same entity in every figure.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub name: String,
    pub slot: usize,
    /// For bar panels: one entry per category (`None` leaves a gap).
    /// For line panels: one entry per x position.
    pub values: Vec<Option<Value>>,
    /// Scatter panels only: text labels next to chosen points.
    pub callouts: Vec<(usize, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// Grouped bars over named categories.
    Bars { categories: Vec<String> },
    /// Lines over numeric x positions with tick labels.
    Lines {
        x: Vec<f64>,
        x_ticks: Vec<String>,
        x_label: String,
    },
    /// Unconnected points with their own x positions per series, plus one
    /// connected series. Used for the risk-coverage figure.
    Scatter {
        x_label: String,
        /// x positions parallel to each series' values.
        xs: Vec<Vec<f64>>,
        /// Index of the series whose points are joined by a line.
        connect: Option<usize>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Panel {
    pub heading: String,
    pub y_label: String,
    pub kind: Kind,
    pub series: Vec<Series>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Figure {
    pub title: String,
    /// One or more lines, separated by `\n`.
    pub subtitle: String,
    pub panels: Vec<Panel>,
}

const WIDTH: f64 = 960.0;
const LEFT: f64 = 76.0;
const RIGHT: f64 = 28.0;
const PANEL_HEIGHT: f64 = 250.0;

const STYLE: &str = r#"
  .bg{fill:#fcfcfb}.t1{fill:#0b0b0b}.t2{fill:#52514e}.t3{fill:#898781}
  .grid{stroke:#e1e0d9;stroke-width:1}.axis{stroke:#c3c2b7;stroke-width:1}
  .err{stroke:#52514e;stroke-width:1}.ring{stroke:#fcfcfb;stroke-width:2}
  .s0{fill:#2a78d6}.s1{fill:#eb6834}.s2{fill:#1baf7a}.s3{fill:#898781}
  .l0{stroke:#2a78d6}.l1{stroke:#eb6834}.l2{stroke:#1baf7a}.l3{stroke:#898781}
  .line{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
  text{font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
  .title{font-size:16px;font-weight:600}.sub{font-size:12px}.h{font-size:13px;font-weight:600}
  .tick{font-size:11px;font-variant-numeric:tabular-nums}.lab{font-size:11px}
  @media (prefers-color-scheme: dark){
    .bg{fill:#1a1a19}.t1{fill:#ffffff}.t2{fill:#c3c2b7}.t3{fill:#898781}
    .grid{stroke:#2c2c2a}.axis{stroke:#383835}.err{stroke:#c3c2b7}.ring{stroke:#1a1a19}
    .s0{fill:#3987e5}.s1{fill:#d95926}.s2{fill:#199e70}
    .l0{stroke:#3987e5}.l1{stroke:#d95926}.l2{stroke:#199e70}
  }
"#;

fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A round upper bound for an axis, and a round step between its ticks.
fn nice_axis(max: f64) -> (f64, f64) {
    if max.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return (1.0, 0.25);
    }
    let magnitude = 10f64.powf(max.log10().floor());
    // (top, step) in units of the magnitude: every tick is a round number.
    for (top, step) in [(1.0, 0.25), (2.0, 0.5), (2.5, 0.5), (5.0, 1.0), (10.0, 2.5)] {
        if top * magnitude >= max {
            return (top * magnitude, step * magnitude);
        }
    }
    (10.0 * magnitude, 2.5 * magnitude)
}

/// Round tick positions covering `[low, high]`, at most about eight.
fn nice_ticks(low: f64, high: f64) -> Vec<f64> {
    let span = (high - low).max(1e-9);
    let step = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5]
        .into_iter()
        .find(|step| span / step <= 8.0)
        .unwrap_or(1.0);
    let first = (low / step).floor() as i64;
    let last = (high / step).ceil() as i64;
    (first..=last).map(|k| k as f64 * step).collect()
}

/// Format a ratio as a percentage with only as many decimals as needed.
pub fn percent(value: f64) -> String {
    let p = value * 100.0;
    if p == 0.0 {
        "0%".to_string()
    } else if p.abs() >= 10.0 {
        format!("{p:.0}%")
    } else if p.abs() >= 1.0 {
        format!("{p:.1}%")
    } else if p.abs() >= 0.1 {
        format!("{p:.2}%")
    } else {
        format!("{p:.3}%")
    }
}

struct Frame {
    top: f64,
    bottom: f64,
    y_max: f64,
}

impl Frame {
    fn y(&self, value: f64) -> f64 {
        self.bottom - (value / self.y_max).clamp(0.0, 1.0) * (self.bottom - self.top)
    }
}

fn panel_max(panel: &Panel) -> f64 {
    panel
        .series
        .iter()
        .flat_map(|s| s.values.iter().flatten())
        .map(|v| v.high.unwrap_or(v.y).max(v.y))
        .fold(0.0, f64::max)
}

fn legend(out: &mut String, series: &[Series], y: f64) {
    let mut x = LEFT;
    for s in series {
        let _ = write!(
            out,
            r#"<rect class="s{}" x="{x:.1}" y="{:.1}" width="10" height="10" rx="2"/><text class="t2 lab" x="{:.1}" y="{:.1}">{}</text>"#,
            s.slot,
            y - 9.0,
            x + 15.0,
            y,
            esc(&s.name)
        );
        x += 15.0 + 6.4 * s.name.len() as f64 + 22.0;
    }
}

fn axes(out: &mut String, frame: &Frame, y_label: &str) {
    let (_, step) = nice_axis(frame.y_max);
    let mut tick = 0.0;
    while tick <= frame.y_max * 1.0001 {
        let y = frame.y(tick);
        let class = if tick == 0.0 { "axis" } else { "grid" };
        let _ = write!(
            out,
            r#"<line class="{class}" x1="{LEFT}" x2="{:.1}" y1="{y:.1}" y2="{y:.1}"/><text class="t3 tick" x="{:.1}" y="{:.1}" text-anchor="end">{}</text>"#,
            WIDTH - RIGHT,
            LEFT - 8.0,
            y + 4.0,
            percent(tick)
        );
        tick += step;
    }
    let mid = (frame.top + frame.bottom) / 2.0;
    let _ = write!(
        out,
        r#"<text class="t2 lab" transform="translate(16 {mid:.1}) rotate(-90)" text-anchor="middle">{}</text>"#,
        esc(y_label)
    );
}

fn error_bar(out: &mut String, frame: &Frame, x: f64, value: &Value) {
    if let (Some(low), Some(high)) = (value.low, value.high) {
        if high > low {
            let (y1, y2) = (frame.y(low), frame.y(high));
            let _ = write!(
                out,
                r#"<line class="err" x1="{x:.1}" x2="{x:.1}" y1="{y1:.1}" y2="{y2:.1}"/><line class="err" x1="{:.1}" x2="{:.1}" y1="{y2:.1}" y2="{y2:.1}"/><line class="err" x1="{:.1}" x2="{:.1}" y1="{y1:.1}" y2="{y1:.1}"/>"#,
                x - 3.0,
                x + 3.0,
                x - 3.0,
                x + 3.0
            );
        }
    }
}

fn bars(out: &mut String, frame: &Frame, categories: &[String], series: &[Series]) {
    let plot = WIDTH - LEFT - RIGHT;
    let band = plot / categories.len().max(1) as f64;
    let gap = 2.0;
    let count = series.len().max(1) as f64;
    let bar = ((band * 0.72 - gap * (count - 1.0)) / count).clamp(3.0, 24.0);
    let group = bar * count + gap * (count - 1.0);
    for (c, category) in categories.iter().enumerate() {
        let centre = LEFT + band * (c as f64 + 0.5);
        for (i, s) in series.iter().enumerate() {
            let Some(Some(value)) = s.values.get(c) else {
                continue;
            };
            let x = centre - group / 2.0 + (bar + gap) * i as f64;
            let y = frame.y(value.y);
            let height = (frame.bottom - y).max(0.0);
            // Rounded at the data end, square at the baseline.
            let r = 4f64.min(bar / 2.0).min(height);
            let _ = write!(
                out,
                r#"<path class="s{}" d="M{x:.1} {:.1}V{:.1}Q{x:.1} {y:.1} {:.1} {y:.1}H{:.1}Q{:.1} {y:.1} {:.1} {:.1}V{:.1}Z"><title>{}</title></path>"#,
                s.slot,
                frame.bottom,
                y + r,
                x + r,
                x + bar - r,
                x + bar,
                x + bar,
                y + r,
                frame.bottom,
                esc(&value.tip)
            );
            error_bar(out, frame, x + bar / 2.0, value);
        }
        let _ = write!(
            out,
            r#"<text class="t2 lab" transform="translate({centre:.1} {:.1}) rotate(-28)" text-anchor="end">{}</text>"#,
            frame.bottom + 14.0,
            esc(category)
        );
    }
}

fn marker(out: &mut String, slot: usize, x: f64, y: f64, tip: &str) {
    let _ = write!(
        out,
        r#"<circle class="s{slot} ring" cx="{x:.1}" cy="{y:.1}" r="4.5"><title>{}</title></circle>"#,
        esc(tip)
    );
}

fn polyline(out: &mut String, slot: usize, points: &[(f64, f64)]) {
    if points.len() < 2 {
        return;
    }
    let path: Vec<String> = points
        .iter()
        .map(|(x, y)| format!("{x:.1},{y:.1}"))
        .collect();
    let _ = write!(
        out,
        r#"<polyline class="line l{slot}" points="{}"/>"#,
        path.join(" ")
    );
}

fn x_scale(xs: impl Iterator<Item = f64>) -> impl Fn(f64) -> f64 {
    let values: Vec<f64> = xs.collect();
    let low = values.iter().copied().fold(f64::INFINITY, f64::min);
    let high = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let span = if high > low { high - low } else { 1.0 };
    let inset = 24.0;
    move |x| LEFT + inset + (x - low) / span * (WIDTH - LEFT - RIGHT - 2.0 * inset)
}

fn x_axis_label(out: &mut String, frame: &Frame, label: &str) {
    let _ = write!(
        out,
        r#"<text class="t2 lab" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
        (LEFT + WIDTH - RIGHT) / 2.0,
        frame.bottom + 36.0,
        esc(label)
    );
}

fn lines(
    out: &mut String,
    frame: &Frame,
    x: &[f64],
    ticks: &[String],
    label: &str,
    series: &[Series],
) {
    let sx = x_scale(x.iter().copied());
    for (position, tick) in x.iter().zip(ticks) {
        let _ = write!(
            out,
            r#"<text class="t3 tick" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
            sx(*position),
            frame.bottom + 16.0,
            esc(tick)
        );
    }
    x_axis_label(out, frame, label);
    for s in series {
        let points: Vec<(f64, f64, &Value)> = s
            .values
            .iter()
            .zip(x)
            .filter_map(|(v, x)| v.as_ref().map(|v| (sx(*x), frame.y(v.y), v)))
            .collect();
        for (px, _, value) in &points {
            error_bar(out, frame, *px, value);
        }
        let path: Vec<(f64, f64)> = points.iter().map(|(x, y, _)| (*x, *y)).collect();
        polyline(out, s.slot, &path);
        for (px, py, value) in &points {
            marker(out, s.slot, *px, *py, &value.tip);
        }
    }
}

fn scatter(
    out: &mut String,
    frame: &Frame,
    label: &str,
    xs: &[Vec<f64>],
    connect: Option<usize>,
    series: &[Series],
) {
    let all: Vec<f64> = xs.iter().flatten().copied().collect();
    let low = all.iter().copied().fold(f64::INFINITY, f64::min);
    let high = all.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let ticks = nice_ticks(low, high);
    let sx = x_scale(ticks.iter().copied());
    for tick in &ticks {
        let _ = write!(
            out,
            r#"<text class="t3 tick" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
            sx(*tick),
            frame.bottom + 16.0,
            percent(*tick)
        );
    }
    x_axis_label(out, frame, label);
    for (i, s) in series.iter().enumerate() {
        let points: Vec<(f64, f64, &Value)> = s
            .values
            .iter()
            .zip(&xs[i])
            .filter_map(|(v, x)| v.as_ref().map(|v| (sx(*x), frame.y(v.y), v)))
            .collect();
        for (px, _, value) in &points {
            error_bar(out, frame, *px, value);
        }
        if connect == Some(i) {
            let path: Vec<(f64, f64)> = points.iter().map(|(x, y, _)| (*x, *y)).collect();
            polyline(out, s.slot, &path);
        }
        for (px, py, value) in &points {
            marker(out, s.slot, *px, *py, &value.tip);
        }
        for (index, text) in &s.callouts {
            if let Some((px, py, _)) = points.get(*index) {
                let _ = write!(
                    out,
                    r#"<text class="t1 lab" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
                    px,
                    py - 12.0,
                    esc(text)
                );
            }
        }
    }
}

impl Figure {
    /// Render the figure as a standalone SVG document.
    pub fn to_svg(&self) -> String {
        let subtitle: Vec<&str> = self.subtitle.lines().collect();
        let header = 48.0 + 16.0 * subtitle.len() as f64;
        // Bar panels need room below the axis for slanted category labels.
        let below = |panel: &Panel| match panel.kind {
            Kind::Bars { .. } => 104.0,
            _ => 64.0,
        };
        let height = header
            + self
                .panels
                .iter()
                .map(|p| 46.0 + PANEL_HEIGHT + below(p))
                .sum::<f64>();
        let mut out = String::new();
        let _ = write!(
            out,
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" height="{height}" role="img" aria-label="{}"><style>{STYLE}</style><rect class="bg" width="100%" height="100%"/>"#,
            esc(&self.title)
        );
        let _ = write!(
            out,
            r#"<text class="t1 title" x="{LEFT}" y="26">{}</text>"#,
            esc(&self.title)
        );
        for (i, line) in subtitle.iter().enumerate() {
            let _ = write!(
                out,
                r#"<text class="t2 sub" x="{LEFT}" y="{}">{}</text>"#,
                45 + 16 * i,
                esc(line)
            );
        }
        let mut origin = header;
        for panel in &self.panels {
            let frame = Frame {
                top: origin + 46.0,
                bottom: origin + 46.0 + PANEL_HEIGHT,
                y_max: nice_axis(panel_max(panel)).0,
            };
            let _ = write!(
                out,
                r#"<text class="t1 h" x="{LEFT}" y="{:.1}">{}</text>"#,
                origin + 14.0,
                esc(&panel.heading)
            );
            if panel.series.len() >= 2 {
                legend(&mut out, &panel.series, origin + 34.0);
            }
            axes(&mut out, &frame, &panel.y_label);
            match &panel.kind {
                Kind::Bars { categories } => bars(&mut out, &frame, categories, &panel.series),
                Kind::Lines {
                    x,
                    x_ticks,
                    x_label,
                } => lines(&mut out, &frame, x, x_ticks, x_label, &panel.series),
                Kind::Scatter {
                    x_label,
                    xs,
                    connect,
                } => scatter(&mut out, &frame, x_label, xs, *connect, &panel.series),
            }
            origin += 46.0 + PANEL_HEIGHT + below(panel);
        }
        out.push_str("</svg>\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(y: f64) -> Option<Value> {
        Some(Value {
            y,
            low: Some(y * 0.9),
            high: Some(y * 1.1),
            tip: format!("value {y}"),
        })
    }

    fn series(name: &str, slot: usize, ys: &[f64]) -> Series {
        Series {
            name: name.to_string(),
            slot,
            values: ys.iter().map(|y| value(*y)).collect(),
            callouts: Vec::new(),
        }
    }

    fn bar_figure() -> Figure {
        Figure {
            title: "A <title> & more".into(),
            subtitle: "subtitle".into(),
            panels: vec![Panel {
                heading: "heading".into(),
                y_label: "rate".into(),
                kind: Kind::Bars {
                    categories: vec!["one".into(), "two".into()],
                },
                series: vec![series("a", 0, &[0.2, 0.4]), series("b", 1, &[0.1, 0.0])],
            }],
        }
    }

    #[test]
    fn axis_bounds_are_round_and_cover_the_data() {
        assert_eq!(nice_axis(0.0), (1.0, 0.25));
        assert_eq!(nice_axis(0.83).0, 1.0);
        assert_eq!(nice_axis(0.42).0, 0.5);
        assert_eq!(nice_axis(0.019).0, 0.02);
        assert_eq!(nice_axis(0.30), (0.5, 0.1));
        assert_eq!(nice_axis(0.62).1, 0.25);
        for max in [0.0003, 0.07, 0.3, 0.99, 1.0] {
            let (top, step) = nice_axis(max);
            assert!(top >= max);
            let steps = top / step;
            assert!((steps - 4.0).abs() < 1e-9 || (steps - 5.0).abs() < 1e-9);
        }
    }

    #[test]
    fn tick_positions_are_round_and_cover_the_range() {
        let ticks = nice_ticks(0.7075, 1.0);
        assert!((ticks[0] - 0.70).abs() < 1e-9 && (ticks[ticks.len() - 1] - 1.0).abs() < 1e-9);
        assert!(ticks.len() <= 9);
        let narrow = nice_ticks(0.707, 0.816);
        assert!(narrow[0] <= 0.707 && narrow[narrow.len() - 1] >= 0.816);
        assert!(narrow.windows(2).all(|w| (w[1] - w[0] - 0.02).abs() < 1e-9));
    }

    #[test]
    fn percentages_use_as_few_decimals_as_needed() {
        assert_eq!(percent(0.0), "0%");
        assert_eq!(percent(0.5), "50%");
        assert_eq!(percent(0.034), "3.4%");
        assert_eq!(percent(0.0042), "0.42%");
        assert_eq!(percent(0.00031), "0.031%");
    }

    #[test]
    fn a_bar_figure_is_well_formed_and_escaped() {
        let svg = bar_figure().to_svg();
        assert!(svg.starts_with("<svg xmlns"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.contains("A &lt;title&gt; &amp; more"));
        // Four bars, each with a hover title.
        assert_eq!(svg.matches("<path class=\"s").count(), 4);
        assert_eq!(svg.matches("<title>value").count(), 4);
        // Two series: a legend with two swatches.
        assert_eq!(svg.matches("<rect class=\"s").count(), 2);
        assert!(svg.contains("prefers-color-scheme: dark"));
        assert_eq!(svg.matches('<').count(), svg.matches('>').count());
    }

    #[test]
    fn a_single_series_gets_no_legend() {
        let mut figure = bar_figure();
        figure.panels[0].series.truncate(1);
        assert_eq!(figure.to_svg().matches("<rect class=\"s").count(), 0);
    }

    #[test]
    fn line_and_scatter_panels_draw_lines_and_markers() {
        let figure = Figure {
            title: "t".into(),
            subtitle: "s".into(),
            panels: vec![
                Panel {
                    heading: "lines".into(),
                    y_label: "y".into(),
                    kind: Kind::Lines {
                        x: vec![0.0, 0.1, 0.2],
                        x_ticks: vec!["0%".into(), "10%".into(), "20%".into()],
                        x_label: "loss".into(),
                    },
                    series: vec![series("a", 0, &[0.1, 0.2, 0.3])],
                },
                Panel {
                    heading: "scatter".into(),
                    y_label: "y".into(),
                    kind: Kind::Scatter {
                        x_label: "coverage".into(),
                        xs: vec![vec![0.7, 0.8, 0.9], vec![1.0]],
                        connect: Some(0),
                    },
                    series: vec![
                        Series {
                            callouts: vec![(1, "chosen".into()), (2, "loosest".into())],
                            ..series("a", 2, &[0.01, 0.02, 0.05])
                        },
                        series("b", 1, &[0.2]),
                    ],
                },
            ],
        };
        let svg = figure.to_svg();
        assert_eq!(svg.matches("<polyline").count(), 2);
        assert_eq!(svg.matches("<circle").count(), 7);
        assert!(svg.contains(">chosen</text>") && svg.contains(">loosest</text>"));
        assert!(svg.contains(">loss</text>"));
        assert!(!svg.contains("NaN") && !svg.contains("inf"));
    }

    #[test]
    fn subtitle_lines_are_stacked_and_bar_panels_leave_room_for_labels() {
        let mut figure = bar_figure();
        let one = figure.to_svg();
        figure.subtitle = "first line\nsecond line".into();
        let two = figure.to_svg();
        assert!(two.contains(">first line</text>") && two.contains(">second line</text>"));
        let height = |svg: &str| -> f64 {
            let start = svg.find("height=\"").unwrap() + 8;
            svg[start..start + svg[start..].find('"').unwrap()]
                .parse()
                .unwrap()
        };
        assert_eq!(height(&two) - height(&one), 16.0);
        // 46 above the plot, 250 of plot, 104 below it for slanted labels.
        assert_eq!(height(&one), 64.0 + 46.0 + 250.0 + 104.0);
    }

    #[test]
    fn rendering_is_deterministic() {
        assert_eq!(bar_figure().to_svg(), bar_figure().to_svg());
    }
}
