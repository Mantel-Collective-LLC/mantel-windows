type Rgb = [f64; 3];

const INK: Rgb = [24.0, 24.0, 27.0];
const WHITE: Rgb = [255.0, 255.0, 255.0];
const STROKE: [(f64, f64); 5] = [(7.0, 16.5), (7.0, 8.2), (12.0, 11.6), (17.0, 8.2), (17.0, 16.5)];

pub fn dot_for(phase: &str) -> Rgb {
    match phase {
        "connected" => [16.0, 185.0, 129.0],
        "stale" => [239.0, 68.0, 68.0],
        "connecting" | "disconnecting" => [245.0, 158.0, 11.0],
        _ => [161.0, 161.0, 170.0],
    }
}

fn inside_rounded_rect(px: f64, py: f64, size: f64, radius: f64) -> bool {
    let cx = px.clamp(radius, size - radius);
    let cy = py.clamp(radius, size - radius);
    (px - cx).powi(2) + (py - cy).powi(2) <= radius * radius
}

fn distance_to_segment(px: f64, py: f64, a: (f64, f64), b: (f64, f64)) -> f64 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let t = (((px - a.0) * dx + (py - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    (px - (a.0 + t * dx)).hypot(py - (a.1 + t * dy))
}

fn sample(u: f64, v: f64, dot: Rgb) -> Option<Rgb> {
    if !inside_rounded_rect(u, v, 24.0, 7.0) {
        return None;
    }
    if (u - 12.0).hypot(v - 17.0) <= 2.2 {
        return Some(dot);
    }
    if STROKE.windows(2).any(|pair| distance_to_segment(u, v, pair[0], pair[1]) <= 1.05) {
        return Some(WHITE);
    }
    Some(INK)
}

pub fn render(size: u32, phase: &str) -> Vec<u8> {
    const SAMPLES: u32 = 4;
    let dot = dot_for(phase);
    let mut buffer = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut sum = [0.0; 3];
            let mut hits = 0.0;
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let u = ((x as f64 + (sx as f64 + 0.5) / SAMPLES as f64) / size as f64) * 24.0;
                    let v = ((y as f64 + (sy as f64 + 0.5) / SAMPLES as f64) / size as f64) * 24.0;
                    if let Some(color) = sample(u, v, dot) {
                        for channel in 0..3 {
                            sum[channel] += color[channel];
                        }
                        hits += 1.0;
                    }
                }
            }
            let coverage = hits / (SAMPLES * SAMPLES) as f64;
            for value in sum {
                buffer.push(if hits > 0.0 { (value / hits).round() as u8 } else { 0 });
            }
            buffer.push((coverage * 255.0).round() as u8);
        }
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(buffer: &[u8], size: u32, x: u32, y: u32) -> &[u8] {
        let offset = ((y * size + x) * 4) as usize;
        &buffer[offset..offset + 4]
    }

    #[test]
    fn draws_logo_and_status_dot() {
        let size = 32;
        let image = render(size, "connected");
        assert_eq!(image.len(), (size * size * 4) as usize);
        assert_eq!(pixel(&image, size, 0, 0)[3], 0, "corner is transparent");
        assert_eq!(pixel(&image, size, 3, 16), &[24, 24, 27, 255], "ink background");
        assert_eq!(pixel(&image, size, 16, 22), &[16, 185, 129, 255], "green dot when connected");
        assert_eq!(pixel(&render(size, "stale"), size, 16, 22), &[239, 68, 68, 255]);
    }
}
