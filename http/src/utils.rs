/// Format a count number to human-readable format (k, M)
pub fn format_count(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}k", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

/// Format bytes to human-readable format (kB, MB, GB)
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1}GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1}MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1}kB", bytes as f64 / 1_000.0)
    } else {
        format!("{}B", bytes)
    }
}

/// Get top N items from a hashmap, sorted by count descending
pub fn get_top_items<T: Clone>(map: &std::collections::HashMap<String, T>, n: usize) -> Vec<(String, T)>
where
    T: Ord + Copy,
{
    let mut items: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1));
    items.into_iter().take(n).collect()
}
