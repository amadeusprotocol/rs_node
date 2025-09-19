use ama_core::node::peers::HandshakeStatus;
use ama_core::{Context, MetricsSnapshot, PeerInfo};
use std::collections::HashMap;

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn generate_protocol_items(protocols: &HashMap<String, u64>) -> String {
    if protocols.is_empty() {
        return r#"<div class="empty-state">No data available</div>"#.to_string();
    }

    let mut items: Vec<_> = protocols.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending

    items
        .into_iter()
        .take(10) // Show top 10
        .map(|(name, count)| {
            format!(
                r#"<div class="message-type-item">
                    <div class="message-type-name">{}</div>
                    <div class="message-type-count">{}</div>
                </div>"#,
                name, count
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn page(
    snapshot: &MetricsSnapshot,
    peers: &HashMap<String, PeerInfo>,
    _entries: &Vec<(u64, u64, u64)>,
    ctx: &Context,
) -> String {
    // Calculate handshaked vs pending peer counts
    let mut handshaked_count = 0;
    let mut pending_count = 0;

    for peer_info in peers.values() {
        match peer_info.handshake_status {
            HandshakeStatus::Completed => {
                handshaked_count += 1;
            }
            _ => {
                pending_count += 1;
            }
        }
    }

    let uptime = ctx.get_uptime();
    let version = ctx.get_config().get_ver();
    let pubkey_bytes = ctx.get_config().get_pk();
    let pubkey = bs58::encode(pubkey_bytes).into_string();
    let block_height = ctx.get_block_height();
    let temporal_height = ctx.get_temporal_height();

    // Get uptime in seconds from metrics snapshot
    let uptime_seconds = snapshot.uptime as f64;

    // Helper function to format bytes with flexible units
    let format_bytes_per_sec = |bytes_per_sec: f64| -> String {
        if bytes_per_sec >= 1024.0 * 1024.0 * 1024.0 {
            format!("{:.1} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
        } else if bytes_per_sec >= 1024.0 * 1024.0 {
            format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
        } else if bytes_per_sec >= 1024.0 {
            format!("{:.1} KB/s", bytes_per_sec / 1024.0)
        } else {
            format!("{:.0} B/s", bytes_per_sec)
        }
    };

    // Helper function to format packets per second with k/M modifiers
    let format_packets_per_sec = |pps: f64| -> String {
        if pps >= 1_000_000.0 {
            format!("{:.1}M pps", pps / 1_000_000.0)
        } else if pps >= 1_000.0 {
            format!("{:.1}k pps", pps / 1_000.0)
        } else {
            format!("{:.0} pps", pps)
        }
    };

    // Use udpps (UDP per second) values directly from metrics snapshot
    let (network_in_bytes_str, network_out_bytes_str, network_in_pps_str, network_out_pps_str) =
        if let Some(ref udpps) = snapshot.udpps {
            // Use the pre-calculated per-second values
            let in_bytes_str = format_bytes_per_sec(udpps.incoming_bytes as f64);
            let out_bytes_str = format_bytes_per_sec(udpps.outgoing_bytes as f64);
            let in_pps_str = format_packets_per_sec(udpps.incoming_packets as f64);
            let out_pps_str = format_packets_per_sec(udpps.outgoing_packets as f64);
            (in_bytes_str, out_bytes_str, in_pps_str, out_pps_str)
        } else {
            // Fallback to calculating from totals if udpps not available
            let incoming_bytes = snapshot.udp.incoming_bytes as f64;
            let outgoing_bytes = snapshot.udp.outgoing_bytes as f64;
            let incoming_packets = snapshot.udp.incoming_packets;
            let outgoing_packets = snapshot.udp.outgoing_packets;

            let in_bytes_per_sec = if uptime_seconds > 0.0 { incoming_bytes / uptime_seconds } else { 0.0 };
            let out_bytes_per_sec = if uptime_seconds > 0.0 { outgoing_bytes / uptime_seconds } else { 0.0 };
            let in_pps = if uptime_seconds > 0.0 { incoming_packets as f64 / uptime_seconds } else { 0.0 };
            let out_pps = if uptime_seconds > 0.0 { outgoing_packets as f64 / uptime_seconds } else { 0.0 };

            (
                format_bytes_per_sec(in_bytes_per_sec),
                format_bytes_per_sec(out_bytes_per_sec),
                format_packets_per_sec(in_pps),
                format_packets_per_sec(out_pps),
            )
        };

    // Calculate total errors from all error types
    let total_errors: u64 = snapshot.errors.values().sum();

    // Placeholder system resource values - will be updated by JavaScript
    let cpu_usage = 0; // Will be updated from /api/metrics
    let memory_usage = 0; // Will be updated from /api/metrics
    let disk_usage = std::cmp::min(60, std::cmp::max(10, (snapshot.uptime / 7200) as i32 + 25)); // Still simulated for now

    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Advanced Dashboard</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <style>
        * {{ 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }}
        
        :root {{
            --background: 0 0% 3.9%;
            --foreground: 0 0% 98%;
            --muted: 0 0% 14.9%;
            --muted-foreground: 0 0% 63.9%;
            --border: 0 0% 14.9%;
            --input: 0 0% 14.9%;
            --card: 0 0% 3.9%;
            --card-foreground: 0 0% 98%;
            --primary: 0 0% 98%;
            --primary-foreground: 0 0% 9%;
            --secondary: 0 0% 14.9%;
            --secondary-foreground: 0 0% 98%;
            --accent: 0 0% 14.9%;
            --accent-foreground: 0 0% 98%;
            --destructive: 0 84.2% 60.2%;
            --destructive-foreground: 0 0% 98%;
            --ring: 0 0% 83.1%;
            --radius: 0.5rem;
        }}

        html, body {{
            height: 100vh;
            margin: 0;
            padding: 0;
            overflow: hidden;
        }}
        
        body {{ 
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            background: hsl(var(--background));
            color: hsl(var(--foreground));
            line-height: 1.6;
            font-size: 14px;
            display: flex;
            flex-direction: column;
            height: 100vh;
        }}
        
        .container {{ 
            width: 100%; 
            padding: 24px; 
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            flex: 1;
            overflow: hidden;
        }}
        
        /* Header */
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 24px;
            border-bottom: 1px solid hsl(var(--border));
            margin-bottom: 24px;
            background: hsl(var(--background));
        }}
        
        .header-left {{
            display: flex;
            align-items: center;
            gap: 16px;
            padding-right: 16px;
        }}
        
        h1 {{ 
            font-size: 32px;
            font-weight: 700;
            color: hsl(var(--foreground));
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .pubkey-badge {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: hsl(var(--background));
            border: 1px solid hsl(var(--foreground));
            color: hsl(var(--foreground));
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 500;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
        }}
        
        .pubkey-badge:hover {{
            background: hsl(var(--muted));
            border-color: hsl(var(--foreground));
            transform: scale(1.02);
        }}
        
        .pubkey-badge:active {{
            transform: scale(0.98);
        }}
        
        .pubkey-icon {{
            width: 16px;
            height: 16px;
            color: hsl(var(--foreground));
        }}
        
        .pubkey-text {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            letter-spacing: 0.5px;
        }}
        
        .copy-tooltip {{
            position: absolute;
            bottom: -30px;
            left: 50%;
            transform: translateX(-50%);
            background: hsl(var(--foreground));
            color: hsl(var(--background));
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }}
        
        .pubkey-badge:hover .copy-tooltip {{
            opacity: 1;
        }}
        
        .version-text {{
            color: hsl(var(--foreground));
            font-size: 12px;
            font-weight: 500;
        }}
        
        .header-right {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        
        .search-container {{
            position: relative;
        }}
        
        .search-icon {{
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            width: 16px;
            height: 16px;
            color: hsl(var(--muted-foreground));
        }}
        
        .search-input {{
            padding: 8px 12px 8px 40px;
            border: 2px solid hsl(var(--border));
            border-radius: 12px;
            font-size: 14px;
            width: 256px;
            background: hsl(var(--background));
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        /* Metrics Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
            margin-bottom: 32px;
        }}
        
        .metric-card {{
            background: hsl(var(--background));
            border: 2px solid hsl(var(--border));
            border-radius: 12px;
            padding: 24px;
            height: fit-content;
            min-height: fit-content;
        }}
        
        .metric-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }}
        
        .metric-title {{
            font-size: 14px;
            color: hsl(var(--muted-foreground));
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .info-btn {{
            background: none;
            border: none;
            cursor: pointer;
            color: #9ca3af;
        }}
        
        .metric-content {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .metric-icon-large {{
            width: 20px;
            height: 20px;
            color: hsl(var(--foreground));
        }}
        
        .metric-value {{
            font-size: 24px;
            font-weight: 700;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .uptime-value {{
            font-size: 18px;
            font-weight: 700;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .network-stats {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        
        .network-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .network-left {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .network-icon {{
            width: 16px;
            height: 16px;
            color: hsl(var(--foreground));
        }}
        
        .network-label {{
            font-size: 16px;
            color: #9ca3af;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .network-value {{
            font-size: 16px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: 600;
        }}

        .peer-stats {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        
        .peer-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .peer-left {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .peer-icon {{
            width: 16px;
            height: 16px;
            color: hsl(var(--foreground));
        }}
        
        .peer-label {{
            font-size: 16px;
            color: #9ca3af;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .peer-value {{
            font-size: 16px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: 600;
        }}

        /* Uptime stats with mixed layout */
        .uptime-stats {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .uptime-main {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 7px 4px; /* Internal padding for visual breathing room */
        }}

        .uptime-icon-large {{
            width: 28px;
            height: 28px;
            color: hsl(var(--foreground));
        }}

        .uptime-value-large {{
            font-size: 28px;
            font-weight: 700;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            word-break: break-word;
            flex: 1;
        }}

        .uptime-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .uptime-left {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .uptime-icon {{
            width: 16px;
            height: 16px;
            color: hsl(var(--foreground));
        }}

        .uptime-label {{
            font-size: 16px;
            color: #9ca3af;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}

        .uptime-secondary-value {{
            font-size: 16px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: 600;
        }}

        /* Block Height stats with matching height */
        .block-stats {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .block-main {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 7px 4px; /* Internal padding for visual breathing room */
        }}

        .block-icon-large {{
            width: 28px;
            height: 28px;
            color: hsl(var(--foreground));
        }}

        .block-value-large {{
            font-size: 28px;
            font-weight: 700;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            word-break: break-word;
            flex: 1;
        }}

        .block-spacer {{
            flex: 1; /* Use available space instead of fixed height */
        }}
        
        /* System Resources */
        .system-card {{
            background: hsl(var(--background));
            border: 2px solid hsl(var(--border));
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
        }}
        
        .system-header {{
            margin-bottom: 24px;
        }}
        
        .system-title {{
            font-size: 16px;
            font-weight: 600;
            color: hsl(var(--foreground));
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .system-subtitle {{
            font-size: 14px;
            color: #9ca3af;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .system-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 32px;
        }}
        
        .resource-item {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        
        .resource-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .resource-label {{
            font-size: 14px;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .resource-value {{
            font-size: 14px;
            font-weight: 600;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
            border: 1px solid #d1d5db;
        }}
        
        .progress-fill {{
            height: 100%;
            background: hsl(var(--foreground));
            transition: width 0.3s ease;
        }}
        
        .resource-info {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .resource-icon {{
            width: 16px;
            height: 16px;
            color: #9ca3af;
        }}
        
        .resource-text {{
            font-size: 12px;
            color: #9ca3af;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        /* Tabs */
        .tabs-container {{
            background: transparent;
            display: flex;
            flex-direction: column;
            flex: 1;
            overflow: hidden;
        }}
        
        .tab-list {{
            display: flex;
            background: hsl(var(--background));
            border: 2px solid hsl(var(--border));
            border-radius: 12px;
            padding: 4px;
            margin-bottom: 24px;
            gap: 4px;
        }}
        
        .tab {{
            flex: 1;
            padding: 12px 20px;
            text-align: center;
            background: transparent;
            border: none;
            color: hsl(var(--muted-foreground));
            cursor: pointer;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.2s ease;
            border-radius: 12px;
            font-size: 14px;
        }}
        
        .tab.active {{
            background: hsl(var(--foreground));
            color: hsl(var(--background));
        }}
        
        .tab:hover:not(.active) {{
            background: hsl(var(--muted));
            color: hsl(var(--foreground));
        }}
        
        .tab-content {{
            display: none;
            overflow: hidden;
        }}
        
        .tab-content.active {{
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }}
        
        /* Overview tab grid layout */
        .overview-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
            flex: 1;
            overflow: hidden;
        }}
        
        @media (min-width: 1024px) {{
            .overview-grid {{
                grid-template-columns: 1fr 1fr;
            }}
        }}
        
        /* Two Column Layout */
        .two-column {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }}
        
        .section-card {{
            background: hsl(var(--background));
            border: 2px solid hsl(var(--border));
            border-radius: 12px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            flex: 1;
            overflow: hidden;
        }}
        
        .section-title {{
            font-size: 16px;
            font-weight: 600;
            color: hsl(var(--foreground));
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            margin-bottom: 0;
        }}

        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .section-packet-count {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .packet-count-icon {{
            width: 16px;
            height: 16px;
            color: #9ca3af;
        }}

        .packet-count-text {{
            font-size: 12px;
            color: #9ca3af;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: normal;
            text-transform: none;
        }}
        
        .status-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}
        
        .status-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }}
        
        .status-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .status-icon {{
            width: 20px;
            height: 20px;
            color: hsl(var(--foreground));
        }}
        
        .status-text {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: 500;
        }}
        
        .status-badge {{
            background: hsl(var(--background));
            color: hsl(var(--foreground));
            border: 1px solid hsl(var(--foreground));
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Semi-transparent badges for SYNCING, DISCONNECTED, and IMPERSONATED */
        .status-syncing,
        .status-disconnected,
        .status-impersonated {{
            opacity: 0.6;
        }}
        
        /* Red color for impersonated status */
        .status-impersonated {{
            border-color: #dc2626;
            color: #dc2626;
        }}
        
        .activity-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}
        
        .activity-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }}
        
        .activity-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .activity-icon {{
            width: 16px;
            height: 16px;
            color: #10b981;
        }}
        
        .activity-details {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        
        .activity-hash {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
            font-weight: 500;
            color: hsl(var(--foreground));
        }}
        
        .activity-time {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 10px;
            color: #9ca3af;
        }}
        
        .activity-right {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 2px;
        }}
        
        .activity-amount {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
            font-weight: 600;
            color: hsl(var(--foreground));
        }}
        
        .activity-type {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 10px;
            color: #9ca3af;
        }}
        
        .empty-state {{
            text-align: center;
            color: #9ca3af;
            padding: 40px;
            font-style: italic;
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        /* Message Tables */
        .message-table-container {{
            overflow-x: auto;
            overflow-y: auto;
            flex: 1;
        }}
        
        /* Utility Classes for Layout */
        .flex {{
            display: flex;
        }}
        
        .items-center {{
            align-items: center;
        }}
        
        .space-x-2 > * + * {{
            margin-left: 8px;
        }}
        
        .font-mono {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        
        /* Custom Scrollbar Styles */
        .message-type-list::-webkit-scrollbar,
        .message-table-container::-webkit-scrollbar {{
            width: 12px;
        }}
        
        .message-type-list::-webkit-scrollbar-track,
        .message-table-container::-webkit-scrollbar-track {{
            background: hsl(var(--background));
            border-radius: 6px;
        }}
        
        .message-type-list::-webkit-scrollbar-thumb,
        .message-table-container::-webkit-scrollbar-thumb {{
            background: hsl(var(--border));
            border-radius: 6px;
            border: 2px solid hsl(var(--background));
        }}
        
        .message-type-list::-webkit-scrollbar-thumb:hover,
        .message-table-container::-webkit-scrollbar-thumb:hover {{
            background: hsl(var(--foreground) / 0.4);
        }}

        .message-type-list::-webkit-scrollbar-corner,
        .message-table-container::-webkit-scrollbar-corner {{
            background: hsl(var(--background));
        }}
        
        .message-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .message-table th {{
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid hsl(var(--border));
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: hsl(var(--foreground));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            cursor: pointer;
            user-select: none;
            position: relative;
        }}
        
        .message-table th .sort-arrow {{
            width: 16px;
            height: 16px;
            color: hsl(var(--foreground));
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            display: none !important;
            stroke: currentColor;
            fill: none;
            opacity: 1;
            z-index: 10;
        }}
        
        .message-table th .sort-arrow[style*="display: block"] {{
            display: block !important;
        }}
        
        .message-table td {{
            padding: 12px;
            border-bottom: 1px solid hsl(var(--border));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
            color: hsl(var(--foreground));
        }}
        
        .message-table tbody tr:hover {{
            background: hsl(var(--muted));
        }}
        
        .message-type {{
            color: hsl(var(--foreground));
            font-weight: 500;
        }}
        
        .message-count {{
            color: #059669;
            font-weight: 700;
        }}
        
        .outgoing-count {{
            color: #dc2626;
            font-weight: 700;
        }}

        /* Message Type Lists */
        .message-type-list {{
            display: flex;
            flex-direction: column;
            flex: 1;
            overflow-y: auto;
        }}

        .message-type-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid hsl(var(--border));
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
            color: hsl(var(--foreground));
        }}
        
        .message-type-item:hover {{
            background: hsl(var(--muted));
        }}

        .message-type-name {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 14px;
            color: hsl(var(--foreground));
        }}

        .message-type-count {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 14px;
            font-weight: 600;
            color: hsl(var(--foreground));
        }}

        /* Grid utilities */
        .grid {{
            display: grid;
        }}

        .grid-cols-1 {{
            grid-template-columns: repeat(1, minmax(0, 1fr));
        }}

        .gap-6 {{
            gap: 24px;
        }}

        .mb-6 {{
            margin-bottom: 24px;
        }}

        @media (min-width: 1024px) {{
            .lg\\:grid-cols-2 {{
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }}
        }}

        /* Flexbox utilities */
        .flex {{
            display: flex;
        }}

        .items-center {{
            align-items: center;
        }}

        .space-x-2 > * + * {{
            margin-left: 8px;
        }}

        .font-mono {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}

        /* Animation utilities */
        .animate-spin {{
            animation: spin 1s linear infinite;
        }}

        @keyframes spin {{
            from {{
                transform: rotate(0deg);
            }}
            to {{
                transform: rotate(-360deg);
            }}
        }}

        /* Orbital Loader Styles */
        .orbital-loader {{
            display: flex;
            align-items: center;
            justify-content: center;
            padding-right: 12px;
        }}

        .orbital-container {{
            position: relative;
            width: 24px;
            height: 24px;
        }}

        .orbital-ring {{
            position: absolute;
            border: 2px solid transparent;
            border-radius: 50%;
            border-top-color: hsl(var(--foreground));
        }}

        .orbital-ring-1 {{
            width: 24px;
            height: 24px;
            top: 0;
            left: 0;
            animation: orbital-spin-1 1s linear infinite;
        }}

        .orbital-ring-2 {{
            width: 16px;
            height: 16px;
            top: 4px;
            left: 4px;
            animation: orbital-spin-2 1.5s linear infinite reverse;
        }}

        .orbital-ring-3 {{
            width: 8px;
            height: 8px;
            top: 8px;
            left: 8px;
            animation: orbital-spin-3 0.8s linear infinite;
        }}

        @keyframes orbital-spin-1 {{
            from {{
                transform: rotate(0deg);
            }}
            to {{
                transform: rotate(360deg);
            }}
        }}

        @keyframes orbital-spin-2 {{
            from {{
                transform: rotate(0deg);
            }}
            to {{
                transform: rotate(-360deg);
            }}
        }}

        @keyframes orbital-spin-3 {{
            from {{
                transform: rotate(0deg);
            }}
            to {{
                transform: rotate(360deg);
            }}
        }}

        /* Status styling matching @design reference */
        .status-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .status-item {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px;
            border: 1px solid hsl(var(--border));
            border-radius: 8px;
        }}

        .status-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .status-text {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            color: hsl(var(--foreground));
        }}

            font-weight: 600;
            padding: 4px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}

        .status-icon {{
            width: 20px;
            height: 20px;
            color: hsl(var(--foreground));
        }}

        /* Progress bars matching @design */
        .progress-bar {{
            height: 12px;
            background: hsl(var(--muted));
            border: 1px solid hsl(var(--border));
            border-radius: 8px;
            position: relative;
            overflow: hidden;
        }}

        .progress-fill {{
            height: 100%;
            background: hsl(var(--foreground));
            border-radius: 8px;
            transition: width 0.3s ease;
        }}
        
        /* Responsive */
        @media (max-width: 1024px) {{
            .metrics-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .system-grid {{
                grid-template-columns: 1fr;
            }}
            .two-column {{
                grid-template-columns: 1fr;
            }}

            /* Tablet layout improvements */
            .container {{
                height: 100vh;
                overflow-y: auto;
                padding-bottom: 24px; /* Match desktop spacing */
                display: flex;
                flex-direction: column;
            }}

            .tabs-container {{
                flex: 1;
                min-height: 400px;
                display: flex !important;
                flex-direction: column;
            }}

            .overview-grid {{
                grid-template-columns: 1fr 1fr; /* Keep two columns for message cards */
            }}

            .section-card {{
                max-height: 450px;
                overflow-y: auto;
            }}

            .message-type-list {{
                max-height: 350px;
                overflow-y: auto;
            }}
        }}
        
        /* Logo responsive behavior */
        .logo-wordmark {{
            height: 40px;
            width: auto;
        }}

        .logo-compact {{
            height: 40px;
            width: auto;
            display: none;
        }}

        /* Medium screens: switch to compact logo but keep full search width */
        @media (max-width: 900px) {{
            .logo-wordmark {{
                display: none;
            }}

            .logo-compact {{
                display: block;
            }}
        }}

        /* Search button for small screens */
        .search-button {{
            display: none;
            background: none;
            border: 2px solid hsl(var(--border));
            border-radius: 12px;
            padding: 8px;
            cursor: pointer;
            color: hsl(var(--foreground));
            transition: all 0.2s ease;
        }}

        .search-button:hover {{
            background: hsl(var(--muted));
            border-color: hsl(var(--foreground));
        }}

        .search-button svg {{
            width: 16px;
            height: 16px;
        }}

        /* Small screens: replace search container with button and adjust layout */
        @media (max-width: 750px) {{
            .container {{ padding: 16px 16px 40px 16px; }}

            .search-container {{
                display: none;
            }}

            .search-button {{
                display: block;
            }}

            .metrics-grid {{
                grid-template-columns: 1fr;
            }}
            .tab-list {{
                display: none; /* Hide tabs list on mobile since all content is visible */
            }}

            /* Always reserve space for orbital loader even when hidden */
            .orbital-loader {{
                visibility: hidden; /* Use visibility instead of display to maintain space */
                margin-left: 12px; /* Same margin as version text */
            }}

            .orbital-loader[style*="display: flex"] {{
                visibility: visible; /* Show when needed */
            }}

            /* Mobile height constraints and scrolling */
            html, body {{
                overflow-x: hidden;
                height: 100vh;
                margin: 0;
                padding: 0;
            }}

            .container {{
                height: 100vh; /* Minimum height, allow expansion */
                overflow-y: auto;
                padding-bottom: 24px; /* Increased to match tablet visual spacing */
                display: flex;
                flex-direction: column;
            }}

            .tabs-container {{
                flex: none; /* Don't constrain height */
                min-height: auto; /* Let content determine height */
                display: flex !important;
                flex-direction: column;
                overflow: visible; /* Allow content to show */
                gap: 24px; /* Standard gap between all tab sections */
            }}

            .tab-content {{
                display: flex !important; /* Show all tab content on mobile */
                flex-direction: column;
                margin-bottom: 0; /* Remove margin, use gap instead */
                overflow-y: visible; /* Remove scrolling */
            }}

            .tab-content.active {{
                display: flex !important;
                flex-direction: column;
            }}

            /* Mobile overview grid - single column with standard gaps */
            .overview-grid {{
                display: grid !important; /* Ensure grid display */
                grid-template-columns: 1fr !important;
                gap: 24px; /* Standard gap like other cards */
                margin-bottom: 0; /* Remove extra margin */
            }}

            .section-card {{
                max-height: 450px; /* Match tablet height */
                overflow-y: auto; /* Enable scrolling when content exceeds height */
                flex-shrink: 0;
                margin-bottom: 0; /* Remove individual margins, use container gap */
            }}

            /* Fix system card margin for consistent spacing */
            .system-card {{
                margin-bottom: 24px; /* Consistent with other cards */
                flex-shrink: 0; /* Prevent shrinking */
            }}

            .message-type-list {{
                max-height: 450px; /* Match section card height */
                overflow-y: auto; /* Enable scrolling like tablet */
            }}

            /* Make incoming/outgoing message cards taller */
            #incoming-content .section-card,
            #outgoing-content .section-card {{
                max-height: 450px; /* Only target message cards specifically */
            }}

            .message-table-container {{
                max-height: none; /* Remove height restrictions for consistency */
                overflow-y: visible; /* Remove scrolling for consistency */
            }}

            /* Ensure metrics grid doesn't take too much space */
            .metrics-grid {{
                flex-shrink: 0;
                margin-bottom: 24px;
            }}

            /* Fix transaction history card height - use min-height for flexibility */
            #transactions-content .section-card {{
                max-height: 450px; /* Only target message cards specifically */
            }}
        }}
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <img src="/static/wordmark-light.svg" alt="Amadeus" class="logo-wordmark">
            <img src="/static/logo-light.svg" alt="Amadeus" class="logo-compact">
            <div class="pubkey-badge" onclick="copyPubkey('{}')" title="Click to copy full public key">
                <svg class="pubkey-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24">
                    <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                        <path d="M7 9.667A2.667 2.667 0 0 1 9.667 7h8.666A2.667 2.667 0 0 1 21 9.667v8.666A2.667 2.667 0 0 1 18.333 21H9.667A2.667 2.667 0 0 1 7 18.333z"/>
                        <path d="M4.012 16.737A2 2 0 0 1 3 15V5c0-1.1.9-2 2-2h10c.75 0 1.158.385 1.5 1"/>
                    </g>
                </svg>
                <span class="pubkey-text">{}...</span>
                <div class="copy-tooltip">Click to copy</div>
            </div>
            <div class="version-text font-mono">v{}</div>
            <div class="orbital-loader" id="node-status-loader" style="display: none;">
                <div class="orbital-container">
                    <div class="orbital-ring orbital-ring-1"></div>
                    <div class="orbital-ring orbital-ring-2"></div>
                    <div class="orbital-ring orbital-ring-3"></div>
                </div>
            </div>
        </div>
        <div class="header-right">
            <div class="search-container">
                <svg class="search-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <input type="text" class="search-input" placeholder="Search transactions..." />
            </div>
            <button class="search-button" type="button" title="Search">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
            </button>
        </div>
    </div>

    <div class="container">
        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <!-- Block Height Card -->
            <div class="metric-card">
                <div class="metric-header">
                    <div class="metric-title">Block Height</div>
                    <button class="info-btn">
                        <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                    </button>
                </div>
                <div class="block-stats">
                    <div class="block-main">
                        <svg class="block-icon-large" xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24">
                            <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                <path d="M4 6a8 3 0 1 0 16 0A8 3 0 1 0 4 6"/>
                                <path d="M4 6v6a8 3 0 0 0 16 0V6"/>
                                <path d="M4 12v6a8 3 0 0 0 16 0v-6"/>
                            </g>
                        </svg>
                        <div class="block-value-large">{}</div>
                    </div>
                    <div class="uptime-row">
                        <div class="uptime-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="uptime-icon">
                                <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                    <path d="M4 6a8 3 0 1 0 16 0A8 3 0 1 0 4 6"/>
                                    <path d="M4 6v6a8 3 0 0 0 16 0V6"/>
                                    <path d="M4 12v6a8 3 0 0 0 16 0v-6"/>
                                </g>
                            </svg>
                            <div class="uptime-label">TEMPORAL:</div>
                        </div>
                        <div class="uptime-secondary-value" id="temporal-height">{}</div>
                    </div>
                    <div class="uptime-row">
                        <div class="uptime-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="uptime-icon">
                                <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                    <path d="M3 12a9 9 0 0 0 9 9a9 9 0 0 0 9-9a9 9 0 0 0-9-9"/>
                                    <path d="M17 12a5 5 0 1 0-5 5"/>
                                </g>
                            </svg>
                            <div class="uptime-label">TODO:</div>
                        </div>
                        <div class="uptime-secondary-value">0</div>
                    </div>
                </div>
            </div>

            <!-- Peer Nodes Card -->
            <div class="metric-card">
                <div class="metric-header">
                    <div class="metric-title">Peer Nodes</div>
                    <button class="info-btn">
                        <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                    </button>
                </div>
                <div class="peer-stats">
                    <div class="peer-row">
                        <div class="peer-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="peer-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 7a4 4 0 1 0 8 0a4 4 0 1 0-8 0M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2m1-17.87a4 4 0 0 1 0 7.75M21 21v-2a4 4 0 0 0-3-3.85"/>
                            </svg>
                            <div class="peer-label">HANDSHAKED:</div>
                        </div>
                        <div class="peer-value" id="handshaked-count">{}</div>
                    </div>
                    <div class="peer-row">
                        <div class="peer-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="peer-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7a4 4 0 1 0 8 0a4 4 0 0 0-8 0M6 21v-2a4 4 0 0 1 4-4h3.5m5.5 7v.01M19 19a2.003 2.003 0 0 0 .914-3.782a1.98 1.98 0 0 0-2.414.483"/>
                            </svg>
                            <div class="peer-label">PENDING:</div>
                        </div>
                        <div class="peer-value" id="pending-count">{}</div>
                    </div>
                    <div class="peer-row">
                        <div class="peer-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="peer-icon">
                                <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                    <path d="M3 12a9 9 0 0 0 9 9a9 9 0 0 0 9-9a9 9 0 0 0-9-9"/>
                                    <path d="M17 12a5 5 0 1 0-5 5"/>
                                </g>
                            </svg>
                            <div class="peer-label">TODO:</div>
                        </div>
                        <div class="peer-value">0</div>
                    </div>
                    <div class="peer-row">
                        <div class="peer-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="peer-icon">
                                <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                    <path d="M3 12a9 9 0 0 0 9 9a9 9 0 0 0 9-9a9 9 0 0 0-9-9"/>
                                    <path d="M17 12a5 5 0 1 0-5 5"/>
                                </g>
                            </svg>
                            <div class="peer-label">TODO:</div>
                        </div>
                        <div class="peer-value">0</div>
                    </div>
                </div>
            </div>

            <!-- Network I/O Card -->
            <div class="metric-card">
                <div class="metric-header">
                    <div class="metric-title">Network I/O</div>
                    <button class="info-btn">
                        <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                    </button>
                </div>
                <div class="network-stats">
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 3v6m-7 9l-3 3l-3-3m3 3V3m13 3l-3-3l-3 3m3 15v-2m0-4v-2"/>
                            </svg>
                            <div class="network-label">DATA IN:</div>
                        </div>
                        <div class="network-value">{}</div>
                    </div>
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 20H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h8m4 0v17m-3-3l3 3l3-3"/>
                            </svg>
                            <div class="network-label">PKT IN:</div>
                        </div>
                        <div class="network-value">{}</div>
                    </div>
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21v-6m13-9l-3-3l-3 3m3-3v18m-7-3l-3 3l-3-3M7 3v2m0 4v2"/>
                            </svg>
                            <div class="network-label">DATA OUT:</div>
                        </div>
                        <div class="network-value">{}</div>
                    </div>
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8m4 0V3m-3 3l3-3l3 3"/>
                            </svg>
                            <div class="network-label">PKT OUT:</div>
                        </div>
                        <div class="network-value">{}</div>
                    </div>
                </div>
            </div>

            <!-- Uptime Card -->
            <div class="metric-card">
                <div class="metric-header">
                    <div class="metric-title">Uptime</div>
                    <button class="info-btn">
                        <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                    </button>
                </div>
                <div class="uptime-stats">
                    <div class="uptime-main">
                        <svg class="uptime-icon-large" xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24">
                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12h4.5L9 6l4 12l2-9l1.5 3H21"/>
                        </svg>
                        <div class="uptime-value-large">{}</div>
                    </div>
                    <div class="uptime-row">
                        <div class="uptime-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="uptime-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 9h6M4 5h4M6 5v11a1 1 0 0 0 1 1h5m0-9a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-6a1 1 0 0 1-1-1zm0 8a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-6a1 1 0 0 1-1-1z"/>
                            </svg>
                            <div class="uptime-label">TASKS:</div>
                        </div>
                        <div class="uptime-secondary-value" id="tasks-count">{}</div>
                    </div>
                    <div class="uptime-row">
                        <div class="uptime-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="uptime-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0m9-3v4m0 3v.01"/>
                            </svg>
                            <div class="uptime-label">ERRORS:</div>
                        </div>
                        <div class="uptime-secondary-value" id="errors-count">{}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- System Resources -->
        <div class="system-card">
            <div class="system-header">
                <div class="system-title">System Resources</div>
                <div class="system-subtitle">Real-time system performance metrics</div>
            </div>
            <div class="system-grid">
                <div class="resource-item">
                    <div class="resource-header">
                        <div class="resource-label">CPU Usage</div>
                        <div class="resource-value">{}%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {}%"></div>
                    </div>
                    <div class="resource-info">
                        <svg class="resource-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <rect width="16" height="16" x="4" y="4" rx="2"/>
                            <rect width="6" height="6" x="9" y="9" rx="1"/>
                            <path d="M15 2v2"/>
                            <path d="M15 20v2"/>
                            <path d="M2 15h2"/>
                            <path d="M2 9h2"/>
                            <path d="M20 15h2"/>
                            <path d="M20 9h2"/>
                            <path d="M9 2v2"/>
                            <path d="M9 20v2"/>
                        </svg>
                        <div class="resource-text">0 cores available</div>
                    </div>
                </div>
                
                <div class="resource-item">
                    <div class="resource-header">
                        <div class="resource-label">Memory Usage</div>
                        <div class="resource-value">{}%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {}%"></div>
                    </div>
                    <div class="resource-info">
                        <svg class="resource-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/>
                            <rect width="20" height="8" x="2" y="14" rx="2" ry="2"/>
                            <line x1="6" x2="6.01" y1="6" y2="6"/>
                            <line x1="6" x2="6.01" y1="18" y2="18"/>
                        </svg>
                        <div class="resource-text">0 GB available (0 B used)</div>
                    </div>
                </div>
                
                <div class="resource-item">
                    <div class="resource-header">
                        <div class="resource-label">Disk Usage (not real)</div>
                        <div class="resource-value">{}%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {}%"></div>
                    </div>
                    <div class="resource-info">
                        <svg class="resource-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <line x1="22" x2="2" y1="12" y2="12"/>
                            <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>
                            <line x1="6" x2="6.01" y1="16" y2="16"/>
                            <line x1="10" x2="10.01" y1="16" y2="16"/>
                        </svg>
                        <div class="resource-text">2TB available (not real)</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs-container">
            <div class="tab-list">
                <button class="tab active" onclick="showTab('overview')">OVERVIEW</button>
                <button class="tab" onclick="showTab('peers')">PEERS</button>
                <button class="tab" onclick="showTab('transactions')">TRANSACTIONS</button>
            </div>
            
            <!-- Overview Tab -->
            <div id="overview-content" class="tab-content active">
                <div class="overview-grid">
                    <div class="section-card">
                        <div class="section-header">
                            <div class="section-title">Incoming Messages</div>
                            <div class="section-packet-count">
                                <svg class="packet-count-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24">
                                    <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                        <path d="M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                                        <path d="m3 7l9 6l9-6"/>
                                    </g>
                                </svg>
                                <span class="packet-count-text" id="incoming-packet-count">{}</span>
                            </div>
                        </div>
                        <div class="message-type-list">
                            {}
                        </div>
                    </div>

                    <div class="section-card">
                        <div class="section-header">
                            <div class="section-title">Outgoing Messages</div>
                            <div class="section-packet-count">
                                <svg class="packet-count-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24">
                                    <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                                        <path d="M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                                        <path d="m3 7l9 6l9-6"/>
                                    </g>
                                </svg>
                                <span class="packet-count-text" id="outgoing-packet-count">{}</span>
                            </div>
                        </div>
                        <div class="message-type-list">
                            {}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Peers Tab -->
            <div id="peers-content" class="tab-content">
                <div class="section-card">
                    <div class="section-title">Connected Peers</div>
                    <div class="message-table-container">
                        <table class="message-table">
                            <thead>
                                <tr>
                                    <th class="sortable" onclick="sortPeersTable('address')">
                                        <span>ADDRESS</span>
                                        <svg class="sort-arrow sort-asc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 14l5-5 5 5"/>
                                        </svg>
                                        <svg class="sort-arrow sort-desc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5 5 5-5"/>
                                        </svg>
                                    </th>
                                    <th class="sortable" onclick="sortPeersTable('status')">
                                        <span>STATUS</span>
                                        <svg class="sort-arrow sort-asc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 14l5-5 5 5"/>
                                        </svg>
                                        <svg class="sort-arrow sort-desc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5 5 5-5"/>
                                        </svg>
                                    </th>
                                    <th class="sortable" onclick="sortPeersTable('latency')">
                                        <span>LATENCY</span>
                                        <svg class="sort-arrow sort-asc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 14l5-5 5 5"/>
                                        </svg>
                                        <svg class="sort-arrow sort-desc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5 5 5-5"/>
                                        </svg>
                                    </th>
                                    <th class="sortable" onclick="sortPeersTable('temporal')">
                                        <span>TEMPORAL</span>
                                        <svg class="sort-arrow sort-asc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 14l5-5 5 5"/>
                                        </svg>
                                        <svg class="sort-arrow sort-desc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5 5 5-5"/>
                                        </svg>
                                    </th>
                                    <th class="sortable" onclick="sortPeersTable('rooted')">
                                        <span>ROOTED</span>
                                        <svg class="sort-arrow sort-asc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 14l5-5 5 5"/>
                                        </svg>
                                        <svg class="sort-arrow sort-desc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5 5 5-5"/>
                                        </svg>
                                    </th>
                                    <th class="sortable" onclick="sortPeersTable('version')">
                                        <span>VERSION</span>
                                        <svg class="sort-arrow sort-asc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 14l5-5 5 5"/>
                                        </svg>
                                        <svg class="sort-arrow sort-desc" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" style="display: none;">
                                            <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5 5 5-5"/>
                                        </svg>
                                    </th>
                                </tr>
                            </thead>
                            <tbody id="peers-table-body">
                                <!-- Peers will be populated dynamically by JavaScript -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Transactions Tab -->
            <div id="transactions-content" class="tab-content">
                <div class="section-card">
                    <div class="section-title">Transaction History</div>
                    <div class="empty-state">Transaction data will be displayed here</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Peers table sorting state
        let peersData = [];
        window.currentSortColumn = '';
        window.currentSortDirection = '';
        
        function sortPeersTable(column, userClick = true) {{
            // Only toggle sort direction if user clicked (not on data refresh)
            if (userClick) {{
                if (window.currentSortColumn === column) {{
                    window.currentSortDirection = window.currentSortDirection === 'asc' ? 'desc' : 'asc';
                }} else {{
                    window.currentSortColumn = column;
                    window.currentSortDirection = 'desc';
                }}
            }}
            
            // Update arrow visibility - force all arrows to be hidden first
            const allArrows = document.querySelectorAll('.sort-arrow');
            allArrows.forEach(arrow => {{
                arrow.style.display = 'none';
            }});
            
            // Find the header that matches the clicked column
            const tableHeaders = document.querySelectorAll('th.sortable');
            let currentHeader = null;
            
            // Find the header by checking onclick attribute content
            for (const header of tableHeaders) {{
                const onclickAttr = header.getAttribute('onclick');
                if (onclickAttr && onclickAttr.includes(`sortPeersTable('${{column}}')`)) {{
                    currentHeader = header;
                    break;
                }}
            }}
            
            if (currentHeader) {{
                // Select the appropriate arrow based on sort direction
                const arrowClass = window.currentSortDirection === 'asc' ? '.sort-asc' : '.sort-desc';
                const targetArrow = currentHeader.querySelector(arrowClass);
                if (targetArrow) {{
                    targetArrow.style.display = 'block';
                }} else {{
                    console.log('Arrow not found:', arrowClass, 'in header:', currentHeader);
                }}
            }} else {{
                console.log('Header not found for column:', column, 'Available headers:', tableHeaders.length);
                // Debug: log all available headers
                tableHeaders.forEach((header, index) => {{
                    console.log(`Header ${{index}}:`, header.getAttribute('onclick'));
                }});
            }}
            
            // Sort the data
            peersData.sort((a, b) => {{
                let aVal, bVal;
                
                switch(column) {{
                    case 'address':
                        aVal = a.address;
                        bVal = b.address;
                        break;
                    case 'status':
                        // Sort by handshake status priority: completed > initiated > failed > none
                        const statusPriority = {{
                            'completed': 4,
                            'initiated': 3,
                            'failed': 2,
                            'none': 1
                        }};
                        aVal = statusPriority[a.peerInfo.handshake_status] || 0;
                        bVal = statusPriority[b.peerInfo.handshake_status] || 0;
                        break;
                    case 'latency':
                        aVal = typeof a.peerInfo.latency === 'number' ? a.peerInfo.latency : -1;
                        bVal = typeof b.peerInfo.latency === 'number' ? b.peerInfo.latency : -1;
                        break;
                    case 'temporal':
                        aVal = typeof a.peerInfo.temporal_height === 'number' ? a.peerInfo.temporal_height : -1;
                        bVal = typeof b.peerInfo.temporal_height === 'number' ? b.peerInfo.temporal_height : -1;
                        break;
                    case 'rooted':
                        aVal = typeof a.peerInfo.rooted_height === 'number' ? a.peerInfo.rooted_height : -1;
                        bVal = typeof b.peerInfo.rooted_height === 'number' ? b.peerInfo.rooted_height : -1;
                        break;
                    case 'height':
                        aVal = typeof a.peerInfo.height === 'number' ? a.peerInfo.height : -1;
                        bVal = typeof b.peerInfo.height === 'number' ? b.peerInfo.height : -1;
                        break;
                    case 'version':
                        aVal = a.peerInfo.version || '';
                        bVal = b.peerInfo.version || '';
                        break;
                    default:
                        return 0;
                }}
                
                if (typeof aVal === 'string' && typeof bVal === 'string') {{
                    const comparison = aVal.localeCompare(bVal);
                    return window.currentSortDirection === 'asc' ? comparison : -comparison;
                }} else {{
                    const comparison = aVal - bVal;
                    return window.currentSortDirection === 'asc' ? comparison : -comparison;
                }}
            }});
            
            // Re-render the table with sorted data
            renderPeersTable();
        }}
        
        function renderPeersTable() {{
            const tbody = document.getElementById('peers-table-body');
            if (!tbody) return;
            
            if (peersData.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: #9ca3af; font-style: italic;">No peers connected</td></tr>';
                return;
            }}
            
            const rows = peersData.map(item => {{
                const address = item.address;
                const peerInfo = item.peerInfo;
                
                // Determine status based on HandshakeStatus enum
                const handshakeStatus = peerInfo.handshake_status;
                let status = 'DISCONNECTED';
                let statusClass = 'status-disconnected';
                let statusIcon = `
                    <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                `;
                
                // Map HandshakeStatus enum to display status
                if (handshakeStatus === 'completed') {{
                    // Connected - white badge
                    status = 'CONNECTED';
                    statusClass = '';
                    statusIcon = `
                        <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                        </svg>
                    `;
                }} else if (handshakeStatus === 'initiated') {{
                    // Connecting - transparent badge with spinning arrows
                    status = 'CONNECTING';
                    statusClass = 'status-syncing';
                    statusIcon = `
                        <svg class="status-icon animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                    `;
                }} else if (handshakeStatus === 'failed') {{
                    // Impersonated - transparent red badge
                    status = 'IMPERSONATED';
                    statusClass = 'status-impersonated';
                    statusIcon = `
                        <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                    `;
                }} else {{
                    // None or other - disconnected (transparent badge)
                    status = 'DISCONNECTED';
                    statusClass = 'status-disconnected';
                }}
                
                // Extract peer info fields with defaults
                const latency = peerInfo.latency || '-';
                const temporalHeight = peerInfo.temporal_height || '-';
                const rootedHeight = peerInfo.rooted_height || '-';
                const version = peerInfo.version || '-';
                
                return `
                    <tr>
                        <td class="font-mono">${{address}}</td>
                        <td>
                            <div class="flex items-center space-x-2">
                                ${{statusIcon}}
                                <div class="status-badge ${{statusClass}}">${{status}}</div>
                            </div>
                        </td>
                        <td class="font-mono">${{typeof latency === 'number' ? latency + 'ms' : latency}}</td>
                        <td class="font-mono">${{typeof temporalHeight === 'number' ? temporalHeight.toLocaleString() : temporalHeight}}</td>
                        <td class="font-mono">${{typeof rootedHeight === 'number' ? rootedHeight.toLocaleString() : rootedHeight}}</td>
                        <td class="font-mono">${{version}}</td>
                    </tr>
                `;
            }}).join('');
            
            tbody.innerHTML = rows;
        }}

        function showTab(tabName) {{
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {{
                tab.classList.remove('active');
            }});
            
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.remove('active');
            }});
            
            // Add active class to clicked tab or find the tab by name
            if (typeof event !== 'undefined' && event && event.target && event.target.classList.contains('tab')) {{
                event.target.classList.add('active');
            }} else {{
                // Find tab by name when called programmatically
                const tabs = document.querySelectorAll('.tab');
                tabs.forEach(tab => {{
                    const onclick = tab.getAttribute('onclick');
                    if (onclick && onclick.includes("'" + tabName + "'")) {{
                        tab.classList.add('active');
                    }}
                }});
            }}
            
            // Show selected tab content
            document.getElementById(tabName + '-content').classList.add('active');
            
            // If switching to peers tab, refresh peer data immediately
            if (tabName === 'peers') {{
                refreshPeersData();
            }}
        }}
        
        // Refresh peers data specifically for peers tab
        async function refreshPeersData() {{
            try {{
                const peersRes = await fetch('/api/peers');
                if (peersRes.ok) {{
                    const peers = await peersRes.json();
                    updatePeersTable(peers);
                }}
            }} catch (error) {{
                console.warn('Failed to refresh peers data:', error);
            }}
        }}
        
        // Auto-refresh dashboard data every second
        let isRefreshing = false;
        
        async function refreshDashboardData() {{
            if (isRefreshing) return;
            isRefreshing = true;
            
            try {{
                const [metricsRes, peersRes] = await Promise.all([
                    fetch('/api/metrics'),
                    fetch('/api/peers')
                ]);

                if (metricsRes.ok && peersRes.ok) {{
                    const [metrics, peers] = await Promise.all([
                        metricsRes.json(),
                        peersRes.json()
                    ]);

                    updateMetricsDisplay(metrics, peers);
                }} else {{
                    // API requests failed - show offline state
                    console.warn('API requests failed - showing offline state');
                    updateMetricsDisplay(null, {{}});
                }}
            }} catch (error) {{
                console.warn('Failed to refresh dashboard data:', error);
                // Network error or other failure - show offline state
                updateMetricsDisplay(null, {{}});
            }} finally {{
                isRefreshing = false;
            }}
        }}
        
        function updateMetricsDisplay(metrics, peers) {{
            // Update all metric cards
            const peerCount = Object.keys(peers || {{}}).length;

            // Show/hide orbital loader based on node status
            const loader = document.getElementById('node-status-loader');
            if (loader) {{
                // Show loader if node appears to be offline (no metrics or very low activity)
                const isOffline = !metrics || (!metrics.uptime && !peerCount);
                loader.style.display = isOffline ? 'flex' : 'none';
            }}

            // If metrics is null (offline), set default offline values
            if (!metrics) {{
                metrics = {{
                    block_height: 0,
                    temporal_height: 0,
                    uptime_formatted: '0d 0h 0m',
                    tasks: 0,
                    errors: {{}},
                    udpps: null,
                    udp: {{}},
                    incoming_protos: {{}},
                    outgoing_protos: {{}}
                }};
            }}
            
            // Update block height using specific selector
            const blockHeightElement = document.querySelector('.block-value-large');
            if (blockHeightElement && metrics.block_height !== undefined) {{
                blockHeightElement.textContent = metrics.block_height.toLocaleString();
            }}

            // Update temporal height
            const temporalHeightElement = document.getElementById('temporal-height');
            if (temporalHeightElement && metrics.temporal_height !== undefined) {{
                temporalHeightElement.textContent = metrics.temporal_height.toLocaleString();
            }}
            
            // Update peer node counts (second card)
            let handshakedCount = 0;
            let pendingCount = 0;
            
            Object.values(peers).forEach(peer => {{
                if (peer.handshake_status === 'completed') {{
                    handshakedCount++;
                }} else {{
                    pendingCount++;
                }}
            }});
            
            const handshakedElement = document.getElementById('handshaked-count');
            const pendingElement = document.getElementById('pending-count');
            const tasksElement = document.getElementById('tasks-count');
            const errorsElement = document.getElementById('errors-count');
            
            if (handshakedElement) {{
                handshakedElement.textContent = handshakedCount.toLocaleString();
            }}
            if (pendingElement) {{
                pendingElement.textContent = pendingCount.toLocaleString();
            }}
            if (tasksElement && metrics.tasks !== undefined) {{
                tasksElement.textContent = metrics.tasks.toLocaleString();
            }}
            if (errorsElement && metrics.errors) {{
                // Calculate total errors from all error types
                const totalErrors = Object.values(metrics.errors).reduce((sum, count) => sum + count, 0);
                errorsElement.textContent = totalErrors.toLocaleString();
            }}
            
            // Update uptime using specific selector
            const uptimeElement = document.querySelector('.uptime-value-large');
            if (uptimeElement && metrics.uptime_formatted) {{
                uptimeElement.textContent = metrics.uptime_formatted;
            }}

            // Update UDP packet counts in overview cards
            const incomingPacketElement = document.getElementById('incoming-packet-count');
            const outgoingPacketElement = document.getElementById('outgoing-packet-count');

            if (incomingPacketElement) {{
                const incomingPackets = (metrics.udp && metrics.udp.incoming_packets !== undefined)
                    ? metrics.udp.incoming_packets
                    : 0;
                incomingPacketElement.textContent = `${{incomingPackets.toLocaleString()}}`;
            }}

            if (outgoingPacketElement) {{
                const outgoingPackets = (metrics.udp && metrics.udp.outgoing_packets !== undefined)
                    ? metrics.udp.outgoing_packets
                    : 0;
                outgoingPacketElement.textContent = `${{outgoingPackets.toLocaleString()}}`;
            }}

            // Helper function to format bytes with flexible units
            function formatBytesPerSec(bytesPerSec) {{
                if (bytesPerSec >= 1024 * 1024 * 1024) {{
                    return `${{(bytesPerSec / (1024 * 1024 * 1024)).toFixed(1)}} GB/s`;
                }} else if (bytesPerSec >= 1024 * 1024) {{
                    return `${{(bytesPerSec / (1024 * 1024)).toFixed(1)}} MB/s`;
                }} else if (bytesPerSec >= 1024) {{
                    return `${{(bytesPerSec / 1024).toFixed(1)}} KB/s`;
                }} else {{
                    return `${{Math.round(bytesPerSec)}} B/s`;
                }}
            }}

            // Helper function to format packets per second with k/M modifiers
            function formatPacketsPerSec(pps) {{
                if (pps >= 1000000) {{
                    return `${{(pps / 1000000).toFixed(1)}}M pps`;
                }} else if (pps >= 1000) {{
                    return `${{(pps / 1000).toFixed(1)}}k pps`;
                }} else {{
                    return `${{Math.round(pps)}} pps`;
                }}
            }}

            // Helper function to format memory with flexible units
            function formatMemorySize(bytes) {{
                if (bytes >= 1024 * 1024 * 1024) {{
                    return `${{(bytes / (1024 * 1024 * 1024)).toFixed(1)}} GB`;
                }} else if (bytes >= 1024 * 1024) {{
                    return `${{(bytes / (1024 * 1024)).toFixed(0)}} MB`;
                }} else if (bytes >= 1024) {{
                    return `${{(bytes / 1024).toFixed(0)}} KB`;
                }} else {{
                    return `${{Math.round(bytes)}} B`;
                }}
            }}

            // Update network I/O using udpps values directly from metrics
            const networkValues = document.querySelectorAll('.network-value');
            if (networkValues.length >= 4) {{
                if (metrics.udpps) {{
                    // Use the pre-calculated per-second values from udpps
                    const inBytesStr = formatBytesPerSec(metrics.udpps.incoming_bytes || 0);
                    const outBytesStr = formatBytesPerSec(metrics.udpps.outgoing_bytes || 0);
                    const inPpsStr = formatPacketsPerSec(metrics.udpps.incoming_packets || 0);
                    const outPpsStr = formatPacketsPerSec(metrics.udpps.outgoing_packets || 0);

                    networkValues[0].textContent = inBytesStr;
                    networkValues[1].textContent = inPpsStr;
                    networkValues[2].textContent = outBytesStr;
                    networkValues[3].textContent = outPpsStr;
                }} else if (metrics.uptime && metrics.uptime > 0) {{
                    // Fallback to calculating from totals if udpps not available
                    const uptime = metrics.uptime;
                    const inBytesPerSec = (metrics.udp?.incoming_bytes || 0) / uptime;
                    const outBytesPerSec = (metrics.udp?.outgoing_bytes || 0) / uptime;
                    const inPps = (metrics.udp?.incoming_packets || 0) / uptime;
                    const outPps = (metrics.udp?.outgoing_packets || 0) / uptime;

                    networkValues[0].textContent = formatBytesPerSec(inBytesPerSec);
                    networkValues[1].textContent = formatPacketsPerSec(inPps);
                    networkValues[2].textContent = formatBytesPerSec(outBytesPerSec);
                    networkValues[3].textContent = formatPacketsPerSec(outPps);
                }} else {{
                    // Node is offline - show zero values
                    networkValues[0].textContent = '0 B/s';    // DATA IN
                    networkValues[1].textContent = '0 pps';    // PKT IN
                    networkValues[2].textContent = '0 B/s';    // DATA OUT
                    networkValues[3].textContent = '0 pps';    // PKT OUT
                }}
            }}
            
            // Update system resources (CPU and memory)
            const resourceValues = document.querySelectorAll('.resource-value');
            const progressFills = document.querySelectorAll('.progress-fill');
            const resourceTexts = document.querySelectorAll('.resource-text');

            if (resourceValues.length >= 2 && progressFills.length >= 2) {{
                if (metrics.cpu_usage !== undefined && metrics.memory_usage !== undefined) {{
                    // CPU usage
                    const coresAvailable = metrics.cores_available || 1;
                    const cpuUsage = Math.round(metrics.cpu_usage) / coresAvailable;
                    resourceValues[0].textContent = `${{cpuUsage}}%`;
                    progressFills[0].style.width = `${{Math.min(100, Math.max(0, cpuUsage))}}%`;

                    // Memory usage - use flexible formatting
                    const memoryUsedFormatted = formatMemorySize(metrics.memory_usage || 0);
                    const totalMemoryGB = metrics.total_memory ? (metrics.total_memory / (1024 * 1024 * 1024)).toFixed(1) : '16.0';
                    const memoryPercent = metrics.total_memory ? Math.round((metrics.memory_usage * 100) / metrics.total_memory) : 0;
                    resourceValues[1].textContent = `${{memoryPercent}}%`;
                    progressFills[1].style.width = `${{Math.min(100, Math.max(0, memoryPercent))}}%`;

                    // Update resource info texts
                    if (resourceTexts.length >= 2) {{
                        // Update CPU info text with cores available
                        if (metrics.cores_available !== undefined) {{
                            resourceTexts[0].textContent = `${{metrics.cores_available}} cores available`;
                        }}
                        // Update memory info text with flexible units and total memory
                        resourceTexts[1].textContent = `${{totalMemoryGB}} GB available (${{memoryUsedFormatted}} used)`;
                    }}
                }} else {{
                    // Node is offline - show default offline values
                    resourceValues[0].textContent = '0%';
                    progressFills[0].style.width = '0%';
                    resourceValues[1].textContent = '0%';
                    progressFills[1].style.width = '0%';

                    if (resourceTexts.length >= 2) {{
                        resourceTexts[0].textContent = '0 cores available';
                        resourceTexts[1].textContent = '0 GB available (0 B used)';
                    }}
                }}
            }}
            
            // Update protocol lists
            updateProtocolList('incoming', metrics.incoming_protos || {{}});
            updateProtocolList('outgoing', metrics.outgoing_protos || {{}});
            
            // Update peers table if peers tab is active or on mobile (width <= 750px)
            const isMobile = window.innerWidth <= 750;
            if (isMobile || document.getElementById('peers-content').classList.contains('active')) {{
                updatePeersTable(peers);
            }}
        }}
        
        function updateProtocolList(type, protocols) {{
            const container = document.querySelector(`#overview-content .section-card:${{type === 'incoming' ? 'first-child' : 'last-child'}} .message-type-list`);
            if (!container) return;
            
            const items = Object.entries(protocols)
                .sort(([,a], [,b]) => b - a)
                .slice(0, 10)
                .map(([name, count]) => `
                    <div class="message-type-item">
                        <div class="message-type-name">${{name}}</div>
                        <div class="message-type-count">${{count.toLocaleString()}}</div>
                    </div>
                `)
                .join('');
            
            container.innerHTML = items || '<div class="empty-state">No data available</div>';
        }}
        
        function updatePeersTable(peers) {{
            const peerEntries = Object.entries(peers);
            
            // Update global peers data for sorting
            peersData = peerEntries.map(([address, peerInfo]) => ({{ address, peerInfo }}));
            
            // Apply current sort if any
            if (window.currentSortColumn && window.currentSortDirection) {{
                // Re-sort with current settings (userClick = false to prevent toggling)
                sortPeersTable(window.currentSortColumn, false);
            }} else {{
                // Just render without sorting
                renderPeersTable();
            }}
        }}
        
        // Auto-switch to transactions tab when user starts typing in search
        document.addEventListener('DOMContentLoaded', function() {{
            const searchInput = document.querySelector('.search-input');
            if (searchInput) {{
                searchInput.addEventListener('input', function(e) {{
                    if (e.target.value.trim().length > 0) {{
                        showTab('transactions');
                    }}
                }});
                
                searchInput.addEventListener('focus', function(e) {{
                    if (e.target.value.trim().length > 0) {{
                        showTab('transactions');
                    }}
                }});
            }}
            
            // Start auto-refresh
            refreshDashboardData();
            setInterval(refreshDashboardData, 1000);
        }});
        
        // Copy pubkey functionality
        function copyPubkey(pubkey) {{
            function showSuccessFeedback() {{
                const badge = document.querySelector('.pubkey-badge');
                const originalBg = badge.style.background;
                badge.style.background = 'hsl(142, 76%, 36%)';
                badge.style.borderColor = 'hsl(142, 76%, 36%)';
                
                const tooltip = badge.querySelector('.copy-tooltip');
                const originalText = tooltip.textContent;
                tooltip.textContent = 'Copied!';
                
                setTimeout(function() {{
                    badge.style.background = originalBg;
                    badge.style.borderColor = '';
                    tooltip.textContent = originalText;
                }}, 1000);
            }}
            
            // Check if modern clipboard API is available
            if (navigator.clipboard && navigator.clipboard.writeText) {{
                navigator.clipboard.writeText(pubkey).then(function() {{
                    showSuccessFeedback();
                }}).catch(function(err) {{
                    console.error('Clipboard API failed: ', err);
                    fallbackCopy();
                }});
            }} else {{
                fallbackCopy();
            }}
            
            function fallbackCopy() {{
                try {{
                    const textArea = document.createElement('textarea');
                    textArea.value = pubkey;
                    textArea.style.position = 'fixed';
                    textArea.style.left = '-9999px';
                    document.body.appendChild(textArea);
                    textArea.select();
                    const successful = document.execCommand('copy');
                    document.body.removeChild(textArea);
                    
                    if (successful) {{
                        showSuccessFeedback();
                    }} else {{
                        console.error('Fallback copy failed');
                    }}
                }} catch (err) {{
                    console.error('Copy failed: ', err);
                }}
            }}
        }}
    </script>
</body>
</html>
"#,
        pubkey,       // Full pubkey for onclick
        &pubkey[..8], // Shortened pubkey for display (first 8 chars)
        version,
        block_height,
        temporal_height,
        handshaked_count,
        pending_count,
        network_in_bytes_str,
        network_in_pps_str,
        network_out_bytes_str,
        network_out_pps_str,
        uptime,
        snapshot.tasks,
        total_errors,
        cpu_usage,
        cpu_usage,
        memory_usage,
        memory_usage,
        disk_usage,
        disk_usage,
        format_number(snapshot.udp.incoming_packets),
        generate_protocol_items(&snapshot.incoming_protos),
        format_number(snapshot.udp.outgoing_packets),
        generate_protocol_items(&snapshot.outgoing_protos),
    )
}
