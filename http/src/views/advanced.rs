use ama_core::node::peers::HandshakeStatus;
use ama_core::{Context, MetricsSnapshot, PeerInfo};
use std::collections::HashMap;

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

    // Get uptime in seconds from metrics snapshot
    let uptime_seconds = snapshot.uptime as f64;

    // Calculate network I/O rates from actual metrics
    let incoming_bytes = snapshot.udp.incoming_bytes as f64;
    let outgoing_bytes = snapshot.udp.outgoing_bytes as f64;
    let incoming_packets = snapshot.udp.incoming_packets;
    let outgoing_packets = snapshot.udp.outgoing_packets;

    let network_in_mbps =
        if uptime_seconds > 0.0 { (incoming_bytes / uptime_seconds) / (1024.0 * 1024.0) } else { 0.0 };
    let network_out_mbps =
        if uptime_seconds > 0.0 { (outgoing_bytes / uptime_seconds) / (1024.0 * 1024.0) } else { 0.0 };
    let network_in_pps = if uptime_seconds > 0.0 { incoming_packets as f64 / uptime_seconds } else { 0.0 };
    let network_out_pps = if uptime_seconds > 0.0 { outgoing_packets as f64 / uptime_seconds } else { 0.0 };

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
            gap: 12px;
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
            min-height: 160px;
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
            flex: 1;
            overflow: hidden;
        }}
        
        .tab-content.active {{
            display: flex;
            flex-direction: column;
            flex: 1;
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
            margin-bottom: 20px;
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
        
        @media (max-width: 768px) {{
            .container {{ padding: 16px; }}
            .header {{ padding: 12px 16px; }}
            .metrics-grid {{
                grid-template-columns: 1fr;
            }}
            .search-input {{ width: 180px; }}
            .tab-list {{
                flex-direction: column;
            }}
            
            /* Switch to compact logo on small screens */
            .logo-wordmark {{
                display: none;
            }}
            
            .logo-compact {{
                display: block;
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
        </div>
        <div class="header-right">
            <div class="search-container">
                <svg class="search-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <input type="text" class="search-input" placeholder="Search transactions..." />
            </div>
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
                <div class="metric-content">
                    <svg class="metric-icon-large" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24">
                        <g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">
                            <path d="M4 6a8 3 0 1 0 16 0A8 3 0 1 0 4 6"/>
                            <path d="M4 6v6a8 3 0 0 0 16 0V6"/>
                            <path d="M4 12v6a8 3 0 0 0 16 0v-6"/>
                        </g>
                    </svg>
                    <div class="metric-value">{}</div>
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
                        <div class="network-value">{:.1}</div>
                    </div>
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 20H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h8m4 0v17m-3-3l3 3l3-3"/>
                            </svg>
                            <div class="network-label">PKT IN:</div>
                        </div>
                        <div class="network-value">{:.0}</div>
                    </div>
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21v-6m13-9l-3-3l-3 3m3-3v18m-7-3l-3 3l-3-3M7 3v2m0 4v2"/>
                            </svg>
                            <div class="network-label">DATA OUT:</div>
                        </div>
                        <div class="network-value">{:.1}</div>
                    </div>
                    <div class="network-row">
                        <div class="network-left">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" class="network-icon">
                                <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8m4 0V3m-3 3l3-3l3 3"/>
                            </svg>
                            <div class="network-label">PKT OUT:</div>
                        </div>
                        <div class="network-value">{:.0}</div>
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
                <div class="metric-content">
                    <svg class="metric-icon-large" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24">
                        <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12h4.5L9 6l4 12l2-9l1.5 3H21"/>
                    </svg>
                    <div class="metric-value">{}</div>
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
                        <div class="resource-text">16GB total</div>
                    </div>
                </div>
                
                <div class="resource-item">
                    <div class="resource-header">
                        <div class="resource-label">Disk Usage</div>
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
                        <div class="resource-text">2TB available</div>
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
                        <div class="section-title">Incoming Messages</div>
                        <div class="message-type-list">
                            {}
                        </div>
                    </div>
                    
                    <div class="section-card">
                        <div class="section-title">Outgoing Messages</div>
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
                                    <th>ADDRESS</th>
                                    <th>STATUS</th>
                                    <th>LATENCY</th>
                                    <th>BLOCK HEIGHT</th>
                                    <th>VERSION</th>
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
                }}
            }} catch (error) {{
                console.warn('Failed to refresh dashboard data:', error);
            }} finally {{
                isRefreshing = false;
            }}
        }}
        
        function updateMetricsDisplay(metrics, peers) {{
            // Update all metric cards
            const metricValues = document.querySelectorAll('.metric-value');
            const peerCount = Object.keys(peers).length;
            
            // Update block height (first card - index 0)
            if (metricValues.length > 0 && metrics.block_height !== undefined) {{
                metricValues[0].textContent = metrics.block_height.toLocaleString();
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
            
            if (handshakedElement) {{
                handshakedElement.textContent = handshakedCount.toLocaleString();
            }}
            if (pendingElement) {{
                pendingElement.textContent = pendingCount.toLocaleString();
            }}
            
            // Update uptime (fourth card - index 1 in metricValues array, since Peer Nodes and Network I/O don't have metric-value)
            if (metricValues.length > 1 && metrics.uptime_formatted) {{
                metricValues[1].textContent = metrics.uptime_formatted;
            }}
            
            // Update network I/O if we have uptime data
            if (metrics.uptime && metrics.uptime > 0) {{
                const uptime = metrics.uptime;
                const inMbps = ((metrics.udp?.incoming_bytes || 0) / uptime) / (1024 * 1024);
                const outMbps = ((metrics.udp?.outgoing_bytes || 0) / uptime) / (1024 * 1024);
                const inPps = (metrics.udp?.incoming_packets || 0) / uptime;
                const outPps = (metrics.udp?.outgoing_packets || 0) / uptime;
                
                const networkValues = document.querySelectorAll('.network-value');
                if (networkValues.length >= 4) {{
                    networkValues[0].textContent = `${{inMbps.toFixed(1)}} MB/s`;
                    networkValues[1].textContent = `${{Math.round(inPps).toLocaleString()}} pkt/s`;
                    networkValues[2].textContent = `${{outMbps.toFixed(1)}} MB/s`;
                    networkValues[3].textContent = `${{Math.round(outPps).toLocaleString()}} pkt/s`;
                }}
            }}
            
            // Update system resources (CPU and memory)
            if (metrics.cpu_usage !== undefined && metrics.memory_usage !== undefined) {{
                const resourceValues = document.querySelectorAll('.resource-value');
                const progressFills = document.querySelectorAll('.progress-fill');
                
                if (resourceValues.length >= 2 && progressFills.length >= 2) {{
                    // CPU usage
                    const coresAvailable = metrics.cores_available || 1;
                    const cpuUsage = Math.round(metrics.cpu_usage) / coresAvailable;
                    resourceValues[0].textContent = `${{cpuUsage}}%`;
                    progressFills[0].style.width = `${{Math.min(100, Math.max(0, cpuUsage))}}%`;
                    
                    // Memory usage
                    const memoryMB = (metrics.memory_usage / 1024 / 1024).toFixed(0);
                    const memoryPercent = Math.round((metrics.memory_usage / 1024 / 1024) * 100 / 16384); // Assuming 16GB total
                    resourceValues[1].textContent = `${{memoryPercent}}%`;
                    progressFills[1].style.width = `${{Math.min(100, Math.max(0, memoryPercent))}}%`;
                    
                    // Update resource info texts
                    const resourceTexts = document.querySelectorAll('.resource-text');
                    if (resourceTexts.length >= 2) {{
                        // Update CPU info text with cores available
                        if (metrics.cores_available !== undefined) {{
                            resourceTexts[0].textContent = `${{metrics.cores_available}} cores available`;
                        }}
                        // Update memory info text  
                        resourceTexts[1].textContent = `${{memoryMB}} MB used`;
                    }}
                }}
            }}
            
            // Update protocol lists
            updateProtocolList('incoming', metrics.incoming_protos || {{}});
            updateProtocolList('outgoing', metrics.outgoing_protos || {{}});
            
            // Update peers table if peers tab is active
            if (document.getElementById('peers-content').classList.contains('active')) {{
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
            const tbody = document.getElementById('peers-table-body');
            if (!tbody) return;
            
            const peerEntries = Object.entries(peers);
            if (peerEntries.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: #9ca3af; font-style: italic;">No peers connected</td></tr>';
                return;
            }}
            
            const rows = peerEntries.map(([address, peerInfo]) => {{
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
                }} else if (handshakeStatus === 'Initiated') {{
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
                const blockHeight = peerInfo.block_height || '-';
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
                        <td class="font-mono">${{typeof blockHeight === 'number' ? blockHeight.toLocaleString() : blockHeight}}</td>
                        <td class="font-mono">${{version}}</td>
                    </tr>
                `;
            }}).join('');
            
            tbody.innerHTML = rows;
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
        handshaked_count,
        pending_count,
        network_in_mbps,
        network_in_pps,
        network_out_mbps,
        network_out_pps,
        uptime,
        cpu_usage,
        cpu_usage,
        memory_usage,
        memory_usage,
        disk_usage,
        disk_usage,
        generate_protocol_items(&snapshot.incoming_protos),
        generate_protocol_items(&snapshot.outgoing_protos),
    )
}
