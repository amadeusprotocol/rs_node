use serde_json::Value;

pub fn page(metrics: Value) -> String {
    let uptime_seconds = metrics["uptime"].as_u64().unwrap_or(0);
    let uptime_formatted = format_uptime(uptime_seconds);

    let packets = &metrics["packets"];
    let total_incoming_bytes = packets["total_incoming_bytes"].as_u64().unwrap_or(0);
    let total_incoming_packets = packets["total_incoming_packets"].as_u64().unwrap_or(0);
    let total_outgoing_bytes = packets["total_outgoing_bytes"].as_u64().unwrap_or(0);
    let total_outgoing_packets = packets["total_outgoing_packets"].as_u64().unwrap_or(0);
    let incoming_bytes_per_second = packets["incoming_bytes_per_second"].as_u64().unwrap_or(0);
    let incoming_packets_per_second = packets["incoming_packets_per_second"].as_u64().unwrap_or(0);
    let outgoing_bytes_per_second = packets["outgoing_bytes_per_second"].as_u64().unwrap_or(0);
    let outgoing_packets_per_second = packets["outgoing_packets_per_second"].as_u64().unwrap_or(0);

    let incoming_bytes_formatted = format_bytes(total_incoming_bytes);
    let outgoing_bytes_formatted = format_bytes(total_outgoing_bytes);
    let incoming_bytes_per_sec_formatted = format_bytes(incoming_bytes_per_second);
    let outgoing_bytes_per_sec_formatted = format_bytes(outgoing_bytes_per_second);

    // Protocol counts from handled_protos (received)
    let empty_map = serde_json::Map::new();
    let handled_protos = metrics["handled_protos"].as_object().unwrap_or(&empty_map);
    let ping_received = handled_protos.get("ping").and_then(|v| v.as_u64()).unwrap_or(0);
    let pong_received = handled_protos.get("pong").and_then(|v| v.as_u64()).unwrap_or(0);
    let entry_received = handled_protos.get("entry").and_then(|v| v.as_u64()).unwrap_or(0);
    let attestation_received = handled_protos.get("attestation_bulk").and_then(|v| v.as_u64()).unwrap_or(0);
    let txpool_received = handled_protos.get("txpool").and_then(|v| v.as_u64()).unwrap_or(0);

    // Protocol counts from sent_packets (sent)
    let sent_packets = metrics["sent_packets"].as_object().unwrap_or(&empty_map);
    let ping_sent = sent_packets.get("ping").and_then(|v| v.as_u64()).unwrap_or(0);
    let pong_sent = sent_packets.get("pong").and_then(|v| v.as_u64()).unwrap_or(0);
    let entry_sent = sent_packets.get("entry").and_then(|v| v.as_u64()).unwrap_or(0);
    let attestation_sent = sent_packets.get("attestation_bulk").and_then(|v| v.as_u64()).unwrap_or(0);
    let txpool_sent = sent_packets.get("txpool").and_then(|v| v.as_u64()).unwrap_or(0);
    let new_phone_who_dis_sent = sent_packets.get("new_phone_who_dis").and_then(|v| v.as_u64()).unwrap_or(0);
    let what_sent = sent_packets.get("what").and_then(|v| v.as_u64()).unwrap_or(0);

    // Error counts
    let empty_errors_map = serde_json::Map::new();
    let errors = metrics["errors"].as_object().unwrap_or(&empty_errors_map);
    let total_errors: u64 = errors.values().filter_map(|v| v.as_u64()).sum();

    let total_received = ping_received + pong_received + entry_received + attestation_received + txpool_received;
    let total_sent =
        ping_sent + pong_sent + entry_sent + attestation_sent + txpool_sent + new_phone_who_dis_sent + what_sent;

    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Metrics - Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: system-ui, -apple-system, sans-serif; 
            background: #0f1419;
            color: #ffffff;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #00d4ff; margin-bottom: 10px; text-align: center; }}
        .subtitle {{ text-align: center; color: #8e8e93; margin-bottom: 30px; }}
        
        .back-btn {{
            background: #333;
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            margin-bottom: 20px;
            text-decoration: none;
            display: inline-block;
        }}
        .back-btn:hover {{ background: #444; }}
        
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ 
            background: #1e1e1e; 
            border-radius: 12px; 
            padding: 20px; 
            border: 1px solid #333;
            transition: transform 0.2s ease;
        }}
        .card:hover {{ transform: translateY(-2px); }}
        
        .card h3 {{ color: #00d4ff; margin-bottom: 15px; font-size: 1.1rem; }}
        .metric {{ display: flex; justify-content: space-between; margin-bottom: 10px; }}
        .metric:last-child {{ margin-bottom: 0; }}
        .metric-label {{ color: #8e8e93; }}
        .metric-value {{ color: #ffffff; font-weight: 600; }}
        
        .status {{ 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.85rem;
            font-weight: 500;
        }}
        .status.online {{ background: #00d4ff20; color: #00d4ff; }}
        .status.error {{ background: #ff453520; color: #ff4535; }}
        
        .refresh-btn {{
            background: #00d4ff;
            color: #0f1419;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            margin: 20px auto;
            display: block;
        }}
        .refresh-btn:hover {{ background: #0099cc; }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 15px; }}
            .grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-btn">← Back to Dashboard</a>
        <h1>📊 Network Metrics</h1>
        <p class="subtitle">Detailed network and protocol statistics</p>
        
        <div class="grid">
            <div class="card">
                <h3>📥 Incoming Traffic</h3>
                <div class="metric">
                    <span class="metric-label">Messages Received:</span>
                    <span class="metric-value" id="total-received">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Bytes Received:</span>
                    <span class="metric-value" id="total-incoming-bytes">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Packets Received:</span>
                    <span class="metric-value" id="total-incoming-packets">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Packets/sec:</span>
                    <span class="metric-value" id="incoming-packets-per-second">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Bytes/sec:</span>
                    <span class="metric-value" id="incoming-bytes-per-second">{}</span>
                </div>
            </div>

            <div class="card">
                <h3>📤 Outgoing Traffic</h3>
                <div class="metric">
                    <span class="metric-label">Messages Sent:</span>
                    <span class="metric-value" id="total-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Bytes Sent:</span>
                    <span class="metric-value" id="total-outgoing-bytes">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Packets Sent:</span>
                    <span class="metric-value" id="total-outgoing-packets">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Packets/sec:</span>
                    <span class="metric-value" id="outgoing-packets-per-second">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Bytes/sec:</span>
                    <span class="metric-value" id="outgoing-bytes-per-second">{}</span>
                </div>
            </div>

            <div class="card">
                <h3>⏱️ System Status</h3>
                <div class="metric">
                    <span class="metric-label">Uptime:</span>
                    <span class="metric-value" id="uptime">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Total Errors:</span>
                    <span class="metric-value" id="total-errors">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Status:</span>
                    <span class="status online">Online</span>
                </div>
            </div>

            <div class="card">
                <h3>📝 Messages Received</h3>
                <div class="metric">
                    <span class="metric-label">Ping:</span>
                    <span class="metric-value" id="ping-received">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Pong:</span>
                    <span class="metric-value" id="pong-received">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Entries:</span>
                    <span class="metric-value" id="entry-received">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Attestations:</span>
                    <span class="metric-value" id="attestation-received">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">TxPool:</span>
                    <span class="metric-value" id="txpool-received">{}</span>
                </div>
            </div>

            <div class="card">
                <h3>📤 Messages Sent</h3>
                <div class="metric">
                    <span class="metric-label">Ping:</span>
                    <span class="metric-value" id="ping-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Pong:</span>
                    <span class="metric-value" id="pong-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Entries:</span>
                    <span class="metric-value" id="entry-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Attestations:</span>
                    <span class="metric-value" id="attestation-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">TxPool:</span>
                    <span class="metric-value" id="txpool-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">NewPhoneWhoDis:</span>
                    <span class="metric-value" id="new-phone-who-dis-sent">{}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">What:</span>
                    <span class="metric-value" id="what-sent">{}</span>
                </div>
            </div>
        </div>
        
        <button class="refresh-btn" onclick="fetchMetrics()">Refresh Metrics</button>
    </div>

<script>
function formatBytes(bytes) {{
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}}

function formatUptime(seconds) {{
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  let parts = [];
  if (days > 0) parts.push(`${{days}}d`);
  if (hours > 0) parts.push(`${{hours}}h`);
  if (minutes > 0) parts.push(`${{minutes}}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${{secs}}s`);
  
  return parts.join(' ');
}}

async function fetchMetrics() {{
  try {{
    const response = await fetch('/metrics/json');
    const metrics = await response.json();
    
    const packets = metrics.packets || {{}};
    const handledProtos = metrics.handled_protos || {{}};
    const sentPackets = metrics.sent_packets || {{}};
    const errors = metrics.errors || {{}};
    
    const totalErrors = Object.values(errors).reduce((sum, val) => sum + (val || 0), 0);
    const totalReceived = Object.values(handledProtos).reduce((sum, val) => sum + (val || 0), 0);
    const totalSent = Object.values(sentPackets).reduce((sum, val) => sum + (val || 0), 0);
    
    // Incoming traffic
    document.getElementById('total-received').textContent = totalReceived.toLocaleString();
    document.getElementById('total-incoming-bytes').textContent = formatBytes(packets.total_incoming_bytes || 0);
    document.getElementById('total-incoming-packets').textContent = (packets.total_incoming_packets || 0).toLocaleString();
    document.getElementById('incoming-packets-per-second').textContent = (packets.incoming_packets_per_second || 0);
    document.getElementById('incoming-bytes-per-second').textContent = formatBytes(packets.incoming_bytes_per_second || 0);
    
    // Outgoing traffic
    document.getElementById('total-sent').textContent = totalSent.toLocaleString();
    document.getElementById('total-outgoing-bytes').textContent = formatBytes(packets.total_outgoing_bytes || 0);
    document.getElementById('total-outgoing-packets').textContent = (packets.total_outgoing_packets || 0).toLocaleString();
    document.getElementById('outgoing-packets-per-second').textContent = (packets.outgoing_packets_per_second || 0);
    document.getElementById('outgoing-bytes-per-second').textContent = formatBytes(packets.outgoing_bytes_per_second || 0);
    
    // System status
    document.getElementById('uptime').textContent = formatUptime(metrics.uptime || 0);
    document.getElementById('total-errors').textContent = totalErrors.toLocaleString();
    
    // Messages received
    document.getElementById('ping-received').textContent = (handledProtos.ping || 0).toLocaleString();
    document.getElementById('pong-received').textContent = (handledProtos.pong || 0).toLocaleString();
    document.getElementById('entry-received').textContent = (handledProtos.entry || 0).toLocaleString();
    document.getElementById('attestation-received').textContent = (handledProtos.attestation_bulk || 0).toLocaleString();
    document.getElementById('txpool-received').textContent = (handledProtos.txpool || 0).toLocaleString();
    
    // Messages sent
    document.getElementById('ping-sent').textContent = (sentPackets.ping || 0).toLocaleString();
    document.getElementById('pong-sent').textContent = (sentPackets.pong || 0).toLocaleString();
    document.getElementById('entry-sent').textContent = (sentPackets.entry || 0).toLocaleString();
    document.getElementById('attestation-sent').textContent = (sentPackets.attestation_bulk || 0).toLocaleString();
    document.getElementById('txpool-sent').textContent = (sentPackets.txpool || 0).toLocaleString();
    document.getElementById('new-phone-who-dis-sent').textContent = (sentPackets.new_phone_who_dis || 0).toLocaleString();
    document.getElementById('what-sent').textContent = (sentPackets.what || 0).toLocaleString();
  }} catch (e) {{
    console.error('Failed to fetch metrics:', e);
  }}
}}

// Load metrics on page load
fetchMetrics();

// Auto-refresh every 1 second
setInterval(fetchMetrics, 1000);
</script>
</body>
</html>
"#,
        total_received,
        incoming_bytes_formatted,
        total_incoming_packets,
        incoming_packets_per_second,
        incoming_bytes_per_sec_formatted,
        total_sent,
        outgoing_bytes_formatted,
        total_outgoing_packets,
        outgoing_packets_per_second,
        outgoing_bytes_per_sec_formatted,
        uptime_formatted,
        total_errors,
        ping_received,
        pong_received,
        entry_received,
        attestation_received,
        txpool_received,
        ping_sent,
        pong_sent,
        entry_sent,
        attestation_sent,
        txpool_sent,
        new_phone_who_dis_sent,
        what_sent,
    )
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let k = 1024_f64;
    let i = (bytes as f64).log(k).floor() as usize;
    let i = i.min(UNITS.len() - 1);
    let size = bytes as f64 / k.powi(i as i32);
    format!("{:.1} {}", size, UNITS[i])
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{}s", secs));
    }

    parts.join(" ")
}
