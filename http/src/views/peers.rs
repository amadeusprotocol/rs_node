use ama_core::PeerInfo;
use ama_core::utils::misc::get_unix_millis_now;
use std::collections::HashMap;

pub fn page(peers: &HashMap<String, PeerInfo>) -> String {
    let rows = rows(peers);
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Peers - Dashboard</title>
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
        
        .table-container {{
            background: #1e1e1e;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #333;
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        
        th {{
            color: #00d4ff;
            font-weight: 600;
            background: #2a2a2a;
        }}
        
        tbody tr {{
            background: #1e1e1e;
        }}
        
        tbody tr:nth-child(even) {{
            background: #252525;
        }}
        
        tr:hover {{
            background: #2a2a2a;
        }}
        
        .pill {{
            background: #00d4ff20;
            color: #00d4ff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }}
        
        .muted {{
            color: #8e8e93;
        }}
        
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
            table {{ font-size: 0.9rem; }}
            th, td {{ padding: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-btn">← Back to Dashboard</a>
        <h1>🌐 Network Peers</h1>
        <p class="subtitle">Connected peer information</p>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr><th>Address</th><th>Version</th><th>Status</th><th>Last Message</th><th>Last Seen</th></tr>
                </thead>
                <tbody id="peer-tbody">
                    {rows}
                </tbody>
            </table>
        </div>
        
        <button class="refresh-btn" onclick="loadPeers()">Refresh Peers</button>
    </div>

<script>
let peersData = {{}};

async function loadPeers() {{
    try {{
        const response = await fetch('/peers/json');
        if (response.ok) {{
            peersData = await response.json();
            renderPeers();
        }}
    }} catch (error) {{
        console.error('Error loading peers:', error);
    }}
}}

function renderPeers() {{
    const tbody = document.getElementById('peer-tbody');
    let html = '';
    
    const sortedPeers = Object.entries(peersData).sort(([,a], [,b]) => 
        (b.last_ts || 0) - (a.last_ts || 0)
    );
    
    for (const [addr, info] of sortedPeers) {{
        const timeAgo = getTimeAgo(info.last_ts || 0);
        const status = getHandshakeStatusDisplay(info.handshake_status);
        html += `<tr>
            <td>${{esc(addr)}}</td>
            <td>${{esc(info.version || 'N/A')}}</td>
            <td>${{status}}</td>
            <td>${{esc(info.last_msg || 'N/A')}}</td>
            <td>${{timeAgo}}</td>
        </tr>`;
    }}
    
    tbody.innerHTML = html || '<tr><td colspan="5" style="text-align: center; color: #8e8e93;">No peers connected</td></tr>';
}}

function getHandshakeStatusDisplay(status) {{
    switch (status) {{
        case 'none':
            return '<span class="pill" style="background: #66666620; color: #666666;">⭕ disconnected</span>';
        case 'sent_new_phone_who_dis':
            return '<span class="pill" style="background: #ffaa0020; color: #ffaa00;">⏳ connecting</span>';
        case 'sent_what':
            return '<span class="pill" style="background: #00ff0020; color: #00ff00;">✅ connected</span>';
        case 'received_what':
            return '<span class="pill" style="background: #00ff0020; color: #00ff00;">✅ connected</span>';
        case 'failed':
            return '<span class="pill" style="background: #ff000020; color: #ff0000;">❌ failed</span>';
        default:
            return '<span class="pill" style="background: #66666620; color: #666666;">❓ unknown</span>';
    }}
}}

function getTimeAgo(lastTs) {{
    const now = Math.floor(Date.now() / 1000);
    const lastTsSeconds = Math.floor(lastTs / 1000); // Convert ms to seconds
    const diff = now - lastTsSeconds;
    if (diff < 60) return `${{diff}}s ago`;
    if (diff < 3600) return `${{Math.floor(diff / 60)}}m ago`;
    if (diff < 86400) return `${{Math.floor(diff / 3600)}}h ago`;
    return `${{Math.floor(diff / 86400)}}d ago`;
}}

function esc(s) {{
    return String(s)
        .replace(/&/g,'&amp;')
        .replace(/</g,'&lt;')
        .replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;')
        .replace(/'/g,'&#39;');
}}

// Load peers on page load
loadPeers();

// Auto-refresh every 1 second
setInterval(loadPeers, 1000);
</script>
</body>
</html>
"#,
    )
}

fn get_handshake_status_html(status: &ama_core::node::peers::HandshakeStatus) -> &'static str {
    use ama_core::node::peers::HandshakeStatus;
    match status {
        HandshakeStatus::None => {
            "<span class=\"pill\" style=\"background: #66666620; color: #666666;\">⭕ disconnected</span>"
        }
        HandshakeStatus::Initiated => {
            "<span class=\"pill\" style=\"background: #ffaa0020; color: #ffaa00;\">⏳ connecting</span>"
        }
        HandshakeStatus::Completed => {
            "<span class=\"pill\" style=\"background: #00ff0020; color: #00ff00;\">✅ connected</span>"
        }
    }
}

pub fn rows(peers: &HashMap<String, PeerInfo>) -> String {
    // snapshot & sort newest first
    let mut v: Vec<(&String, &PeerInfo)> = peers.iter().collect();
    v.sort_by(|(_, a), (_, b)| b.last_ts.cmp(&a.last_ts));

    let mut s = String::with_capacity(v.len() * 96);
    for (addr, info) in v {
        use std::fmt::Write;
        let time_ago = get_time_ago(info.last_ts);
        let status_html = get_handshake_status_html(&info.handshake_status);
        let _ = write!(
            s,
            "<tr>\
               <td>{}</td>\
               <td>{}</td>\
               <td>{}</td>\
               <td>{}</td>\
               <td>{}</td>\
             </tr>",
            esc(addr),
            esc(info.version.as_deref().unwrap_or("N/A")),
            status_html,
            esc(&info.last_msg),
            time_ago,
        );
    }
    s
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn get_time_ago(last_ts: u64) -> String {
    let now = get_unix_millis_now();
    let last_ts_secs = last_ts / 1000; // convert ms to seconds
    let diff = now.saturating_sub(last_ts_secs);
    if diff < 60 {
        format!("{}s", diff)
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else {
        format!("{}h", diff / 3600)
    }
}
