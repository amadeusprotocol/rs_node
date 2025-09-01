use crate::utils::{format_bytes, format_count, get_top_items};
use ama_core::{Context, MetricsSnapshot, PeerInfo};
use std::collections::HashMap;

pub fn page(snapshot: &MetricsSnapshot, peers: &HashMap<String, PeerInfo>, ctx: &Context) -> String {
    let total_errors: u64 = snapshot.errors.values().sum();
    let total_packets = snapshot.udp.incoming_packets + snapshot.udp.outgoing_packets;
    let total_bytes = snapshot.udp.incoming_bytes + snapshot.udp.outgoing_bytes;
    let peers_count = peers.len();

    let uptime = ctx.get_uptime();

    let top_incoming = get_top_items(&snapshot.incoming_protos, 3);
    let top_outgoing = get_top_items(&snapshot.outgoing_protos, 3);

    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Node Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: system-ui, -apple-system, sans-serif; 
            background: #0f1419;
            color: #ffffff;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #00d4ff; margin-bottom: 10px; text-align: center; font-size: 2.5rem; }}
        .subtitle {{ text-align: center; color: #8e8e93; margin-bottom: 40px; font-size: 1.1rem; }}
        
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
        }}
        
        .card {{
            background: #1e1e1e;
            border-radius: 12px;
            padding: 24px;
            border: 1px solid #333;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            color: inherit;
            display: block;
        }}
        
        .card:hover {{
            background: #252525;
            border-color: #00d4ff;
            transform: translateY(-2px);
        }}
        
        .card-icon {{
            font-size: 2.5rem;
            margin-bottom: 12px;
        }}
        
        .card-title {{
            color: #00d4ff;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 12px;
        }}
        
        .card-content {{
            color: #8e8e93;
            font-size: 0.9rem;
            line-height: 1.4;
        }}
        
        .card-main-stat {{
            color: #ffffff;
            font-size: 1.8rem;
            font-weight: 700;
            margin: 8px 0;
        }}
        
        .card-sub-stat {{
            color: #8e8e93;
            font-size: 0.85rem;
        }}
        
        .errors {{
            color: #ff4444;
        }}
        
        .uptime {{
            color: #00ff88;
        }}
        
        .network {{
            color: #00ff88;
        }}
        
        .peers {{
            color: #ff9900;
        }}
        
        .messages {{
            color: #9966ff;
        }}
        
        .entries {{
            color: #00d4ff;
        }}
        
        .message-list {{
            margin-top: 8px;
        }}
        
        .message-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            margin-bottom: 4px;
            color: #aaa;
        }}
        
        .message-count {{
            font-weight: 600;
            color: #ffffff;
        }}
        
        .dots {{
            text-align: center;
            margin-top: 8px;
            color: #666;
            font-size: 1.2rem;
        }}
        
        .epoch-list {{
            margin-top: 8px;
        }}
        
        .epoch-item {{
            background: #2a2a2a;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-bottom: 4px;
            color: #00d4ff;
            font-family: monospace;
        }}
        
        @media (max-width: 1024px) {{
            .cards-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 15px; }}
            .cards-grid {{ 
                grid-template-columns: 1fr;
                gap: 16px;
            }}
            h1 {{ font-size: 2rem; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Amadeus Node</h1>
        <p class="subtitle">Real-time node monitoring and statistics</p>
        
        <div class="cards-grid">
            <a href="/errors" class="card">
                <div class="card-icon">⚠️</div>
                <div class="card-title">System Status</div>
                <div class="card-main-stat uptime">{} uptime</div>
                <div class="card-sub-stat errors">{} errors</div>
            </a>
            
            <a href="/network" class="card">
                <div class="card-icon">🌐</div>
                <div class="card-title">Network Traffic</div>
                <div class="card-main-stat network">{} packets</div>
                <div class="card-main-stat network">{} bytes</div>
            </a>
            
            <a href="/peers" class="card">
                <div class="card-icon">👥</div>
                <div class="card-title">Peers</div>
                <div class="card-sub-stat">online</div>
                <div class="card-main-stat peers">{}</div>
            </a>
            
            <a href="/incoming" class="card">
                <div class="card-icon">📥</div>
                <div class="card-title">Messages Incoming</div>
                <div class="message-list">
                    {}
                </div>
                <div class="dots">⋯</div>
            </a>
            
            <a href="/outgoing" class="card">
                <div class="card-icon">📤</div>
                <div class="card-title">Messages Outgoing</div>
                <div class="message-list">
                    {}
                </div>
                <div class="dots">⋯</div>
            </a>
            
            <a href="/entries" class="card">
                <div class="card-icon">📦</div>
                <div class="card-title">Entries</div>
                <div class="epoch-list">
                    <div class="epoch-item">Epoch 201</div>
                    <div class="epoch-item">Epoch 202</div>
                    <div class="epoch-item">Epoch 203</div>
                </div>
                <div class="dots">⋯</div>
            </a>
        </div>
    </div>
    <script>
        // Auto-refresh page every second
        setInterval(() => {{
            location.reload();
        }}, 1000);
    </script>
</body>
</html>
"#,
        uptime,
        total_errors,
        format_count(total_packets),
        format_bytes(total_bytes),
        peers_count,
        format_message_list(&top_incoming),
        format_message_list(&top_outgoing),
    )
}

fn format_message_list(messages: &[(String, u64)]) -> String {
    if messages.is_empty() {
        return r#"<div class="message-item" style="color: #666;">No messages recorded</div>"#.to_string();
    }

    let mut result = String::new();
    for (msg_type, count) in messages {
        result.push_str(&format!(
            r#"<div class="message-item">
                <span>{}</span>
                <span class="message-count">{}</span>
            </div>"#,
            esc(msg_type),
            count
        ));
    }
    result
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
