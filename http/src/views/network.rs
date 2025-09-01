use crate::utils::{format_bytes, format_count};
use ama_core::UdpStats;

pub fn page(udp: &UdpStats, udpps: &Option<UdpStats>) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Network Traffic - Dashboard</title>
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
        
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .card {{
            background: #1e1e1e;
            border-radius: 12px;
            padding: 24px;
            border: 1px solid #333;
        }}
        
        .card-title {{
            color: #00d4ff;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 16px;
        }}
        
        .stat-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}
        
        .stat-label {{
            color: #8e8e93;
        }}
        
        .stat-value {{
            font-weight: 600;
            color: #ffffff;
        }}
        
        .stat-value.incoming {{
            color: #00ff88;
        }}
        
        .stat-value.outgoing {{
            color: #ff9900;
        }}
        
        .traffic-stats {{
            margin-top: 16px;
        }}
        
        .packets-line, .bytes-line {{
            font-size: 1.1rem;
            margin-bottom: 8px;
        }}
        
        .packets-line {{
            color: #00ff88;
            font-weight: 600;
        }}
        
        .bytes-line {{
            color: #ff9900;
            font-weight: 600;
        }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 15px; }}
            .cards-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-btn">← Back to Dashboard</a>
        <h1>🌐 Network Traffic</h1>
        <p class="subtitle">UDP packet and byte statistics</p>
        
        <div class="cards-grid">
            <div class="card">
                <div class="card-title">📥 Incoming</div>
                <div class="traffic-stats">
                    <div class="packets-line">Packets: {} packets{}</div>
                    <div class="bytes-line">Bytes: {} bytes{}</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">📤 Outgoing</div>
                <div class="traffic-stats">
                    <div class="packets-line">Packets: {} packets{}</div>
                    <div class="bytes-line">Bytes: {} bytes{}</div>
                </div>
            </div>
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
        format_count(udp.incoming_packets),
        format_rate_packets(udpps, true),
        format_bytes(udp.incoming_bytes),
        format_rate_bytes(udpps, true),
        format_count(udp.outgoing_packets),
        format_rate_packets(udpps, false),
        format_bytes(udp.outgoing_bytes),
        format_rate_bytes(udpps, false),
    )
}

fn format_rate_packets(udpps: &Option<UdpStats>, is_incoming: bool) -> String {
    if let Some(rates) = udpps {
        let count = if is_incoming { rates.incoming_packets } else { rates.outgoing_packets };
        format!(" ({} pps)", format_count(count))
    } else {
        String::new()
    }
}

fn format_rate_bytes(udpps: &Option<UdpStats>, is_incoming: bool) -> String {
    if let Some(rates) = udpps {
        let bytes = if is_incoming { rates.incoming_bytes } else { rates.outgoing_bytes };
        format!(" ({}/s)", format_bytes(bytes))
    } else {
        String::new()
    }
}
