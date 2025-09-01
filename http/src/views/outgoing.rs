use std::collections::HashMap;

pub fn page(outgoing: &HashMap<String, u64>) -> String {
    let rows = rows(outgoing);
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Outgoing Messages - Dashboard</title>
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
        
        .count {{
            color: #ff9900;
            font-weight: 600;
        }}
        
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
        <h1>📤 Outgoing Messages</h1>
        <p class="subtitle">Protocol messages sent by count</p>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr><th>Message Type</th><th>Count</th></tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
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
    )
}

fn rows(outgoing: &HashMap<String, u64>) -> String {
    let mut v: Vec<(&String, &u64)> = outgoing.iter().collect();
    v.sort_by(|(_, a), (_, b)| b.cmp(a)); // sort by count descending

    let mut s = String::with_capacity(v.len() * 100);
    for (msg_type, count) in v {
        use std::fmt::Write;
        let _ = write!(
            s,
            r#"<tr>
               <td>{}</td>
               <td><span class="count">{}</span></td>
             </tr>"#,
            esc(msg_type),
            count,
        );
    }

    if s.is_empty() {
        s = r#"<tr><td colspan="2" style="text-align: center; color: #8e8e93;">No outgoing messages recorded</td></tr>"#.to_string();
    }

    s
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
