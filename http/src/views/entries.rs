use crate::utils;

pub fn page(entries: &[(u64, u64, u64)]) -> String {
    let entries_rows = entries
        .iter()
        .map(|(epoch, height, size)| {
            format!(
                r#"<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>"#,
                epoch,
                height,
                utils::format_bytes(*size)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amadeus Entries - Dashboard</title>
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
            margin-top: 20px;
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
        
        @media (max-width: 768px) {{
            .container {{ padding: 10px; }}
            h1 {{ font-size: 2rem; }}
            th, td {{ padding: 8px 6px; font-size: 14px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-btn">← Back to Dashboard</a>
        <h1>📦 Entries</h1>
        <p class="subtitle">Archived blockchain entries by epoch and height</p>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Epoch</th>
                        <th>Height</th>
                        <th>Size</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"#,
        if entries.is_empty() {
            r#"<tr><td colspan="3" style="text-align: center; padding: 40px; color: #8e8e93;">No entries found</td></tr>"#.to_string()
        } else {
            entries_rows
        }
    )
}
