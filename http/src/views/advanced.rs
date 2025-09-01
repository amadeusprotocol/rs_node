use ama_core::{Context, MetricsSnapshot, PeerInfo};
use std::collections::HashMap;

pub fn page(snapshot: &MetricsSnapshot, peers: &HashMap<String, PeerInfo>, _entries: &Vec<(u64, u64, u64)>, ctx: &Context) -> String {
    let peers_count = peers.len();
    let uptime = ctx.get_uptime();
    let version = ctx.get_config().get_ver();

    // Calculate network I/O rates (mock values for now)
    let network_in_mbps = 2.4;
    let network_out_mbps = 1.8;
    let network_in_pps = 156;  // packets per second
    let network_out_pps = 123; // packets per second

    // Mock system resources (in a real implementation, these would come from the context)
    let cpu_usage = 65;
    let memory_usage = 78;
    let disk_usage = 45;


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
        
        .mainnet-badge {{
            background: hsl(var(--background));
            border: 1px solid hsl(var(--foreground));
            color: hsl(var(--foreground));
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
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
        
        /* Semi-transparent badges for SYNCING and DISCONNECTED */
        .status-syncing,
        .status-disconnected {{
            opacity: 0.6;
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
            <div class="mainnet-badge">MAINNET</div>
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
                    <div class="metric-value">812,345</div>
                </div>
            </div>

            <!-- Connected Peers Card -->
            <div class="metric-card">
                <div class="metric-header">
                    <div class="metric-title">Connected Peers</div>
                    <button class="info-btn">
                        <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                    </button>
                </div>
                <div class="metric-content">
                    <svg class="metric-icon-large" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24">
                        <path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 7a4 4 0 1 0 8 0a4 4 0 1 0-8 0M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2m1-17.87a4 4 0 0 1 0 7.75M21 21v-2a4 4 0 0 0-3-3.85"/>
                    </svg>
                    <div class="metric-value">{}</div>
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
                        <div class="network-label">IN:</div>
                        <div class="network-value">{:.1} MB/s | {}k pps</div>
                    </div>
                    <div class="network-row">
                        <div class="network-label">OUT:</div>
                        <div class="network-value">{:.1} MB/s | {}k pps</div>
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
                        <div class="resource-text">8 cores available</div>
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
                            <div class="message-type-item">
                                <div class="message-type-name">Ping</div>
                                <div class="message-type-count">1,247</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Entry</div>
                                <div class="message-type-count">856</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Pong</div>
                                <div class="message-type-count">623</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Transaction</div>
                                <div class="message-type-count">412</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Consensus</div>
                                <div class="message-type-count">298</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Attestation</div>
                                <div class="message-type-count">187</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Block</div>
                                <div class="message-type-count">156</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Sync</div>
                                <div class="message-type-count">134</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Handshake</div>
                                <div class="message-type-count">89</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Heartbeat</div>
                                <div class="message-type-count">67</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Discovery</div>
                                <div class="message-type-count">45</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="section-card">
                        <div class="section-title">Outgoing Messages</div>
                        <div class="message-type-list">
                            <div class="message-type-item">
                                <div class="message-type-name">Pong</div>
                                <div class="message-type-count">1,156</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Ping</div>
                                <div class="message-type-count">934</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Entry</div>
                                <div class="message-type-count">567</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Transaction</div>
                                <div class="message-type-count">389</div>
                            </div>
                            <div class="message-type-item">
                                <div class="message-type-name">Consensus</div>
                                <div class="message-type-count">245</div>
                            </div>
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
                            <tbody>
                                <tr>
                                    <td class="font-mono">192.168.1.100:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                            </svg>
                                            <div class="status-badge">CONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">45ms</td>
                                    <td class="font-mono">812,345</td>
                                    <td class="font-mono">24.0.1</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">10.0.0.50:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                            </svg>
                                            <div class="status-badge status-syncing">SYNCING</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">120ms</td>
                                    <td class="font-mono">812,340</td>
                                    <td class="font-mono">23.0.0</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">172.16.0.25:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                            </svg>
                                            <div class="status-badge status-disconnected">DISCONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">-</td>
                                    <td class="font-mono">812,300</td>
                                    <td class="font-mono">22.1.0</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">203.0.113.15:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                            </svg>
                                            <div class="status-badge">CONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">78ms</td>
                                    <td class="font-mono">812,344</td>
                                    <td class="font-mono">24.1.0</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">198.51.100.42:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                            </svg>
                                            <div class="status-badge status-syncing">SYNCING</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">95ms</td>
                                    <td class="font-mono">812,335</td>
                                    <td class="font-mono">23.2.1</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">192.0.2.100:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                            </svg>
                                            <div class="status-badge">CONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">32ms</td>
                                    <td class="font-mono">812,345</td>
                                    <td class="font-mono">24.0.1</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">172.16.1.50:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                            </svg>
                                            <div class="status-badge status-disconnected">DISCONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">-</td>
                                    <td class="font-mono">812,280</td>
                                    <td class="font-mono">22.0.5</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">10.1.1.75:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                            </svg>
                                            <div class="status-badge status-syncing">SYNCING</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">156ms</td>
                                    <td class="font-mono">812,320</td>
                                    <td class="font-mono">23.1.2</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">203.0.113.89:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                            </svg>
                                            <div class="status-badge">CONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">67ms</td>
                                    <td class="font-mono">812,345</td>
                                    <td class="font-mono">24.0.1</td>
                                </tr>
                                <tr>
                                    <td class="font-mono">192.168.50.10:8333</td>
                                    <td>
                                        <div class="flex items-center space-x-2">
                                            <svg class="status-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px;">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                            </svg>
                                            <div class="status-badge status-disconnected">DISCONNECTED</div>
                                        </div>
                                    </td>
                                    <td class="font-mono">-</td>
                                    <td class="font-mono">812,275</td>
                                    <td class="font-mono">21.3.0</td>
                                </tr>
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
        }});
        
        // Removed auto-refresh to prevent tab switching issues
        // Auto-refresh can be added back with proper state preservation
    </script>
</body>
</html>
"#,
        version,
        peers_count,
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
    )
}