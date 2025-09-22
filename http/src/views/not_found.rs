pub fn page() -> String {
    r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | Amadeus</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --background: 0 0% 3.9%;
            --foreground: 0 0% 98%;
            --muted: 0 0% 14.9%;
            --muted-foreground: 0 0% 63.9%;
            --border: 0 0% 14.9%;
            --card: 0 0% 3.9%;
            --card-foreground: 0 0% 98%;
            --primary: 0 0% 98%;
            --primary-foreground: 0 0% 9%;
            --secondary: 0 0% 14.9%;
            --secondary-foreground: 0 0% 98%;
            --accent: 0 0% 14.9%;
            --accent-foreground: 0 0% 98%;
            --ring: 0 0% 83.1%;
            --radius: 0.5rem;
        }

        html, body {
            height: 100vh;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            background: hsl(var(--background));
            color: hsl(var(--foreground));
            line-height: 1.6;
            font-size: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            position: relative;
            overflow: hidden;
        }

        /* Grid background pattern */
        .grid-bg {
            position: fixed;
            inset: 0;
            z-index: 0;
            opacity: 0.1;
            background-image:
                linear-gradient(to right, hsl(var(--border)) 1px, transparent 1px),
                linear-gradient(to bottom, hsl(var(--border)) 1px, transparent 1px);
            background-size: 32px 32px;
        }

        .container {
            position: relative;
            z-index: 10;
            text-align: center;
            max-width: 800px;
            padding: 24px;
            animation: fadeInUp 0.8s ease-out;
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideInScale {
            from {
                opacity: 0;
                transform: scale(0.9);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        .amadeus-wordmark {
            margin-bottom: 3rem;
            animation: slideInScale 1s ease-out 0.2s both;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }

        .amadeus-logo {
            width: clamp(280px, 50vw, 480px);
            height: auto;
            opacity: 0.95;
            transition: all 0.3s ease;
            /* The wordmark-light.svg is already optimized for dark backgrounds */
        }

        .amadeus-logo:hover {
            opacity: 1;
            filter: drop-shadow(0 0 20px rgba(0, 240, 222, 0.3));
            transform: scale(1.02);
        }

        .error-code {
            font-size: 2.5rem;
            font-weight: 600;
            color: hsl(var(--muted-foreground));
            margin-bottom: 1rem;
            animation: fadeInUp 0.8s ease-out 0.4s both;
        }

        .error-message {
            font-size: 1.5rem;
            font-weight: 500;
            color: hsl(var(--foreground));
            margin-bottom: 1rem;
            animation: fadeInUp 0.8s ease-out 0.6s both;
        }

        .error-description {
            font-size: 1rem;
            color: hsl(var(--muted-foreground));
            margin-bottom: 3rem;
            max-width: 500px;
            margin-left: auto;
            margin-right: auto;
            line-height: 1.6;
            animation: fadeInUp 0.8s ease-out 0.8s both;
        }

        .action-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
            animation: fadeInUp 0.8s ease-out 1s both;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 12px 24px;
            border-radius: var(--radius);
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 14px;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s ease;
            cursor: pointer;
            border: 1px solid transparent;
        }

        .btn-primary {
            background: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
            border-color: hsl(var(--primary));
        }

        .btn-primary:hover {
            background: hsl(var(--primary) / 0.9);
            transform: translateY(-1px);
        }

        .btn-secondary {
            background: hsl(var(--secondary));
            color: hsl(var(--secondary-foreground));
            border-color: hsl(var(--border));
        }

        .btn-secondary:hover {
            background: hsl(var(--muted));
            transform: translateY(-1px);
        }

        /* Decorative elements */
        .decoration {
            position: absolute;
            border: 1px solid hsl(var(--border));
            border-radius: 50%;
            opacity: 0.2;
            animation: float 6s ease-in-out infinite;
        }

        .decoration-1 {
            top: 10%;
            left: 10%;
            width: 160px;
            height: 160px;
            animation-delay: 0s;
        }

        .decoration-2 {
            bottom: 15%;
            right: 15%;
            width: 120px;
            height: 120px;
            animation-delay: 3s;
        }

        .decoration-3 {
            top: 20%;
            right: 20%;
            width: 80px;
            height: 80px;
            animation-delay: 1.5s;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px) rotate(0deg); }
            33% { transform: translateY(-10px) rotate(2deg); }
            66% { transform: translateY(5px) rotate(-1deg); }
        }

        /* Icons */
        .icon {
            display: inline-block;
            width: 16px;
            height: 16px;
            vertical-align: middle;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }

            .error-code {
                font-size: 2rem;
            }

            .error-message {
                font-size: 1.25rem;
            }

            .action-buttons {
                flex-direction: column;
                align-items: center;
            }

            .btn {
                width: 100%;
                max-width: 200px;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="grid-bg"></div>

    <div class="container">
        <div class="amadeus-wordmark">
            <img src="/static/wordmark-light.svg" alt="Amadeus" class="amadeus-logo">
        </div>

        <div class="error-code">404</div>

        <h2 class="error-message">Page not found</h2>

        <p class="error-description">
            The page you are looking for doesn't exist or has been moved.
            You can return to the dashboard or navigate back to the previous page.
        </p>

        <div class="action-buttons">
            <a href="javascript:history.back()" class="btn btn-secondary">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                </svg>
                Go back
            </a>
            <a href="/" class="btn btn-primary">
                <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
                </svg>
                Go home
            </a>
        </div>
    </div>

    <!-- Decorative elements -->
    <div class="decoration decoration-1"></div>
    <div class="decoration decoration-2"></div>
    <div class="decoration decoration-3"></div>
</body>
</html>
"#.to_string()
}
