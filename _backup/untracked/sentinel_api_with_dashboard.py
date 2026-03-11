from sentinel_api import app
from dashboard_patch import mount_dashboard
from sentinel_api import app
from dashboard_patch import mount_dashboard
from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def homepage():
    return """
    <html>
      <head>
        <title>Sentinel SCA – Autonomous Revenue Protection</title>
      </head>
      <body style="background:black;color:white;text-align:center;padding-top:80px;font-family:Arial;">
        <h1>Sentinel SCA</h1>
        <h2>Autonomous Protection for Revenue-Generating Bots & Validators</h2>
        <p>If your bot stops, you lose money.</p>
        <p><strong>Sentinel detects. Approves. Executes. Recovers.</strong></p>
        <br>
        <p>✔ 24/7 Monitoring</p>
        <p>✔ Self-Healing Automation</p>
        <p>✔ Policy-Gated Execution</p>
        <p>✔ Uptime Protection</p>
        <br>
        <a href="/dashboard" style="color:#00ffcc;font-size:18px;">Enter Dashboard</a>
      </body>
    </html>
    """

mount_dashboard(app)
