import os, json
from fastapi.responses import HTMLResponse

def mount_dashboard(app):
    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard():
        html = []
        html.append("<!doctype html><html><head><meta charset='utf-8'>")
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
        html.append("<title>Sentinel Dashboard</title></head>")
        html.append("<body style='font-family:system-ui;padding:18px'>")
        html.append("<h2>Sentinel Dashboard</h2>")
        html.append("<p><a href='/health'>/health</a> | <a href='/openapi.json'>/openapi.json</a></p>")

        queues = [
            ("ops:incidents", "Incidents"),
            ("ops:incidents:triaged", "Triaged"),
            ("ops:actions:proposed", "Proposed"),
            ("ops:actions:approved", "Approved"),
            ("ops:actions:executed", "Executed"),
            ("ops:actions:rejected", "Rejected"),
        ]

        html.append("<h3>Queues</h3><ul>")
        try:
            import redis
            r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
            for k, label in queues:
                html.append(f"<li><b>{label}</b> ({k}): {r.llen(k)}</li>")

            last = r.lrange("ops:actions:executed", 0, 0)
            if last:
                html.append("</ul><h3>Last executed</h3><pre style='white-space:pre-wrap'>")
                html.append(json.dumps(json.loads(last[0]), indent=2)[:4000])
                html.append("</pre>")
            else:
                html.append("</ul><p><i>No executed actions yet.</i></p>")
        except Exception as e:
            html.append("</ul><p><i>Redis not reachable from API container.</i></p>")

        html.append("</body></html>")
        return HTMLResponse("".join(html))
