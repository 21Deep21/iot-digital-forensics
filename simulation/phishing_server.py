
from flask import Flask, render_template_string, request
from datetime import datetime, timezone

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Awareness Simulation</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f4f8;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .card {
            background: white;
            padding: 35px;
            border-radius: 10px;
            text-align: center;
            max-width: 420px;
        }
        a {
            display: inline-block;
            background: #2563eb;
            color: white;
            padding: 12px 22px;
            border-radius: 6px;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="card">
        <h2>Account Security Notification</h2>
        <p>This is a controlled phishing awareness simulation.</p>
        <p>Click below to simulate following a suspicious link.</p>
        <a href="/verify">Verify Account</a>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/verify")
def verify():
    timestamp = datetime.now(timezone.utc).isoformat()

    print(
        f"[SIMULATED PHISHING CLICK] "
        f"Time={timestamp} "
        f"Source={request.remote_addr} "
        f"Path={request.path}",
        flush=True
    )

    return """
    <h2>Phishing Simulation Completed</h2>
    <p>Your click generated an HTTP request.</p>
    <p>No credentials or personal data were collected.</p>
    <p>This traffic can now be examined using Wireshark.</p>
    """


from flask import Response

@app.route("/payload")
def payload():
    print("[SIMULATED PAYLOAD DOWNLOAD]", flush=True)

    return Response(
        "ADF LAB - harmless simulated payload\n",
        mimetype="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=demo_payload.txt"
        }
    )


@app.route("/c2/checkin")
def c2_checkin():
    timestamp = datetime.now(timezone.utc).isoformat()

    print(
        f"[SIMULATED C2 BEACON] "
        f"Time={timestamp} "
        f"Source={request.remote_addr}",
        flush=True
    )

    return {"status": "received", "simulation": True}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
