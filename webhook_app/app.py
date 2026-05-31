from flask import Flask, request, abort
from prometheus_client import Counter, Histogram, generate_latest
import hmac, hashlib
from dateutil.parser import isoparse

app = Flask(__name__)

# Prometheus metrics
workflow_runs_total = Counter(
    'github_workflow_runs_total',
    'Total number of GitHub workflow runs',
    ['status']
)

workflow_duration_seconds = Histogram(
    'github_workflow_duration_seconds',
    'Duration of GitHub workflow runs in seconds'
)

# Secret for verifying GitHub webhook signatures
GITHUB_SECRET = b"your-secret-here"  # replace with the same secret you set in GitHub

def verify_signature(payload, signature):
    mac = hmac.new(GITHUB_SECRET, msg=payload, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route("/github-webhook", methods=["POST"])
def github_webhook():
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(request.data, signature):
        abort(403)

    data = request.json
    if "workflow_run" in data:
        run = data["workflow_run"]
        status = run.get("conclusion", "unknown")
        workflow_runs_total.labels(status=status).inc()

        if run.get("run_started_at") and run.get("updated_at"):
            start = isoparse(run["run_started_at"])
            end = isoparse(run["updated_at"])
            workflow_duration_seconds.observe((end - start).total_seconds())
    return "ok"

@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
