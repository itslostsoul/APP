"""AMAS dashboard: a small local web app that reads the JSON reports written by the
Java analyzer and serves them to the browser. Everything is same-origin, so no CORS."""
import json
import os
import re
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

HERE = Path(__file__).resolve().parent
REPORTS = Path(os.environ.get("AMAS_REPORTS", HERE.parent / "reports")).resolve()
STATIC = HERE / "static"
ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$")
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}

app = Flask(__name__, static_folder=None)


@app.before_request
def guard():
    # Blocks DNS-rebinding: only answer requests addressed to a loopback name.
    host = request.host.rsplit(":", 1)[0] if not request.host.startswith("[") else request.host.split("]")[0] + "]"
    if host not in ALLOWED_HOSTS:
        abort(403)
    if request.method in ("POST", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != request.host:
            abort(403)


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def load(rid):
    if not ID_RE.match(rid):
        abort(404)
    path = REPORTS / f"report-{rid}.json"
    if not path.is_file():
        abort(404)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        abort(500)


def summary(d):
    return {
        "id": d.get("id"),
        "created_at": d.get("created_at"),
        "status": d.get("status", "completed"),
        "sample": d.get("sample", {}),
        "verdict": d.get("verdict", {}),
        "error": d.get("error"),
    }


@app.get("/api/reports")
def list_reports():
    items = []
    for p in sorted(REPORTS.glob("report-*.json"), reverse=True):
        try:
            items.append(summary(json.loads(p.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            continue
    items.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return jsonify(items)


@app.get("/api/report/<rid>")
def get_report(rid):
    return jsonify(load(rid))


@app.delete("/api/reports")
def clear_reports():
    n = 0
    for p in REPORTS.glob("report-*.*"):
        if p.suffix in (".json", ".txt"):
            p.unlink(missing_ok=True)
            n += 1
    return jsonify({"deleted": n})


@app.delete("/api/report/<rid>")
def delete_report(rid):
    load(rid)
    for ext in ("json", "txt"):
        (REPORTS / f"report-{rid}.{ext}").unlink(missing_ok=True)
    return jsonify({"deleted": rid})


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/<path:name>")
def assets(name):
    return send_from_directory(STATIC, name)


if __name__ == "__main__":
    REPORTS.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("AMAS_PORT", "5000"))
    print(f"AMAS dashboard: http://localhost:{port}  (reports: {REPORTS})")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
