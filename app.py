"""
Security Log Analyzer
Main Flask application.

Run with:
    python app.py
Then open http://127.0.0.1:5000 in your browser.

Supports THREE log types in a single uploaded file: Auth (login),
Application, and Network/Firewall logs. Each line is auto-detected
and routed to the matching parser/detector rules.
"""

import os
import sqlite3
import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, flash, jsonify, g
)
from werkzeug.utils import secure_filename

from analyzer.parser import parse_log_file
from analyzer.detector import run_detection
from analyzer.report import generate_pdf_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
CHARTS_DIR = os.path.join(BASE_DIR, "static", "charts")
DB_PATH = os.path.join(BASE_DIR, "database.db")
ALLOWED_EXTENSIONS = {"log", "txt", "csv"}

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            upload_date TEXT NOT NULL,
            analysis_time TEXT NOT NULL,
            total_logs INTEGER,
            auth_count INTEGER,
            application_count INTEGER,
            network_count INTEGER,
            success_count INTEGER,
            failed_count INTEGER,
            unique_users INTEGER,
            unique_ips INTEGER,
            error_count INTEGER,
            blocked_count INTEGER,
            suspicious_ip_count INTEGER,
            risk_score INTEGER
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            log_type TEXT,
            date TEXT, time TEXT,
            user TEXT, ip TEXT, status TEXT,
            level TEXT, message TEXT,
            src TEXT, dst TEXT, port TEXT, proto TEXT, action TEXT,
            FOREIGN KEY(analysis_id) REFERENCES analyses(id)
        );

        CREATE TABLE IF NOT EXISTS suspicious (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            log_type TEXT,
            ip TEXT, reason TEXT, risk TEXT,
            FOREIGN KEY(analysis_id) REFERENCES analyses(id)
        );
        """
    )
    conn.commit()
    conn.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------------------------------------------------------ charts
def build_dashboard_charts(analysis_id, stats, top_failed_ips, top_blocked_src, level_counts, records):
    auth_records = [r for r in records if r["log_type"] == "auth"]

    # Pie: log type breakdown
    type_path = os.path.join(CHARTS_DIR, f"{analysis_id}_types.png")
    plt.figure(figsize=(4, 4))
    counts = [stats["auth_count"], stats["application_count"], stats["network_count"]]
    labels = ["Auth", "Application", "Network"]
    nz_labels = [l for l, c in zip(labels, counts) if c > 0]
    nz_counts = [c for c in counts if c > 0]
    if nz_counts:
        plt.pie(nz_counts, labels=nz_labels, autopct="%1.1f%%",
                 colors=["#3498db", "#9b59b6", "#1abc9c"], startangle=90)
    plt.title("Log Type Breakdown")
    plt.tight_layout()
    plt.savefig(type_path, dpi=140)
    plt.close()

    # Pie: success vs failed (auth only)
    pie_path = os.path.join(CHARTS_DIR, f"{analysis_id}_pie.png")
    plt.figure(figsize=(4, 4))
    plt.pie(
        [stats["success_count"], stats["failed_count"]] or [1],
        labels=["Success", "Failed"],
        autopct="%1.1f%%",
        colors=["#2ecc71", "#e74c3c"],
        startangle=90,
    )
    plt.title("Auth: Success vs Failure")
    plt.tight_layout()
    plt.savefig(pie_path, dpi=140)
    plt.close()

    # Bar: top failed IPs (auth)
    bar_path = os.path.join(CHARTS_DIR, f"{analysis_id}_bar.png")
    plt.figure(figsize=(5, 3.2))
    if top_failed_ips:
        plt.bar([x[0] for x in top_failed_ips], [x[1] for x in top_failed_ips], color="#e67e22")
        plt.xticks(rotation=25, ha="right", fontsize=8)
    plt.title("Top Failed-Login IPs")
    plt.tight_layout()
    plt.savefig(bar_path, dpi=140)
    plt.close()

    # Bar: top active users (auth)
    from collections import Counter
    user_counts = Counter(r["user"] for r in auth_records)
    top_users = user_counts.most_common(5)
    users_path = os.path.join(CHARTS_DIR, f"{analysis_id}_users.png")
    plt.figure(figsize=(5, 3.2))
    if top_users:
        plt.bar([x[0] for x in top_users], [x[1] for x in top_users], color="#3498db")
        plt.xticks(rotation=25, ha="right", fontsize=8)
    plt.title("Top Active Users")
    plt.tight_layout()
    plt.savefig(users_path, dpi=140)
    plt.close()

    # Timeline: logins per hour (auth)
    hour_counts = Counter(int(r["time"].split(":")[0]) for r in auth_records)
    hours = list(range(24))
    counts_by_hour = [hour_counts.get(h, 0) for h in hours]
    timeline_path = os.path.join(CHARTS_DIR, f"{analysis_id}_timeline.png")
    plt.figure(figsize=(7, 3))
    plt.plot(hours, counts_by_hour, marker="o", color="#9b59b6")
    plt.xticks(hours)
    plt.title("Logins per Hour")
    plt.xlabel("Hour of day")
    plt.ylabel("Logins")
    plt.tight_layout()
    plt.savefig(timeline_path, dpi=140)
    plt.close()

    # Bar: application log levels
    levels_path = os.path.join(CHARTS_DIR, f"{analysis_id}_levels.png")
    plt.figure(figsize=(5, 3.2))
    order = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    lvl_vals = [level_counts.get(l, 0) for l in order]
    if any(lvl_vals):
        plt.bar(order, lvl_vals, color=["#95a5a6", "#3498db", "#f1c40f", "#e67e22", "#c0392b"])
    plt.title("Application Log Levels")
    plt.tight_layout()
    plt.savefig(levels_path, dpi=140)
    plt.close()

    # Bar: top blocked network sources
    blocked_path = os.path.join(CHARTS_DIR, f"{analysis_id}_blocked.png")
    plt.figure(figsize=(5, 3.2))
    if top_blocked_src:
        plt.bar([x[0] for x in top_blocked_src], [x[1] for x in top_blocked_src], color="#c0392b")
        plt.xticks(rotation=25, ha="right", fontsize=8)
    plt.title("Top Blocked Network Sources")
    plt.tight_layout()
    plt.savefig(blocked_path, dpi=140)
    plt.close()


# ------------------------------------------------------------------ routes
@app.route("/")
def index():
    db = get_db()
    history = db.execute(
        "SELECT * FROM analyses ORDER BY id DESC LIMIT 10"
    ).fetchall()
    return render_template("index.html", history=history)


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("logfile")
    if not file or file.filename == "":
        flash("Please choose a log file to upload.")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Only .log, .txt, or .csv files are allowed.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    saved_name = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    filepath = os.path.join(UPLOAD_DIR, saved_name)
    file.save(filepath)

    start = datetime.datetime.now()
    records, unparsed = parse_log_file(filepath)
    result = run_detection(records)
    stats = result["stats"]
    elapsed = (datetime.datetime.now() - start).total_seconds()

    db = get_db()
    cur = db.execute(
        """INSERT INTO analyses
           (filename, upload_date, analysis_time, total_logs, auth_count,
            application_count, network_count, success_count, failed_count,
            unique_users, unique_ips, error_count, blocked_count,
            suspicious_ip_count, risk_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            filename,
            start.strftime("%Y-%m-%d %H:%M:%S"),
            f"{elapsed:.2f}s",
            stats["total_logs"],
            stats["auth_count"],
            stats["application_count"],
            stats["network_count"],
            stats["success_count"],
            stats["failed_count"],
            stats["unique_users"],
            stats["unique_ips"],
            stats["error_count"],
            stats["blocked_count"],
            stats["suspicious_ip_count"],
            stats["risk_score"],
        ),
    )
    analysis_id = cur.lastrowid

    db.executemany(
        """INSERT INTO logs
           (analysis_id, log_type, date, time, user, ip, status, level,
            message, src, dst, port, proto, action)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                analysis_id, r["log_type"], r["date"], r["time"], r["user"], r["ip"],
                r["status"], r["level"], r["message"], r["src"], r["dst"], r["port"],
                r["proto"], r["action"],
            )
            for r in records
        ],
    )
    db.executemany(
        "INSERT INTO suspicious (analysis_id, log_type, ip, reason, risk) VALUES (?,?,?,?,?)",
        [(analysis_id, s["type"], s["ip"], s["reason"], s["risk"]) for s in result["suspicious_ips"]],
    )
    db.commit()

    build_dashboard_charts(
        analysis_id, stats, result["top_failed_ips"], result["top_blocked_src"],
        result["level_counts"], records,
    )

    if unparsed:
        flash(f"Note: {unparsed} line(s) did not match any known log format (Auth / Application / Network) and were skipped.")

    return redirect(url_for("dashboard", analysis_id=analysis_id))


@app.route("/dashboard/<int:analysis_id>")
def dashboard(analysis_id):
    db = get_db()
    analysis = db.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
    if not analysis:
        flash("Analysis not found.")
        return redirect(url_for("index"))

    suspicious = db.execute(
        "SELECT * FROM suspicious WHERE analysis_id=? ORDER BY CASE risk WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END",
        (analysis_id,),
    ).fetchall()

    return render_template(
        "dashboard.html",
        analysis=analysis,
        suspicious=suspicious,
    )


@app.route("/api/logs/<int:analysis_id>")
def api_logs(analysis_id):
    """JSON endpoint used by the dashboard's search & filter controls."""
    db = get_db()
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "all")
    type_filter = request.args.get("type", "all")
    only_suspicious = request.args.get("suspicious", "") == "1"

    query = "SELECT * FROM logs WHERE analysis_id=?"
    params = [analysis_id]

    if type_filter in ("auth", "application", "network"):
        query += " AND log_type=?"
        params.append(type_filter)

    if status_filter in ("SUCCESS", "FAILED"):
        query += " AND status=?"
        params.append(status_filter)

    if q:
        like = f"%{q}%"
        query += " AND (user LIKE ? OR ip LIKE ? OR date LIKE ? OR src LIKE ? OR dst LIKE ? OR message LIKE ?)"
        params.extend([like, like, like, like, like, like])

    if only_suspicious:
        sus_ids = [
            r["ip"] for r in db.execute(
                "SELECT DISTINCT ip FROM suspicious WHERE analysis_id=?", (analysis_id,)
            ).fetchall()
        ]
        if sus_ids:
            placeholders = ",".join("?" * len(sus_ids))
            query += f" AND (ip IN ({placeholders}) OR src IN ({placeholders}))"
            params.extend(sus_ids)
            params.extend(sus_ids)
        else:
            query += " AND 1=0"

    query += " ORDER BY date, time LIMIT 500"
    rows = db.execute(query, params).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route("/download_report/<int:analysis_id>")
def download_report(analysis_id):
    db = get_db()
    analysis = db.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
    if not analysis:
        flash("Analysis not found.")
        return redirect(url_for("index"))

    suspicious = db.execute(
        "SELECT * FROM suspicious WHERE analysis_id=?", (analysis_id,)
    ).fetchall()
    suspicious_list = [dict(r) for r in suspicious]

    top_failed = db.execute(
        """SELECT ip, COUNT(*) as c FROM logs
           WHERE analysis_id=? AND log_type='auth' AND status='FAILED'
           GROUP BY ip ORDER BY c DESC LIMIT 5""",
        (analysis_id,),
    ).fetchall()
    top_failed_ips = [(r["ip"], r["c"]) for r in top_failed]

    stats = {
        "total_logs": analysis["total_logs"],
        "auth_count": analysis["auth_count"],
        "application_count": analysis["application_count"],
        "network_count": analysis["network_count"],
        "success_count": analysis["success_count"],
        "failed_count": analysis["failed_count"],
        "unique_users": analysis["unique_users"],
        "unique_ips": analysis["unique_ips"],
        "error_count": analysis["error_count"],
        "blocked_count": analysis["blocked_count"],
        "suspicious_ip_count": analysis["suspicious_ip_count"],
        "risk_score": analysis["risk_score"],
    }

    pdf_path = generate_pdf_report(
        analysis_id, analysis["filename"], stats, suspicious_list,
        top_failed_ips, CHARTS_DIR, REPORTS_DIR,
    )
    return send_file(pdf_path, as_attachment=True, download_name=f"security_report_{analysis_id}.pdf")


@app.route("/history")
def history():
    db = get_db()
    rows = db.execute("SELECT * FROM analyses ORDER BY id DESC").fetchall()
    return render_template("index.html", history=rows)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
