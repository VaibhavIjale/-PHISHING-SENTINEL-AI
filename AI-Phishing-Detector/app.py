from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import joblib
import numpy as np
import os
import socket
import ssl
from datetime import datetime
import whois
import psutil
from urllib.parse import urlparse
import threading

# Import Industry Modules
from sniffer import start_sniffing, get_live_packets
from detector import detect_threat, analyze_packet
from alerts.alert import trigger_alert
from features import extract_features, get_feature_names
from database import db, ScanHistory, init_db
import plotly.graph_objects as go
import plotly.io as pio
import json

app = Flask(__name__)
app.secret_key = "cyber-sentinel-ultra-secret-key-999"

# --- AUTHENTICATION ---
SECRET_ID = "378139"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- BACKGROUND SERVICES ---
# Start Packet Sniffer in Background
threading.Thread(target=start_sniffing, daemon=True).start()

# Start File Monitor in Background
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

file_events = []
class MonitorHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if not event.is_directory:
            event_type = event.event_type.upper()
            file_name = os.path.basename(event.src_path)
            file_events.append({"type": event_type, "file": file_name, "time": datetime.now().strftime("%H:%M:%S")})
            if len(file_events) > 10: file_events.pop(0)

def start_file_monitor():
    path = "."
    observer = Observer()
    observer.schedule(MonitorHandler(), path, recursive=False)
    observer.start()
    while True:
        import time
        time.sleep(1)

threading.Thread(target=start_file_monitor, daemon=True).start()

# Database Initialization
init_db(app)

# Load AI Model
MODEL_PATH = "saved_model/model.pkl"
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None

# --- ROUTES ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_id = request.form.get("secret_id")
        if user_id == SECRET_ID:
            session["user_id"] = user_id
            return redirect(url_for("home"))
        return render_template("login.html", error="ACCESS DENIED: INVALID SECRET ID")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return render_template("index.html")

# --- AI Intrusion Detection (Industry Module) ---
@app.route("/threats")
@login_required
def threats_home():
    packets = get_live_packets()
    return render_template("threats.html", packets=packets)

@app.route("/threats/data")
@login_required
def threats_data():
    packets = get_live_packets()
    # Simulate a threat detection if a packet is large
    for p in packets:
        if p['len'] > 1000: # Simulated threshold
            trigger_alert("Large Packet Anomaly", p['src'])
            
    return jsonify({
        "packets": packets,
        "net_io": psutil.net_io_counters()._asdict(),
        "threat_status": "Active Monitoring"
    })

# --- Phishing Detector ---
@app.route("/phishing")
@login_required
def phishing_home():
    history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()
    return render_template("phishing.html", history=history)

@app.route("/phishing/predict", methods=["POST"])
@login_required
def phishing_predict():
    url = request.form.get("url")
    if not url: return render_template("phishing.html", error="URL required")
    
    if not (url.startswith("http://") or url.startswith("https://")): url = "http://" + url
    domain = urlparse(url).netloc
    
    resolved_ip = None
    try: resolved_ip = socket.gethostbyname(domain)
    except: pass

    features = extract_features(url)
    features_array = np.array([features])

    if model:
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0]
        confidence = round(max(probability) * 100, 2)
        result = "Phishing/Malicious" if prediction == 1 else "Safe/Legitimate"
        status_class = "danger" if prediction == 1 else "success"
    else:
        result, confidence, status_class = "Model not trained", 0, "warning"

    # Gauge Chart
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = confidence if (model and prediction == 1) else (100 - confidence),
        title = {'text': "Threat Probability (%)", 'font': {'color': "white"}},
        gauge = {'bar': {'color': "red" if (model and prediction == 1) else "green"}}
    ))
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"}, height=300)
    graph_json = pio.to_json(fig)

    try:
        new_scan = ScanHistory(url=url, result=result, confidence=confidence, status_class=status_class)
        db.session.add(new_scan)
        db.session.commit()
    except: pass

    return render_template("phishing.html", url=url, result=result, confidence=confidence, status_class=status_class, graph_json=graph_json, resolved_ip=resolved_ip, features=dict(zip(get_feature_names(), features)))

# --- Other Modules ---
@app.route("/vulnerability")
@login_required
def vulnerability_home(): return render_template("vulnerability.html")

@app.route("/vulnerability/scan", methods=["POST"])
@login_required
def vulnerability_scan():
    target = request.form.get("target")
    results = {}
    try:
        ip = socket.gethostbyname(target)
        for port in [21, 22, 80, 443, 3306]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0: results[port] = "Open"
            s.close()
    except: return render_template("vulnerability.html", error="Scan failed")
    return render_template("vulnerability.html", target=target, results=results, resolved_ip=ip)

@app.route("/siem")
@login_required
def siem_home():
    stats = {"cpu": psutil.cpu_percent(), "memory": psutil.virtual_memory().percent, "processes": len(psutil.pids())}
    return render_template("siem.html", stats=stats)

@app.route("/siem/stats")
@login_required
def siem_stats():
    return jsonify({"cpu": psutil.cpu_percent(), "memory": psutil.virtual_memory().percent, "processes": len(psutil.pids())})

@app.route("/ransomware")
@login_required
def ransomware_home(): return render_template("ransomware.html", events=file_events)

@app.route("/ransomware/events")
@login_required
def ransomware_events(): return jsonify(file_events)

@app.route("/resources")
@login_required
def cyber_resources(): return render_template("resources.html")

@app.route("/future")
@login_required
def cyber_future(): return render_template("future.html")

@app.route("/alerts/recent")
@login_required
def get_recent_alerts():
    try:
        if os.path.exists("alerts/security_alerts.log"):
            with open("alerts/security_alerts.log", "r") as f:
                lines = f.readlines()
                return jsonify([line.strip() for line in lines[-5:]])
        return jsonify(["System Monitoring Active: No Critical Threats"])
    except:
        return jsonify(["Monitoring Status: Operational"])

@app.route("/siem/events")
@login_required
def get_siem_events():
    events = []
    try:
        # Get actual recent processes
        for proc in psutil.process_iter(['name']):
            events.append(f"Process Active: {proc.info['name']}")
            if len(events) >= 5: break
    except:
        events = ["Failed to fetch process logs"]
    return jsonify(events)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
