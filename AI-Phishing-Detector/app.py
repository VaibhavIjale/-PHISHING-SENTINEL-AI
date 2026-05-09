from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import os
import socket
import ssl
from datetime import datetime
import whois
from features import extract_features, get_feature_names
from database import db, ScanHistory, init_db
import plotly.graph_objects as go
import plotly.io as pio
import json

app = Flask(__name__)

# Database Initialization
init_db(app)

# Paths
MODEL_PATH = "saved_model/model.pkl"

# Load model
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None

def get_ssl_details(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert['issuer'])['commonName'],
                    "expiry": cert['notAfter'],
                    "status": "Valid SSL"
                }
    except Exception as e:
        return {"status": "No SSL / Invalid SSL", "error": str(e)}

def get_whois_details(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "country": w.country
        }
    except Exception:
        return {"error": "WHOIS Lookup Failed"}

def get_vt_analysis(url):
    """
    Placeholder for VirusTotal API Integration.
    To enable, get an API key from virustotal.com and implement the request.
    """
    return {"status": "Integration Ready", "positives": 0, "total": 0}

@app.route("/")
def home():
    # Get recent history
    history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()
    return render_template("index.html", history=history)

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url")
    if not url:
        return render_template("index.html", error="Please enter a URL")

    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    # Extract domain
    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    # Feature Extraction
    features = extract_features(url)
    features_array = np.array([features])

    # Prediction
    if model:
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0]
        confidence = round(max(probability) * 100, 2)
        
        if prediction == 1:
            result = "Phishing/Malicious"
            status_class = "danger"
        else:
            result = "Safe/Legitimate"
            status_class = "success"
    else:
        result = "Model not trained"
        confidence = 0
        status_class = "warning"

    # Create Threat Gauge Chart
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = confidence if prediction == 1 else (100 - confidence),
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Threat Probability (%)", 'font': {'color': "white"}},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
            'bar': {'color': "red" if prediction == 1 else "green"},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(34, 197, 94, 0.3)'},
                {'range': [50, 80], 'color': 'rgba(245, 158, 11, 0.3)'},
                {'range': [80, 100], 'color': 'rgba(239, 68, 68, 0.3)'}],
        }
    ))
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white", 'family': "Arial"}, height=300)
    graph_json = pio.to_json(fig)

    # Save to Database
    try:
        new_scan = ScanHistory(
            url=url, 
            result=result, 
            confidence=confidence, 
            status_class=status_class
        )
        db.session.add(new_scan)
        db.session.commit()
    except Exception as e:
        print(f"Database Error: {e}")

    # Advanced Analysis
    ssl_info = get_ssl_details(domain) if domain else {}
    whois_info = get_whois_details(domain) if domain else {}
    vt_info = get_vt_analysis(url)

    # Get recent history
    history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()

    return render_template(
        "index.html", 
        url=url,
        result=result, 
        confidence=confidence,
        status_class=status_class,
        ssl_info=ssl_info,
        whois_info=whois_info,
        vt_info=vt_info,
        graph_json=graph_json,
        history=history,
        features=dict(zip(get_feature_names(), features))
    )

@app.route("/history")
def view_history():
    all_history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
    return render_template("history.html", history=all_history)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
