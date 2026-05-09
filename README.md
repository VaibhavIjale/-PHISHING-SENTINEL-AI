# AI-Based Intrusion Detection & Threat Monitoring System

An industry-level cybersecurity suite integrated with Artificial Intelligence for real-time network traffic analysis, phishing detection, and system health monitoring.

---

### 🚀 Quick Access (Local Deployment)
*   **Dashboard URL**: [http://127.0.0.1:5000](http://127.0.0.1:5000)
*   **Authorized Secret ID**: `378139`

---

## 🚀 Key Features

*   **AI Phishing Detector**: Real-time URL analysis using Machine Learning (Random Forest) with feature extraction.
*   **Real-Time Packet Sniffer**: Live network traffic monitoring using Scapy with protocol analysis.
*   **Vulnerability Scanner**: Port scanning and service detection for system hardening.
*   **SIEM Dashboard**: Live system performance monitoring (CPU, RAM, Processes) with dynamic visualization.
*   **Ransomware Shield**: Heuristic filesystem monitoring using Watchdog to detect suspicious file activities.
*   **Automated Alerts**: Logging and notification system for critical security threats.

## 🛠️ Technology Stack

*   **Backend**: Python, Flask
*   **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
*   **Network Security**: Scapy, Socket Programming
*   **System Monitoring**: Psutil, Watchdog
*   **Database**: SQLite (SQLAlchemy)
*   **Visualization**: Plotly.js

## 📦 Installation & Setup

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/VaibhavIjale/-PHISHING-SENTINEL-AI.git
    cd -PHISHING-SENTINEL-AI
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Train the AI Model**:
    ```bash
    python generate_data.py
    python model.py
    ```

4.  **Launch the Application**:
    ```bash
    python app.py
    ```

## 🔒 Authorized Access

The system is protected by a Secret ID authentication layer.
*   **Default Secret ID**: `378139`

## 📖 Learning Resources

The project includes a dedicated **Learning Center** featuring essential tools for cybersecurity research:
*   Kali Linux
*   Wireshark
*   Aircrack-ng
*   Scapy

## 🛡️ Disclaimer

This project is intended for **educational and defensive purposes only**. Unauthorized access to networks or systems is illegal and unethical.

---
Built with ❤️ for Cybersecurity Research.
