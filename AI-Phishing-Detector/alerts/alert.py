import smtplib
from datetime import datetime

def trigger_alert(threat_type, source_ip):
    """
    Simulates a security alert being triggered.
    In a real industry system, this would send an Email, SMS, or Telegram msg.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[CRITICAL ALERT] {timestamp} - {threat_type} detected from {source_ip}"
    
    print(alert_msg)
    
    # Save to alert logs
    with open("alerts/security_alerts.log", "a") as f:
        f.write(alert_msg + "\n")
    
    return alert_msg

def send_email_alert(subject, message):
    # Placeholder for actual SMTP logic
    # server = smtplib.SMTP('smtp.gmail.com', 587)
    # ...
    print(f"Email Alert Sent: {subject}")
