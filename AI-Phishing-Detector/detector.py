import joblib
import numpy as np
import os

# Load the trained model
MODEL_PATH = "saved_model/model.pkl"

def get_detector_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return None

def detect_threat(features):
    model = get_detector_model()
    if not model:
        return "Model not trained"
    
    data = np.array([features])
    prediction = model.predict(data)[0]
    
    if prediction == 1:
        return "Malicious"
    else:
        return "Normal"

def analyze_packet(packet_data):
    """
    Analyzes packet features and returns a threat classification.
    Features: [length, protocol_id, ttl, is_suspicious_port]
    """
    model = get_detector_model()
    if not model:
        return "Safe"

    # Simulated feature extraction for the packet
    # In a real industry IDS, you would extract 70+ features here
    packet_features = np.array([packet_data])
    
    try:
        prediction = model.predict(packet_features)[0]
        return "Threat Detected" if prediction == 1 else "Safe"
    except:
        return "Analysis Failed"
