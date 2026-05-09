from scapy.all import sniff, IP, TCP, UDP
import threading
from datetime import datetime

# Global list to store captured logs
captured_packets = []

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        
        log_entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": ip_src,
            "dst": ip_dst,
            "proto": proto,
            "len": len(packet),
            "summary": packet.summary()[:50]
        }
        
        captured_packets.append(log_entry)
        if len(captured_packets) > 20:
            captured_packets.pop(0)

def start_sniffing(interface=None):
    """
    Starts the Scapy sniffer in a background thread with fallback.
    """
    try:
        print(f"[*] Attempting Scapy Packet Sniffer on {interface if interface else 'default interface'}...")
        sniff(prn=process_packet, store=False, filter="ip")
    except Exception as e:
        print(f"[!] Scapy failed: {e}. Falling back to Connection Monitoring.")
        import psutil
        import time
        while True:
            try:
                connections = psutil.net_connections()
                for conn in connections[:5]:
                    log_entry = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "src": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "localhost",
                        "dst": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "LISTEN",
                        "proto": "TCP" if conn.type == 1 else "UDP",
                        "len": 0,
                        "summary": f"Connection Status: {conn.status}"
                    }
                    captured_packets.append(log_entry)
                    if len(captured_packets) > 20: captured_packets.pop(0)
                time.sleep(2)
            except:
                time.sleep(5)

def get_live_packets():
    return captured_packets
