import os
import time
import csv
import threading
import requests
from datetime import datetime
from scapy.all import sniff, wrpcap
from cicflowmeter.flow_session import FlowSession

pcap_path = "/cowrie/logs/pcap/cowrie.pcap"
os.makedirs(os.path.dirname(pcap_path), exist_ok=True)

packet_buffer = []
buffer_lock = threading.Lock()

def flush_packets():
    global packet_buffer
    while True:
        time.sleep(5)
        with buffer_lock:
            if packet_buffer:
                print(f"Time-based flush: writing {len(packet_buffer)} packets to {pcap_path}...")
                try:
                    wrpcap(pcap_path, packet_buffer, append=True)
                except Exception as e:
                    print(f"Error writing PCAP: {e}")
                packet_buffer.clear()

# Start background flush thread
flush_thread = threading.Thread(target=flush_packets, daemon=True)
flush_thread.start()

def packet_callback(pkt):
    global packet_buffer
    with buffer_lock:
        packet_buffer.append(pkt)
        if len(packet_buffer) >= 100:
            print(f"Buffer limit reached: flushing {len(packet_buffer)} packets...")
            try:
                wrpcap(pcap_path, packet_buffer, append=True)
            except Exception as e:
                print(f"Error writing PCAP: {e}")
            packet_buffer.clear()

def rotate_csv_file(target_csv, max_size_mb=100):
    if not os.path.exists(target_csv):
        return
    size_mb = os.path.getsize(target_csv) / (1024 * 1024)
    if size_mb <= max_size_mb:
        return
        
    print(f"[Rotation] {target_csv} size ({size_mb:.2f}MB) exceeds limit ({max_size_mb}MB). Truncating...")
    try:
        with open(target_csv, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = list(reader)
            
        # Keep last 50% of rows to keep the log size down
        keep_count = len(rows) // 2
        rows_to_keep = rows[-keep_count:]
        
        with open(target_csv, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows_to_keep)
        print(f"[Rotation] Successfully rotated CSV, kept last {keep_count} rows.")
    except Exception as e:
        print(f"[Rotation] Error rotating CSV: {e}")

def process_pcap(pcap_in, csv_out_dir):
    temp_csv = "/cowrie/logs/pcap/temp_flows.csv"
    if os.path.exists(temp_csv):
        try:
            os.remove(temp_csv)
        except Exception:
            pass
            
    # Subclass FlowSession to fix Scapy 2.7+ compatibility
    class MyFlowSession(FlowSession):
        output_mode = "csv"
        output = temp_csv

        def process(self, pkt):
            self.on_packet_received(pkt)
            return super().process(pkt)
            
    session = MyFlowSession()
    print(f"Running flow extraction on {pcap_in}...")
    try:
        sniff(offline=pcap_in, session=session, store=False)
        session.garbage_collect(None)
        if hasattr(session, 'output_writer'):
            del session.output_writer
    except Exception as e:
        print(f"Error during flow extraction: {e}")
        return
        
    if not os.path.exists(temp_csv) or os.path.getsize(temp_csv) == 0:
        print("No flows extracted.")
        return
        
    sentinel_api = os.environ.get("SENTINEL_API", "http://backend:5000/api")
    sentinel_key = os.environ.get("SENTINEL_KEY")
    if not sentinel_key:
        sys.exit("Error: SENTINEL_KEY environment variable not set")
    match_url = f"{sentinel_api}/honeypot/ingest/match-session"
    
    labeled_rows = []
    headers = []
    
    try:
        with open(temp_csv, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            for row in reader:
                src_ip = row.get("src_ip")
                src_port = row.get("src_port")
                timestamp_str = row.get("timestamp")
                
                label = "Unknown"
                label_source = "unmatched_fallback"
                
                if src_ip and src_port and timestamp_str:
                    try:
                        # Convert YYYY-MM-DD HH:MM:SS format to ISO string (UTC)
                        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        iso_time = dt.isoformat() + "Z"
                        
                        resp = requests.post(
                            match_url,
                            headers={"x-api-key": sentinel_key},
                            json={
                                "sourceIP": src_ip,
                                "sourcePort": int(src_port),
                                "startTime": iso_time
                            },
                            timeout=5
                        )
                        if resp.status_code == 200:
                            res_json = resp.json()
                            if res_json.get("success") and res_json.get("data", {}).get("matched"):
                                session_data = res_json["data"]
                                if session_data.get("aiClassification"):
                                    label = session_data["aiClassification"]
                                    label_source = "session_matched"
                                    print(f"Matched flow {src_ip}:{src_port} -> session classification: '{label}'")
                    except Exception as ex:
                        print(f"Error matching flow: {ex}")
                        
                row["label"] = label
                row["label_source"] = label_source
                labeled_rows.append(row)
    except Exception as e:
        print(f"Error processing temp CSV: {e}")
        return
        
    if not labeled_rows:
        return
        
    os.makedirs(csv_out_dir, exist_ok=True)
    target_csv = os.path.join(csv_out_dir, "flows.csv")
    file_exists = os.path.exists(target_csv)
    out_headers = list(headers) + ["label", "label_source"]
    
    try:
        with open(target_csv, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=out_headers)
            if not file_exists:
                writer.writeheader()
            for r in labeled_rows:
                filtered_row = {k: r.get(k, "") for k in out_headers}
                writer.writerow(filtered_row)
        print(f"Successfully appended {len(labeled_rows)} flows to {target_csv}")
    except Exception as e:
        print(f"Error writing to target CSV: {e}")
        
    try:
        rotate_csv_file(target_csv)
    except Exception as e:
        print(f"Error during CSV rotation: {e}")
        
    try:
        os.remove(temp_csv)
    except Exception:
        pass

def process_loop():
    pcap_dir = os.path.dirname(pcap_path)
    processing_pcap = os.path.join(pcap_dir, "processing.pcap")
    csv_out_dir = "/app/datasets/honeypot_derived"
    
    # Wait 30 seconds initially on startup to let system stabilize
    time.sleep(30)
    
    while True:
        time.sleep(120)
        if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
            continue
            
        print("Flow extraction thread: Raw packets detected. Running batch processing...")
        with buffer_lock:
            try:
                if os.path.exists(processing_pcap):
                    os.remove(processing_pcap)
                os.rename(pcap_path, processing_pcap)
            except Exception as e:
                print(f"Error renaming PCAP: {e}")
                continue
                
        try:
            process_pcap(processing_pcap, csv_out_dir)
        except Exception as e:
            print(f"Error during batch processing: {e}")
        finally:
            try:
                if os.path.exists(processing_pcap):
                    os.remove(processing_pcap)
            except Exception:
                pass

# Start background periodic processing thread
process_thread = threading.Thread(target=process_loop, daemon=True)
process_thread.start()

print("Starting honeypot traffic sniffer on port 2222...")
sniff(filter="tcp port 2222", prn=packet_callback, store=False)
