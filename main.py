# Suricata Alert Parser, Visualizer, and Simple Response
import json
import os
import time
import pandas as pd
import matplotlib.pyplot as plt

# Path to Suricata eve.json log file (update if needed)
EVE_JSON_PATH = r'C:\Program Files\Suricata\log\eve.json'

def parse_alerts(eve_json_path):
  alerts = []
  if not os.path.exists(eve_json_path):
    print(f"Log file not found: {eve_json_path}")
    return alerts
  with open(eve_json_path, 'r', encoding='utf-8') as f:
    for line in f:
      try:
        event = json.loads(line)
        if event.get('event_type') == 'alert':
          alerts.append(event)
      except Exception:
        continue
  return alerts

def visualize_alerts(alerts):
  if not alerts:
    print("No alerts to visualize.")
    return
  df = pd.DataFrame([
    {
      'timestamp': a['timestamp'],
      'src_ip': a['src_ip'],
      'dest_ip': a['dest_ip'],
      'signature': a['alert']['signature']
    }
    for a in alerts
  ])
  # Count alerts by signature
  sig_counts = df['signature'].value_counts()
  sig_counts.plot(kind='bar', title='Alert Signature Counts')
  plt.xlabel('Signature')
  plt.ylabel('Count')
  plt.tight_layout()
  plt.show()

def respond_to_alerts(alerts):
  for alert in alerts:
    sig = alert['alert']['signature']
    src = alert['src_ip']
    dest = alert['dest_ip']
    print(f"[ALERT] {sig} from {src} to {dest}")
    # Example: Add custom response logic here (e.g., send email, block IP, etc.)

def main():
  print("Parsing Suricata alerts...")
  alerts = parse_alerts(EVE_JSON_PATH)
  print(f"Total alerts found: {len(alerts)}")
  respond_to_alerts(alerts)
  visualize_alerts(alerts)

if __name__ == "__main__":
  main()
