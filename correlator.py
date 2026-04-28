import urllib.request
import json
from datetime import datetime, timedelta
from database import get_connection

def load_rules():
    with open('rules.json', 'r') as f:
        data = json.load(f)
    return [r for r in data['rules'] if r.get('enabled', True)]

def send_slack_alert(rule_name, severity, source_ip, description):
    slack_webhook = None
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            slack_webhook = config.get('slack_webhook_url')
    except:
        return

    if not slack_webhook:
        return

    severity_emoji = {
        'critical': ':red_circle:',
        'high': ':orange_circle:',
        'medium': ':yellow_circle:',
        'low': ':white_circle:'
    }

    payload = {
        "text": f"{severity_emoji.get(severity, ':white_circle:')} *SIEM Alert: {rule_name}*",
        "attachments": [
            {
                "color": "#f85149" if severity == "critical" else "#d29922",
                "fields": [
                    {"title": "Rule", "value": rule_name, "short": True},
                    {"title": "Severity", "value": severity.upper(), "short": True},
                    {"title": "Source IP", "value": source_ip, "short": True},
                    {"title": "Time", "value": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "short": True},
                    {"title": "Description", "value": description, "short": False}
                ]
            }
        ]
    }

    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            slack_webhook,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"Slack alert sent for {rule_name}")
    except Exception as e:
        print(f"Slack alert failed: {e}")

def insert_alert(rule_name, severity, source_ip, description, event_ids):
    conn = get_connection()
    conn.execute('''
        INSERT INTO alerts (timestamp, rule_name, severity, source_ip, description, event_ids)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), rule_name, severity, source_ip, description, json.dumps(event_ids)))
    conn.commit()
    conn.close()
    if severity in ['critical', 'high']:
        send_slack_alert(rule_name, severity, source_ip, description)

def run_threshold_rule(rule):
    conn = get_connection()
    window = (datetime.now() - timedelta(minutes=rule['window_minutes'])).isoformat()
    rows = conn.execute(f'''
        SELECT source_ip, COUNT(*) as cnt, GROUP_CONCAT(id) as ids
        FROM events
        WHERE event_type = ?
        AND timestamp >= ?
        GROUP BY source_ip
        HAVING cnt >= ?
    ''', (rule['event_type'], window, rule['threshold'])).fetchall()
    conn.close()
    triggered = 0
    for row in rows:
        insert_alert(
            rule_name=rule['name'],
            severity=rule['severity'],
            source_ip=row['source_ip'],
            description=f"{rule['description']} ({row['cnt']} events from {row['source_ip']})",
            event_ids=row['ids'].split(',') if row['ids'] else []
        )
        triggered += 1
    print(f"{rule['name']}: {triggered} alerts triggered")

def run_followup_rule(rule):
    conn = get_connection()
    window = (datetime.now() - timedelta(minutes=rule['window_minutes'])).isoformat()
    failed_ips = conn.execute('''
        SELECT DISTINCT source_ip FROM events
        WHERE event_type = ?
        AND timestamp >= ?
    ''', (rule['event_type'], window)).fetchall()
    failed_ips = [row['source_ip'] for row in failed_ips]
    triggered = 0
    for ip in failed_ips:
        success = conn.execute('''
            SELECT id FROM events
            WHERE event_type = ?
            AND source_ip = ?
            AND timestamp >= ?
            LIMIT 1
        ''', (rule['success_event_type'], ip, window)).fetchone()
        if success:
            insert_alert(
                rule_name=rule['name'],
                severity=rule['severity'],
                source_ip=ip,
                description=f"{rule['description']} - IP: {ip}",
                event_ids=[success['id']]
            )
            triggered += 1
    conn.close()
    print(f"{rule['name']}: {triggered} alerts triggered")

def run_all_rules():
    print("Running correlation rules...")
    rules = load_rules()
    for rule in rules:
        if 'success_event_type' in rule:
            run_followup_rule(rule)
        else:
            run_threshold_rule(rule)
    print("Correlation complete")

if __name__ == '__main__':
    run_all_rules()