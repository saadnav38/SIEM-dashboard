import json
import re
import sqlite3
import random
from datetime import datetime, timedelta
from database import get_connection

def insert_event(timestamp, source_ip, destination_ip, severity, event_type, source, message, raw):
    conn = get_connection()
    conn.execute('''
        INSERT INTO events (timestamp, source_ip, destination_ip, severity, event_type, source, message, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, source_ip, destination_ip, severity, event_type, source, message, raw))
    conn.commit()
    conn.close()

def parse_suricata_log(filepath):
    parsed = 0
    with open(filepath, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                if data.get('event_type') != 'alert':
                    continue
                timestamp = data.get('timestamp', datetime.now().isoformat())
                source_ip = data.get('src_ip', 'unknown')
                destination_ip = data.get('dest_ip', 'unknown')
                severity_num = data.get('alert', {}).get('severity', 3)
                severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
                severity = severity_map.get(severity_num, 'low')
                message = data.get('alert', {}).get('signature', 'Suricata Alert')
                insert_event(timestamp, source_ip, destination_ip, severity, 'ids_alert', 'suricata', message, line.strip())
                parsed += 1
            except Exception as e:
                continue
    print(f"Suricata: parsed {parsed} alerts")

def parse_suricata_eve(filepath):
    parsed = 0
    with open(filepath, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                event_type = data.get('event_type', '')
                timestamp = data.get('timestamp', datetime.now().isoformat())
                source_ip = data.get('src_ip', 'unknown')
                destination_ip = data.get('dest_ip', 'unknown')

                if event_type == 'alert':
                    severity_num = data.get('alert', {}).get('severity', 3)
                    severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
                    severity = severity_map.get(severity_num, 'low')
                    message = data.get('alert', {}).get('signature', 'Suricata Alert')
                    insert_event(timestamp, source_ip, destination_ip, severity, 'ids_alert', 'suricata', message, line.strip())
                    parsed += 1

                elif event_type == 'flow':
                    flow = data.get('flow', {})
                    proto = data.get('proto', 'unknown')
                    dest_port = data.get('dest_port', '')
                    bytes_to = flow.get('bytes_toserver', 0)
                    bytes_from = flow.get('bytes_toclient', 0)
                    severity = 'low'
                    if dest_port in [22, 23, 3389, 445, 1433]:
                        severity = 'medium'
                    message = f"Network flow {proto} from {source_ip} to {destination_ip}:{dest_port} bytes sent:{bytes_to} received:{bytes_from}"
                    insert_event(timestamp, source_ip, destination_ip, severity, 'network_flow', 'suricata', message, line.strip())
                    parsed += 1

                elif event_type == 'dns':
                    dns = data.get('dns', {})
                    query = dns.get('rrname', 'unknown')
                    dns_type = dns.get('type', 'unknown')
                    message = f"DNS {dns_type} for {query} from {source_ip}"
                    insert_event(timestamp, source_ip, destination_ip, 'low', 'dns_query', 'suricata', message, line.strip())
                    parsed += 1

                elif event_type == 'dhcp':
                    dhcp = data.get('dhcp', {})
                    dhcp_type = dhcp.get('type', 'unknown')
                    hostname = dhcp.get('hostname', 'unknown')
                    assigned_ip = dhcp.get('assigned_ip', 'unknown')
                    message = f"DHCP {dhcp_type} hostname:{hostname} assigned:{assigned_ip}"
                    insert_event(timestamp, source_ip, destination_ip, 'low', 'dhcp_event', 'suricata', message, line.strip())
                    parsed += 1

            except Exception as e:
                continue
    print(f"Suricata eve.json: parsed {parsed} real events")


if __name__ == '__main__':
    import os
    eve_path = os.path.join('logs', 'eve.json')
    if os.path.exists(eve_path):
        parse_suricata_eve(eve_path)
    else:
        print("No eve.json found in logs/, generating sample data instead")
        generate_sample_logs(200)    

def parse_auth_log(filepath):
    parsed = 0
    failed_pattern = re.compile(r'(\w+\s+\d+\s+[\d:]+).*Failed password for (\S+) from ([\d.]+)')
    accepted_pattern = re.compile(r'(\w+\s+\d+\s+[\d:]+).*Accepted password for (\S+) from ([\d.]+)')
    with open(filepath, 'r') as f:
        for line in f:
            try:
                failed = failed_pattern.search(line)
                accepted = accepted_pattern.search(line)
                if failed:
                    timestamp, user, source_ip = failed.group(1), failed.group(2), failed.group(3)
                    message = f"Failed SSH login for user {user} from {source_ip}"
                    insert_event(datetime.now().isoformat(), source_ip, 'local', 'medium', 'auth_failure', 'auth_log', message, line.strip())
                    parsed += 1
                elif accepted:
                    timestamp, user, source_ip = accepted.group(1), accepted.group(2), accepted.group(3)
                    message = f"Successful SSH login for user {user} from {source_ip}"
                    insert_event(datetime.now().isoformat(), source_ip, 'local', 'low', 'auth_success', 'auth_log', message, line.strip())
                    parsed += 1
            except Exception as e:
                continue
    print(f"Auth log: parsed {parsed} events")

def parse_firewall_log(filepath):
    parsed = 0
    pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T[\d:]+).*?(ALLOW|DENY).*?SRC=([\d.]+).*?DST=([\d.]+).*?DPT=(\d+)')
    with open(filepath, 'r') as f:
        for line in f:
            try:
                match = pattern.search(line)
                if match:
                    timestamp, action, source_ip, dest_ip, port = match.groups()
                    severity = 'high' if action == 'DENY' and port in ['22', '3389', '445'] else 'low'
                    message = f"Firewall {action} from {source_ip} to {dest_ip} on port {port}"
                    insert_event(timestamp, source_ip, dest_ip, severity, f'firewall_{action.lower()}', 'firewall', message, line.strip())
                    parsed += 1
            except Exception as e:
                continue
    print(f"Firewall log: parsed {parsed} events")

def generate_sample_logs(num_events=200):
    ips = ['192.168.1.105', '10.0.0.23', '172.16.0.8', '45.33.32.156', '198.51.100.42', '203.0.113.15']
    event_types = ['ids_alert', 'auth_failure', 'auth_success', 'firewall_deny', 'firewall_allow']
    severities = ['critical', 'high', 'medium', 'low']
    messages = {
        'ids_alert': ['ET SCAN Nmap OS Detection', 'ET EXPLOIT EternalBlue', 'ET MALWARE CobaltStrike Beacon', 'ET SCAN Port Sweep'],
        'auth_failure': ['Failed SSH login for user root', 'Failed SSH login for user admin', 'Failed SSH login for user ubuntu'],
        'auth_success': ['Successful SSH login for user saad', 'Successful SSH login for user admin'],
        'firewall_deny': ['Firewall DENY on port 22', 'Firewall DENY on port 445', 'Firewall DENY on port 3389'],
        'firewall_allow': ['Firewall ALLOW on port 80', 'Firewall ALLOW on port 443']
    }
    now = datetime.now()
    inserted = 0
    for i in range(num_events):
        event_type = random.choice(event_types)
        source_ip = random.choice(ips)
        severity = 'critical' if event_type == 'ids_alert' and random.random() < 0.2 else random.choice(severities)
        timestamp = (now - timedelta(minutes=random.randint(0, 1440))).isoformat()
        message = random.choice(messages[event_type])
        insert_event(timestamp, source_ip, '192.168.1.1', severity, event_type, 'simulated', message, f'simulated log entry {i}')
        inserted += 1
    print(f"Generated {inserted} sample events")

if __name__ == '__main__':
    import os
    eve_path = os.path.join('logs', 'eve.json')
    if os.path.exists(eve_path):
        parse_suricata_eve(eve_path)
    else:
        print("No eve.json found in logs/, generating sample data instead")
        generate_sample_logs(200)