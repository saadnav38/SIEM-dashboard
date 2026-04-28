from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from database import get_connection, init_db
from correlator import run_all_rules
from ingestor import generate_sample_logs
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'siem-secret-key-change-in-production'

USERS = {
    'analyst': generate_password_hash('siem1234'),
    'admin': generate_password_hash('admin5678')
}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and check_password_hash(USERS[username], password):
            session['username'] = username
            return redirect(url_for('index'))
        error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/api/events')
@login_required
def get_events():
    conn = get_connection()
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    source_ip = request.args.get('source_ip')
    hours = int(request.args.get('hours', 24))
    limit = int(request.args.get('limit', 100))

    window = (datetime.now() - timedelta(hours=hours)).isoformat()
    query = 'SELECT * FROM events WHERE timestamp >= ?'
    params = [window]

    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if event_type:
        query += ' AND event_type = ?'
        params.append(event_type)
    if source_ip:
        query += ' AND source_ip = ?'
        params.append(source_ip)

    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/alerts')
@login_required
def get_alerts():
    conn = get_connection()
    rows = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50').fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/stats')
@login_required
def get_stats():
    conn = get_connection()
    hours = int(request.args.get('hours', 24))
    window = (datetime.now() - timedelta(hours=hours)).isoformat()

    severity_counts = conn.execute('''
        SELECT severity, COUNT(*) as count FROM events
        WHERE timestamp >= ?
        GROUP BY severity
    ''', (window,)).fetchall()

    type_counts = conn.execute('''
        SELECT event_type, COUNT(*) as count FROM events
        WHERE timestamp >= ?
        GROUP BY event_type
    ''', (window,)).fetchall()

    top_ips = conn.execute('''
        SELECT source_ip, COUNT(*) as count FROM events
        WHERE timestamp >= ?
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 5
    ''', (window,)).fetchall()

    total = conn.execute('SELECT COUNT(*) as count FROM events WHERE timestamp >= ?', (window,)).fetchone()
    alert_count = conn.execute('SELECT COUNT(*) as count FROM alerts').fetchone()

    conn.close()
    return jsonify({
        'severity_counts': [dict(r) for r in severity_counts],
        'type_counts': [dict(r) for r in type_counts],
        'top_ips': [dict(r) for r in top_ips],
        'total_events': total['count'],
        'total_alerts': alert_count['count']
    })

@app.route('/api/events/<int:event_id>')
@login_required
def get_event(event_id):
    conn = get_connection()
    row = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'Event not found'}), 404

@app.route('/api/export')
@login_required
def export_events():
    import csv
    import io
    import json as json_lib
    conn = get_connection()
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    source_ip = request.args.get('source_ip')
    hours = int(request.args.get('hours', 24))
    fmt = request.args.get('format', 'csv')

    window = (datetime.now() - timedelta(hours=hours)).isoformat()
    query = 'SELECT * FROM events WHERE timestamp >= ?'
    params = [window]

    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if event_type:
        query += ' AND event_type = ?'
        params.append(event_type)
    if source_ip:
        query += ' AND source_ip = ?'
        params.append(source_ip)

    query += ' ORDER BY timestamp DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    events = [dict(row) for row in rows]

    if fmt == 'json':
        output = json_lib.dumps(events, indent=2)
        return app.response_class(
            response=output,
            status=200,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=siem_export.json'}
        )
    else:
        output = io.StringIO()
        if events:
            writer = csv.DictWriter(output, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        return app.response_class(
            response=output.getvalue(),
            status=200,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=siem_export.csv'}
        )

@app.route('/api/timeline')
@login_required
def get_timeline():
    conn = get_connection()
    hours = int(request.args.get('hours', 24))
    window = (datetime.now() - timedelta(hours=hours)).isoformat()
    rows = conn.execute('''
        SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
               COUNT(*) as count
        FROM events
        WHERE timestamp >= ?
        GROUP BY hour
        ORDER BY hour ASC
    ''', (window,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/ingest', methods=['POST'])
@login_required
def ingest():
    generate_sample_logs(50)
    run_all_rules()
    return jsonify({'status': 'ingestion and correlation complete'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)