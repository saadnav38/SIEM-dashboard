let severityChart = null;
let typeChart = null;
let timelineChart = null;

async function fetchJSON(url) {
    const res = await fetch(url);
    return res.json();
}

function getHours() {
    return document.getElementById('filter-hours').value;
}

function getSeverity() {
    return document.getElementById('filter-severity').value;
}

function getType() {
    return document.getElementById('filter-type').value;
}

function getIP() {
    return document.getElementById('filter-ip').value;
}

function formatTime(ts) {
    if (!ts) return '--';
    return new Date(ts).toLocaleString();
}

function badge(severity) {
    return `<span class="badge ${severity}">${severity}</span>`;
}

async function loadStats() {
    const hours = getHours();
    const data = await fetchJSON(`/api/stats?hours=${hours}`);

    document.getElementById('total-events').textContent = data.total_events;
    document.getElementById('total-alerts').textContent = data.total_alerts;

    const severityMap = {};
    data.severity_counts.forEach(s => severityMap[s.severity] = s.count);
    document.getElementById('critical-count').textContent = severityMap['critical'] || 0;
    document.getElementById('high-count').textContent = severityMap['high'] || 0;
    document.getElementById('medium-count').textContent = severityMap['medium'] || 0;

    const severityLabels = data.severity_counts.map(s => s.severity);
    const severityValues = data.severity_counts.map(s => s.count);
    const severityColors = severityLabels.map(s => {
        if (s === 'critical') return '#f85149';
        if (s === 'high') return '#d29922';
        if (s === 'medium') return '#388bfd';
        return '#3fb950';
    });

    if (severityChart) severityChart.destroy();
    severityChart = new Chart(document.getElementById('severity-chart'), {
        type: 'doughnut',
        data: {
            labels: severityLabels,
            datasets: [{ data: severityValues, backgroundColor: severityColors, borderWidth: 0 }]
        },
        options: { 
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#c9d1d9' } } } }
    });

    const typeLabels = data.type_counts.map(t => t.event_type);
    const typeValues = data.type_counts.map(t => t.count);

    if (typeChart) typeChart.destroy();
    typeChart = new Chart(document.getElementById('type-chart'), {
        type: 'bar',
        data: {
            labels: typeLabels,
            datasets: [{
                label: 'Events',
                data: typeValues,
                backgroundColor: '#1f6feb',
                borderRadius: 4
            }]
        },
        options: {
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
            }
        }
    });
}

async function loadAlerts() {
    const data = await fetchJSON('/api/alerts');
    const tbody = document.getElementById('alerts-body');
    tbody.innerHTML = '';
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:#8b949e;text-align:center;">No alerts triggered</td></tr>';
        return;
    }
    data.forEach(alert => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatTime(alert.timestamp)}</td>
            <td>${alert.rule_name}</td>
            <td>${badge(alert.severity)}</td>
            <td>${alert.source_ip}</td>
            <td>${alert.description}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function loadEvents() {
    const hours = getHours();
    const severity = getSeverity();
    const type = getType();
    const ip = getIP();

    let url = `/api/events?hours=${hours}&limit=100`;
    if (severity) url += `&severity=${severity}`;
    if (type) url += `&event_type=${type}`;
    if (ip) url += `&source_ip=${ip}`;

    const data = await fetchJSON(url);
    const tbody = document.getElementById('events-body');
    tbody.innerHTML = '';
    data.forEach(event => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatTime(event.timestamp)}</td>
            <td>${event.source_ip}</td>
            <td>${badge(event.severity)}</td>
            <td>${event.event_type}</td>
            <td>${event.source}</td>
            <td>${event.message}</td>
        `;
        tr.onclick = () => openModal(event.id);
        tbody.appendChild(tr);
    });
}

async function openModal(id) {
    const event = await fetchJSON(`/api/events/${id}`);
    const fields = ['id', 'timestamp', 'source_ip', 'destination_ip', 'severity', 'event_type', 'source', 'message', 'raw'];
    let html = '';
    fields.forEach(f => {
        html += `
            <div class="modal-body-row">
                <div class="modal-body-label">${f}</div>
                <div class="modal-body-value">${event[f] || '--'}</div>
            </div>
        `;
    });
    document.getElementById('modal-body').innerHTML = html;
    document.getElementById('modal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal').classList.add('hidden');
}

async function loadAll() {
    await Promise.all([loadStats(), loadAlerts(), loadEvents(), loadTopIPs(), loadTimeline()]);
    document.getElementById('last-updated').textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
}

function exportEvents(format) {
    const hours = getHours();
    const severity = getSeverity();
    const type = getType();
    const ip = getIP();

    let url = `/api/export?format=${format}&hours=${hours}`;
    if (severity) url += `&severity=${severity}`;
    if (type) url += `&event_type=${type}`;
    if (ip) url += `&source_ip=${ip}`;

    const a = document.createElement('a');
    a.href = url;
    a.download = `siem_export.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

async function triggerIngest() {
    const btn = document.getElementById('ingest-btn');
    btn.textContent = 'Running...';
    btn.disabled = true;
    await fetch('/api/ingest', { method: 'POST' });
    await loadAll();
    btn.textContent = 'Run Ingestion';
    btn.disabled = false;
}

async function loadTimeline() {
    const hours = getHours();
    const data = await fetchJSON(`/api/timeline?hours=${hours}`);

    const labels = data.map(d => {
        const date = new Date(d.hour);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    const values = data.map(d => d.count);

    if (timelineChart) timelineChart.destroy();
    timelineChart = new Chart(document.getElementById('timeline-chart'), {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Events per Hour',
                data: values,
                borderColor: '#58a6ff',
                backgroundColor: 'rgba(88, 166, 255, 0.1)',
                borderWidth: 2,
                pointRadius: 3,
                pointBackgroundColor: '#58a6ff',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            plugins: { legend: { labels: { color: '#c9d1d9' } } },
            scales: {
                x: {
                    ticks: { color: '#8b949e', maxTicksLimit: 12 },
                    grid: { color: '#21262d' }
                },
                y: {
                    ticks: { color: '#8b949e' },
                    grid: { color: '#21262d' },
                    beginAtZero: true
                }
            }
        }
    });
}

async function loadTopIPs() {
    const hours = getHours();
    const data = await fetchJSON(`/api/stats?hours=${hours}`);
    const tbody = document.getElementById('top-ips-body');
    tbody.innerHTML = '';
    if (data.top_ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="color:#8b949e;text-align:center;">No data</td></tr>';
        return;
    }
    data.top_ips.forEach(ip => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${ip.source_ip}</td>
            <td>${ip.count}</td>
            <td><button onclick="filterByIP('${ip.source_ip}')">Investigate</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function filterByIP(ip) {
    document.getElementById('filter-ip').value = ip;
    loadEvents();
    document.getElementById('events-body').scrollIntoView({ behavior: 'smooth' });
}

loadAll();
setInterval(loadAll, 30000);