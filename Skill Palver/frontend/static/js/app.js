const COLORS = {
    UDP: '#ef4444',
    TCP: '#3b82f6',
    HTTP: '#10b981',
    ICMP: '#f59e0b',
    DNS: '#8b5cf6'
};

const PROTOCOL_COLORS = ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'];
let colorIndex = 0;

function getProtocolColor(proto) {
    if (COLORS[proto]) return COLORS[proto];
    const color = PROTOCOL_COLORS[colorIndex % PROTOCOL_COLORS.length];
    COLORS[proto] = color;
    colorIndex++;
    return color;
}

const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
    type: 'line',
    data: { labels: [], datasets: [] },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
            x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
        },
        plugins: {
            legend: { position: 'top', labels: { color: '#f8fafc', usePointStyle: true, pointStyle: 'circle' } }
        },
        animation: { duration: 0 }
    }
});

const effCtx = document.getElementById('effectivenessChart').getContext('2d');
const effectivenessChart = new Chart(effCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Normal State',
                data: [],
                borderColor: '#22c55e',
                backgroundColor: 'rgba(34,197,94,0.1)',
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2
            },
            {
                label: 'During Attack',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239,68,68,0.1)',
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2
            },
            {
                label: 'After Mitigation',
                data: [],
                borderColor: '#38bdf8',
                backgroundColor: 'rgba(56,189,248,0.1)',
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
            x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
        },
        plugins: { legend: { labels: { color: '#f8fafc' } } },
        animation: { duration: 0 }
    }
});

const gridContainer = document.getElementById('protocol-status-grid');

function ensureProtocolUI(proto) {
    if (!document.getElementById(`card-${proto}`)) {
        const col = document.createElement('div');
        col.className = 'col-md-2 mb-3';
        col.style.width = '20%';
        col.innerHTML = `
            <div class="card h-100 mb-0 protocol-card border-0" id="card-${proto}">
                <div class="card-body p-2 text-center">
                    <div class="small text-muted mb-1">${proto}</div>
                    <div class="h4 fw-bold mb-0" id="pps-${proto}">0</div>
                    <div class="small fw-bold" id="status-${proto}" style="color: #10b981; font-size: 0.65rem;">NORMAL</div>
                </div>
            </div>
        `;
        gridContainer.appendChild(col);

        trafficChart.data.datasets.push({
            label: proto,
            data: new Array(trafficChart.data.labels.length).fill(0),
            borderColor: getProtocolColor(proto),
            backgroundColor: getProtocolColor(proto),
            tension: 0.3,
            pointRadius: 0,
            borderWidth: 2
        });
    }
}

function updateEffectivenessChart(history) {
    const maxLen = Math.max(history.normal.length, history.during_attack.length, history.after_mitigation.length, 1);
    const labels = Array.from({ length: maxLen }, (_, i) => `${i + 1}`);
    effectivenessChart.data.labels = labels;
    effectivenessChart.data.datasets[0].data = [...history.normal];
    effectivenessChart.data.datasets[1].data = [...history.during_attack];
    effectivenessChart.data.datasets[2].data = [...history.after_mitigation];
    effectivenessChart.update('none');
}

function updateBlockedIpList(blockedIps) {
    const list = document.getElementById('blocked-ip-list');
    if (!blockedIps.length) {
        list.innerText = 'No blocked IPs';
        return;
    }
    list.innerHTML = blockedIps.map((ip) => `<div><code>${ip}</code></div>`).join('');
}

function updateFlowStepper(intellect, mit) {
    const steps = [
        { id: 'step-detection', active: intellect.attack_detected },
        { id: 'step-classification', active: intellect.attack_type !== 'None' },
        { id: 'step-intelligence', active: intellect.confidence_score > 40 },
        { id: 'step-mitigation', active: mit.stage > 0 },
        { id: 'step-stabilization', active: mit.stage > 0 && mit.effectiveness.stabilized !== 'N/A' }
    ];

    steps.forEach((step) => {
        const el = document.getElementById(step.id);
        const state = step.active ? 'ACTIVE' : 'PENDING';
        el.classList.toggle('flow-active', step.active);
        el.classList.toggle('flow-pending', !step.active);
        el.querySelector('span').innerText = state;
    });
}

function renderSourceTable(intellect, mit) {
    const attackerTbody = document.getElementById('attacker-table');
    attackerTbody.innerHTML = '';

    const activeProtos = Object.keys(intellect.protocols);
    const topTalkers = [];
    activeProtos.forEach((proto) => {
        intellect.protocols[proto].sources.forEach((src) => {
            topTalkers.push({ ...src, proto });
        });
    });

    topTalkers.sort((a, b) => b.threat_confidence - a.threat_confidence);
    topTalkers.slice(0, 12).forEach((src) => {
        const protoBlocked = mit.proto_blocked[src.proto] || [];
        const isBlocked = mit.global_blocked.includes(src.ip) || protoBlocked.includes(src.ip);
        const row = `
            <tr>
                <td><code>${src.ip}</code> <span class="text-muted">(${src.proto})</span></td>
                <td>${src.country || src.geo}</td>
                <td><span class="fw-bold ${src.risk_score > 70 ? 'text-danger' : 'text-warning'}">${src.risk_score}</span></td>
                <td><span class="fw-bold ${src.threat_confidence > 70 ? 'text-danger' : 'text-info'}">${src.threat_confidence}%</span></td>
                <td><span class="text-danger">${src.bot_probability}% bot</span> / <span class="text-success">${src.human_probability}% human</span></td>
                <td>
                    <button class="btn btn-xs ${isBlocked ? 'btn-success' : 'btn-outline-danger'} p-0 px-1" style="font-size: 0.6rem;"
                        onclick="${isBlocked ? `unblockIp('${src.ip}', '${src.proto}')` : `blockIp('${src.ip}', '${src.proto}')`}">
                        ${isBlocked ? 'UNBLOCK' : 'BLOCK'}
                    </button>
                </td>
            </tr>
        `;
        attackerTbody.innerHTML += row;
    });
}

function updateStats() {
    fetch('/simulate')
        .then(() => fetch('/status'))
        .then((res) => res.json())
        .then((data) => {
            const intellect = data.intelligence;
            const mit = data.mitigation;

            const globalSev = document.getElementById('global-severity');
            globalSev.innerText = intellect.severity;
            globalSev.className = `badge-severity severity-${intellect.severity.toLowerCase()}`;

            const banner = document.getElementById('attack-banner');
            if (intellect.attack_detected) {
                banner.classList.remove('d-none');
            } else {
                banner.classList.add('d-none');
            }

            document.getElementById('detected-type').innerText = intellect.attack_type;
            document.getElementById('detected-confidence').innerText = `${intellect.confidence_score}%`;
            document.getElementById('recommended-action').innerText = mit.recommended;
            document.getElementById('attack-type-value').innerText = intellect.attack_type;

            document.getElementById('confidence-fill').style.width = `${intellect.confidence_score}%`;
            document.getElementById('confidence-text').innerText = `${intellect.confidence_score}%`;
            document.getElementById('entropy-value').innerText = intellect.entropy;
            document.getElementById('dropped-value').innerText = data.dropped_packets;
            document.getElementById('dropped-total').innerText = data.dropped_packets;

            const fwBadge = document.getElementById('fw-status');
            fwBadge.innerText = mit.firewall_status;
            fwBadge.className = `badge ${mit.firewall_status === 'Triggered' ? 'bg-danger' : 'bg-secondary'}`;

            document.getElementById('blocked-count').innerText = mit.blocked_count;
            document.getElementById('rate-limited-count').innerText = mit.rate_limited_count;
            document.getElementById('mitigation-status').innerText = mit.status;
            document.getElementById('mitigation-action').innerText = mit.action_taken;
            updateBlockedIpList(mit.blocked_ips);

            document.getElementById('eff-normal').innerText = mit.effectiveness.normal;
            document.getElementById('eff-attack').innerText = mit.effectiveness.during_attack;
            document.getElementById('eff-stabilized').innerText = mit.effectiveness.stabilized;

            const actionList = document.getElementById('action-list');
            actionList.innerHTML = '';
            mit.actions.slice().reverse().forEach((act) => {
                const div = document.createElement('div');
                div.className = 'log-entry border-0 py-1';
                div.innerHTML = `<span class="text-muted">[${act.timestamp}]</span> <span class="text-info">${act.action}:</span> ${act.detail}`;
                actionList.appendChild(div);
            });

            updateFlowStepper(intellect, mit);

            const now = new Date().toLocaleTimeString();
            const activeProtos = Object.keys(intellect.protocols);

            activeProtos.forEach((proto) => {
                ensureProtocolUI(proto);
                const pData = intellect.protocols[proto];
                document.getElementById(`pps-${proto}`).innerText = pData.pps;

                const statusText = document.getElementById(`status-${proto}`);
                const card = document.getElementById(`card-${proto}`);
                if (pData.attack) {
                    statusText.innerText = 'ATTACK';
                    statusText.style.color = '#ef4444';
                    card.classList.add('alert-pulse');
                } else {
                    statusText.innerText = 'NORMAL';
                    statusText.style.color = '#10b981';
                    card.classList.remove('alert-pulse');
                }
            });

            if (trafficChart.data.labels.length > 30) {
                trafficChart.data.labels.shift();
                trafficChart.data.datasets.forEach((ds) => ds.data.shift());
            }

            trafficChart.data.labels.push(now);
            trafficChart.data.datasets.forEach((ds) => {
                const pData = intellect.protocols[ds.label];
                const pps = pData ? pData.pps : 0;
                ds.data.push(pps);
                ds.borderWidth = pData && pData.attack ? 4 : 2;
                ds.pointRadius = pData && pData.attack ? 2 : 0;
            });
            trafficChart.update('none');

            const logContainer = document.getElementById('timeline-log');
            logContainer.innerHTML = '';
            data.timeline.forEach((entry) => {
                const div = document.createElement('div');
                div.className = 'log-entry';
                if (entry.includes('ALERT') || entry.includes('DETECTED')) div.classList.add('text-danger');
                else if (entry.includes('ACTION') || entry.includes('MITIGATION')) div.classList.add('text-warning');
                div.innerText = entry;
                logContainer.appendChild(div);
            });

            renderSourceTable(intellect, mit);
            updateEffectivenessChart(data.traffic_history);
        })
        .catch((err) => console.error('Update failed:', err));
}

function unblockIp(ip, proto = null) {
    fetch('/api/mitigate/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, protocol: proto })
    }).then(() => updateStats());
}

function blockIp(ip, proto = null) {
    fetch('/api/mitigate/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, protocol: proto })
    }).then(() => updateStats());
}

function startAttack() {
    const type = document.getElementById('attack-type-select').value;
    fetch(`/start_attack?type=${encodeURIComponent(type)}`).then(() => updateStats());
}

function stopAttack() {
    fetch('/stop_attack').then(() => updateStats());
}

setInterval(updateStats, 1000);
updateStats();
