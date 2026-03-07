/**
 * PhishWatch v2 — Dashboard Controller
 * Real-time Phishing Detection Platform
 */

class PhishWatchDashboard {
    constructor() {
        this.socket = io();
        this.detections = [];
        this.monitoring = false;
        this.charts = {};
        this.init();
    }

    init() {
        this.bindUI();
        this.bindSocket();
        this.initCharts();
        this.fetchStatus();
    }

    bindUI() {
        document.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', e => { e.preventDefault(); this.switchView(el.dataset.view); });
        });
        document.getElementById('toggleMonitor').addEventListener('click', () => this.toggleMonitoring());
        ['filterRisk', 'filterSource'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('change', () => this.applyFilters());
        });
        document.getElementById('btnExportCSV').addEventListener('click', () => { window.open('/api/v2/export?format=csv', '_blank'); });
        document.getElementById('btnRefresh').addEventListener('click', () => this.fetchDetections());
        document.getElementById('btnAnalyze').addEventListener('click', () => this.analyzeDomain());
        document.getElementById('analyzeDomain').addEventListener('keypress', e => { if (e.key === 'Enter') this.analyzeDomain(); });
        document.getElementById('modalClose').addEventListener('click', () => this.closeModal());
        document.getElementById('modalOverlay').addEventListener('click', e => { if (e.target === e.currentTarget) this.closeModal(); });
    }

    bindSocket() {
        this.socket.on('connect', () => console.log('[WS] Connected'));
        this.socket.on('new_detection', det => {
            this.detections.unshift(det);
            if (this.detections.length > 500) this.detections.pop();
            this.renderFeed();
            this.renderTable();
            this.renderThreatFeed();
            this.updateCharts();
            this.showToast(det);
        });
        this.socket.on('stats_update', stats => this.updateStats(stats));
    }

    switchView(name) {
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const view = document.getElementById(`view-${name}`);
        if (view) view.classList.add('active');
        const nav = document.querySelector(`.nav-item[data-view="${name}"]`);
        if (nav) nav.classList.add('active');
        const titles = { dashboard: 'Dashboard', detections: 'All Detections', threats: 'Threat Intelligence', analyze: 'Domain Analysis' };
        document.getElementById('viewTitle').textContent = titles[name] || 'Dashboard';
    }

    async toggleMonitoring() {
        const endpoint = this.monitoring ? '/api/v2/stop' : '/api/v2/start';
        try {
            const res = await fetch(endpoint, { method: 'POST' });
            const data = await res.json();
            this.monitoring = data.active;
            this.updateMonitorUI();
        } catch (err) { console.error('Toggle error:', err); }
    }

    updateMonitorUI() {
        const btn = document.getElementById('toggleMonitor');
        const dot = document.getElementById('statusDot');
        const label = document.getElementById('statusLabel');
        if (this.monitoring) {
            btn.textContent = 'Stop Monitoring'; btn.classList.add('active');
            dot.classList.add('active'); label.textContent = 'Monitoring';
        } else {
            btn.textContent = 'Start Monitoring'; btn.classList.remove('active');
            dot.classList.remove('active'); label.textContent = 'Offline';
        }
    }

    updateStats(stats) {
        this.monitoring = stats.monitoring;
        this.updateMonitorUI();
        this.setText('sTotalDetections', stats.total || 0);
        this.setText('sCritical', stats.critical || 0);
        this.setText('sHigh', stats.high || 0);
        this.setText('sAvgRisk', stats.avg_risk || 0);
    }

    renderFeed() {
        const container = document.getElementById('detectionFeed');
        const filtered = this.getFiltered();
        if (!filtered.length) {
            container.innerHTML = '<div class="feed__empty"><p>No detections match current filters.</p></div>';
            return;
        }
        container.innerHTML = filtered.slice(0, 80).map(d => {
            const rc = this.riskClass(d.risk_score);
            const time = this.timeAgo(d.timestamp);
            const target = d.similarity?.target;
            const targetBadge = target ? `<span class="target-tag">${target}</span>` : '';
            const icsBadge = d.ics_targeted ? `<span class="ics-tag">ICS/OT</span>` : '';
            return `<div class="feed-item" onclick="dashboard.showDetail(${d.id})">
                <div>
                    <div class="feed-item__domain">${this.esc(d.domain)}</div>
                    <div class="feed-item__meta">
                        <span>${d.source}</span>
                        <span>${time}</span>
                        ${targetBadge}${icsBadge}
                    </div>
                </div>
                <span class="risk-pill risk-pill--${rc}">${d.risk_score}</span>
            </div>`;
        }).join('');
    }

    renderTable() {
        const tbody = document.getElementById('detectionsBody');
        if (!tbody) return;
        tbody.innerHTML = this.detections.slice(0, 200).map(d => {
            const rc = this.riskClass(d.risk_score);
            return `<tr onclick="dashboard.showDetail(${d.id})" style="cursor:pointer">
                <td class="mono">${this.esc(d.domain)}</td>
                <td><span class="risk-pill risk-pill--${rc}">${d.risk_score}</span></td>
                <td>${d.threat_level}</td>
                <td>${d.source}</td>
                <td>${d.similarity?.target || '—'}</td>
                <td>${this.timeAgo(d.timestamp)}</td>
            </tr>`;
        }).join('');
    }

    renderThreatFeed() {
        const container = document.getElementById('threatFeed');
        if (!container) return;
        const critical = this.detections.filter(d => d.risk_score >= 80);
        if (!critical.length) {
            container.innerHTML = '<div class="feed__empty"><p>No critical threats detected yet.</p></div>';
            return;
        }
        container.innerHTML = critical.slice(0, 50).map(d => {
            const rc = this.riskClass(d.risk_score);
            const factors = (d.risk_factors || []).slice(0, 3).join(' · ');
            return `<div class="feed-item" onclick="dashboard.showDetail(${d.id})">
                <div>
                    <div class="feed-item__domain">${this.esc(d.domain)}</div>
                    <div class="feed-item__meta">
                        <span>${d.threat_level}</span>
                        <span>${d.similarity?.target || '—'}</span>
                        <span>${this.timeAgo(d.timestamp)}</span>
                        ${d.similarity?.typosquat ? '<span class="typo-tag">Typosquat</span>' : ''}
                        ${d.homograph?.detected ? '<span class="homo-tag">Homograph</span>' : ''}
                        ${d.ics_targeted ? '<span class="ics-tag">ICS/OT</span>' : ''}
                    </div>
                </div>
                <span class="risk-pill risk-pill--${rc}">${d.risk_score}</span>
            </div>`;
        }).join('');
    }

    showDetail(id) {
        const d = this.detections.find(x => x.id === id);
        if (!d) return;
        const body = document.getElementById('modalBody');

        let icsSection = '';
        if (d.ics_targeted) {
            icsSection = `<div style="margin-top:1rem; padding:0.85rem; background:var(--amber-dim); border:1px solid var(--amber); border-radius:var(--r);">
                <h4 style="color:var(--amber); margin-bottom:0.5rem;">ICS/OT Targeting Detected</h4>
                <div class="detail-grid">
                    <div class="detail-item"><label>Category</label><span>${d.ics_category || '—'}</span></div>
                    <div class="detail-item"><label>Sector</label><span>${d.ics_sector || '—'}</span></div>
                    <div class="detail-item"><label>Vendors</label><span class="mono">${(d.ics_vendors || []).join(', ') || '—'}</span></div>
                    <div class="detail-item"><label>Protocols</label><span class="mono">${(d.ics_protocols || []).join(', ') || '—'}</span></div>
                    <div class="detail-item"><label>MITRE ICS</label><span class="mono">${(d.ics_mitre || []).join(', ') || '—'}</span></div>
                </div>
            </div>`;
        }

        body.innerHTML = `
            <div class="result-header">
                <div class="result-score" style="border:3px solid ${d.color || '#6b7280'}; color:${d.color || '#6b7280'}">${d.risk_score}</div>
                <div>
                    <div style="font-family:var(--font-mono); font-size:1.05rem; color:var(--text-0); word-break:break-all">${this.esc(d.domain)}</div>
                    <div style="font-size:0.82rem; color:var(--text-2)">${d.threat_level} · ${d.source} · ${d.timestamp}</div>
                </div>
            </div>
            <div class="detail-grid" style="margin-top:1rem">
                <div class="detail-item"><label>Target Brand</label><span>${d.similarity?.target || '—'}</span></div>
                <div class="detail-item"><label>Similarity</label><span>${d.similarity?.score || 0}%</span></div>
                <div class="detail-item"><label>Entropy</label><span class="mono">${(d.entropy || 0).toFixed(2)}</span></div>
                <div class="detail-item"><label>IP Address</label><span class="mono">${d.ip_address || '—'}</span></div>
                <div class="detail-item"><label>Homograph</label><span>${d.homograph?.detected ? 'Yes ⚠' : 'No'}</span></div>
                <div class="detail-item"><label>Typosquat</label><span>${d.similarity?.typosquat ? 'Yes ⚠' : 'No'}</span></div>
            </div>
            ${icsSection}
            <div style="margin-top:1rem">
                <h4 style="font-size:0.78rem; text-transform:uppercase; color:var(--text-3); margin-bottom:0.35rem">Risk Factors</h4>
                <ul style="list-style:none; padding:0">
                    ${(d.risk_factors || []).map(f => `<li style="padding:0.15rem 0; font-size:0.85rem; color:var(--text-1)">› ${this.esc(f)}</li>`).join('')}
                </ul>
            </div>`;
        document.getElementById('modalOverlay').classList.add('active');
    }

    closeModal() { document.getElementById('modalOverlay').classList.remove('active'); }

    async analyzeDomain() {
        const input = document.getElementById('analyzeDomain');
        const domain = input.value.trim();
        if (!domain) return;
        const resultDiv = document.getElementById('analyzeResult');
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<p style="color:var(--text-2)">Analyzing...</p>';
        try {
            const res = await fetch('/api/v2/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }) });
            const data = await res.json();
            let icsHtml = '';
            if (data.ics_context) {
                const ctx = data.ics_context;
                icsHtml = `<div class="result-section" style="background:var(--amber-dim); padding:0.75rem; border-radius:var(--r); border:1px solid var(--amber)">
                    <h4 style="color:var(--amber)">ICS/OT Context</h4>
                    <ul><li>Category: ${ctx.category || '—'}</li><li>Sector: ${ctx.sector || '—'}</li><li>Vendors: ${(ctx.vendors || []).join(', ') || 'None'}</li><li>MITRE ICS: ${(ctx.mitre_techniques || []).join(', ') || 'None'}</li></ul>
                </div>`;
            }
            resultDiv.innerHTML = `
                <div class="result-header">
                    <div class="result-score" style="border:3px solid ${data.color}; color:${data.color}">${data.risk_score}</div>
                    <div>
                        <div style="font-family:var(--font-mono); font-size:1.1rem; color:var(--text-0)">${this.esc(domain)}</div>
                        <div style="color:var(--text-2); font-size:0.85rem">${data.threat_level} — ${data.summary || ''}</div>
                    </div>
                </div>
                <div class="result-sections" style="margin-top:1rem">
                    ${icsHtml}
                    <div class="result-section"><h4>Recommendations</h4><ul>${(data.recommendations || []).map(r => `<li>${this.esc(r)}</li>`).join('')}</ul></div>
                </div>`;
        } catch (err) { resultDiv.innerHTML = `<p style="color:var(--red)">Error: ${err.message}</p>`; }
    }

    initCharts() {
        Chart.defaults.color = '#7a8baa'; Chart.defaults.borderColor = '#1e2a42';
        const riskCtx = document.getElementById('chartRisk');
        if (riskCtx) {
            this.charts.risk = new Chart(riskCtx, {
                type: 'doughnut',
                data: { labels: ['Critical', 'High', 'Medium', 'Low'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'], borderWidth: 0 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12, font: { size: 11 } } } } }
            });
        }
        const timeCtx = document.getElementById('chartTimeline');
        if (timeCtx) {
            this.charts.timeline = new Chart(timeCtx, {
                type: 'bar',
                data: { labels: Array.from({length:12},(_,i)=>`${i*2}:00`), datasets: [{ label: 'Detections', data: new Array(12).fill(0), backgroundColor: '#3b82f6', borderRadius: 4 }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: '#1e2a42' } } } }
            });
        }
    }

    updateCharts() {
        if (this.charts.risk) {
            const c = this.detections.reduce((a,d) => { if(d.risk_score>=90) a[0]++; else if(d.risk_score>=70) a[1]++; else if(d.risk_score>=50) a[2]++; else a[3]++; return a; }, [0,0,0,0]);
            this.charts.risk.data.datasets[0].data = c; this.charts.risk.update('none');
        }
        if (this.charts.timeline) {
            const buckets = new Array(12).fill(0);
            this.detections.forEach(d => { try { buckets[Math.floor(new Date(d.timestamp).getHours()/2)]++; } catch{} });
            this.charts.timeline.data.datasets[0].data = buckets; this.charts.timeline.update('none');
        }
    }

    getFiltered() {
        let list = [...this.detections];
        const risk = document.getElementById('filterRisk')?.value || 'all';
        const source = document.getElementById('filterSource')?.value || 'all';
        if (risk !== 'all') { const ranges = {critical:[90,101],high:[70,90],medium:[50,70]}; const [lo,hi]=ranges[risk]||[0,101]; list=list.filter(d=>d.risk_score>=lo&&d.risk_score<hi); }
        if (source !== 'all') list = list.filter(d => d.source.toLowerCase() === source);
        return list;
    }

    applyFilters() { this.renderFeed(); }

    showToast(d) {
        if (d.risk_score < 70) return;
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<div class="toast__title">🚨 ${d.threat_level} Threat</div><div class="toast__domain">${this.esc(d.domain)}</div><div class="toast__score">Score: ${d.risk_score}/100 · ${d.similarity?.target || 'Unknown target'}</div>`;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 6000);
    }

    async fetchStatus() {
        try { const res = await fetch('/api/v2/status'); const data = await res.json(); this.monitoring = data.monitoring; this.updateMonitorUI(); this.updateStats(data.stats); } catch {}
        this.fetchDetections();
    }

    async fetchDetections() {
        try { const res = await fetch('/api/v2/detections?limit=200'); const data = await res.json(); this.detections = data.detections || []; this.renderFeed(); this.renderTable(); this.renderThreatFeed(); this.updateCharts(); } catch (err) { console.error('Fetch error:', err); }
    }

    setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
    riskClass(s) { return s >= 90 ? 'critical' : s >= 70 ? 'high' : s >= 50 ? 'medium' : 'low'; }
    timeAgo(ts) { const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000); if (s<60) return s+'s ago'; if (s<3600) return Math.floor(s/60)+'m ago'; if (s<86400) return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
    esc(str) { const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML; }
}

document.addEventListener('DOMContentLoaded', () => { window.dashboard = new PhishWatchDashboard(); });
