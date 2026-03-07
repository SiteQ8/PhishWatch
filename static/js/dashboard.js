// PhishGuard Dashboard JavaScript
class PhishGuardDashboard {
    constructor() {
        this.socket = io();
        this.isMonitoring = false;
        this.detections = [];
        this.setupEventListeners();
        this.setupSocketEvents();
    }

    setupEventListeners() {
        // Toggle monitoring
        document.getElementById('toggleMonitoring').addEventListener('click', () => {
            this.toggleMonitoring();
        });

        // Filters
        document.getElementById('riskFilter').addEventListener('change', () => {
            this.applyFilters();
        });

        document.getElementById('sourceFilter').addEventListener('change', () => {
            this.applyFilters();
        });

        // Export button
        document.getElementById('exportBtn').addEventListener('click', () => {
            this.exportData();
        });

        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshData();
        });
    }

    setupSocketEvents() {
        this.socket.on('connect', () => {
            console.log('Connected to server');
        });

        this.socket.on('new_detection', (detection) => {
            this.addDetection(detection);
        });

        this.socket.on('stats_update', (stats) => {
            this.updateStats(stats);
        });
    }

    toggleMonitoring() {
        const endpoint = this.isMonitoring ? '/api/stop_monitoring' : '/api/start_monitoring';

        fetch(endpoint, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                this.isMonitoring = !this.isMonitoring;
                this.updateMonitoringUI();
            })
            .catch(error => {
                console.error('Error toggling monitoring:', error);
            });
    }

    updateMonitoringUI() {
        const button = document.getElementById('toggleMonitoring');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');

        if (this.isMonitoring) {
            button.textContent = 'Stop Monitoring';
            statusDot.classList.add('active');
            statusText.textContent = 'Monitoring Active';
        } else {
            button.textContent = 'Start Monitoring';
            statusDot.classList.remove('active');
            statusText.textContent = 'Monitoring Stopped';
        }
    }

    addDetection(detection) {
        this.detections.unshift(detection);
        this.renderDetections();
        this.showAlert(detection);
    }

    renderDetections() {
        const container = document.getElementById('detectionList');

        if (this.detections.length === 0) {
            container.innerHTML = '<div class="no-detections"><p>🔍 No detections yet. Start monitoring to see live phishing domains.</p></div>';
            return;
        }

        const html = this.detections.slice(0, 50).map(detection => {
            const riskClass = this.getRiskClass(detection.risk_score);
            const timeAgo = this.timeAgo(new Date(detection.timestamp));

            return `
                <div class="detection-item" onclick="showDetectionDetails('${detection.id}')">
                    <div class="detection-header">
                        <span class="domain-name">${detection.domain}</span>
                        <span class="risk-badge risk-${riskClass}">${detection.risk_score}</span>
                    </div>
                    <div class="detection-meta">
                        <span>📡 ${detection.source}</span>
                        <span>🎯 ${detection.similarity || 'Unknown'}</span>
                        <span>⏱️ ${timeAgo}</span>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = html;
        document.getElementById('detectionCount').textContent = this.detections.length;
    }

    getRiskClass(score) {
        if (score >= 90) return 'critical';
        if (score >= 70) return 'high';
        if (score >= 50) return 'medium';
        return 'low';
    }

    timeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);

        if (seconds < 60) return seconds + 's ago';
        if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
        if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
        return Math.floor(seconds / 86400) + 'd ago';
    }

    showAlert(detection) {
        if (detection.risk_score >= 90) {
            const alert = document.createElement('div');
            alert.className = 'alert alert-critical';
            alert.innerHTML = `
                <strong>🚨 Critical Threat Detected!</strong><br>
                <strong>${detection.domain}</strong><br>
                Risk Score: ${detection.risk_score}
            `;

            document.getElementById('alertSystem').appendChild(alert);

            setTimeout(() => {
                alert.remove();
            }, 5000);
        }
    }

    updateStats(stats) {
        document.getElementById('totalDetections').textContent = stats.total_detections || 0;
        document.getElementById('criticalAlerts').textContent = stats.critical_alerts || 0;
        document.getElementById('avgRiskScore').textContent = stats.avg_risk_score || '0.0';
    }

    exportData() {
        window.open('/api/export_detections', '_blank');
    }

    refreshData() {
        fetch('/api/detections')
            .then(response => response.json())
            .then(data => {
                this.detections = data.detections || [];
                this.renderDetections();
            })
            .catch(error => {
                console.error('Error refreshing data:', error);
            });
    }

    applyFilters() {
        // Implement filtering logic
        const riskFilter = document.getElementById('riskFilter').value;
        const sourceFilter = document.getElementById('sourceFilter').value;

        // This would normally filter the displayed detections
        console.log('Applying filters:', { riskFilter, sourceFilter });
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new PhishGuardDashboard();
});

// Global function for detection details
function showDetectionDetails(detectionId) {
    console.log('Show details for detection:', detectionId);
    // Implement modal display logic
}
