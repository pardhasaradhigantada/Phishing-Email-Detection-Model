// ==========================================================================
// SentinelMail Dashboard - Chart.js & Interactive Telemetry
// ==========================================================================

let trendChartInstance = null;
let ratioChartInstance = null;
let keywordsChartInstance = null;
let urlIndicatorsChartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
    initDashboardCharts();
    setupInspectModal();
});

async function initDashboardCharts() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to fetch dashboard statistics');
        const data = await response.json();

        renderTrendChart(data.timeline);
        renderRatioChart(data.ratio);
        renderKeywordsChart(data.top_keywords);
        renderUrlIndicatorsChart(data.url_indicators);
    } catch (err) {
        console.error('Error initializing dashboard charts:', err);
    }
}

// 1. Phishing Detection Trend Chart (Past 7 Days Area/Line)
function renderTrendChart(timeline) {
    const ctx = document.getElementById('trendChart');
    if (!ctx) return;

    if (trendChartInstance) trendChartInstance.destroy();

    trendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timeline.labels,
            datasets: [
                {
                    label: 'Phishing Detections',
                    data: timeline.phishing,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointBackgroundColor: '#ef4444',
                    pointRadius: 4
                },
                {
                    label: 'Safe Communications',
                    data: timeline.safe,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.08)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointBackgroundColor: '#10b981',
                    pointRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: { boxWidth: 12, font: { size: 11 } }
                },
                tooltip: {
                    backgroundColor: '#111827',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: '#233044',
                    borderWidth: 1,
                    padding: 10
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(35, 48, 68, 0.6)' },
                    ticks: { font: { size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(35, 48, 68, 0.6)' },
                    ticks: { precision: 0, font: { size: 11 } }
                }
            }
        }
    });
}

// 2. Safe vs Phishing Ratio (Doughnut Chart)
function renderRatioChart(ratio) {
    const ctx = document.getElementById('ratioChart');
    if (!ctx) return;

    if (ratioChartInstance) ratioChartInstance.destroy();

    ratioChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ratio.labels,
            datasets: [{
                data: ratio.data,
                backgroundColor: ['#ef4444', '#10b981'],
                borderColor: '#131c2e',
                borderWidth: 3,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { boxWidth: 12, padding: 16, font: { size: 11 } }
                },
                tooltip: {
                    backgroundColor: '#111827',
                    borderColor: '#233044',
                    borderWidth: 1
                }
            }
        }
    });
}

// 3. Top Suspicious Keywords Detected (Horizontal Bar)
function renderKeywordsChart(keywords) {
    const ctx = document.getElementById('keywordsChart');
    if (!ctx) return;

    if (keywordsChartInstance) keywordsChartInstance.destroy();

    keywordsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: keywords.labels,
            datasets: [{
                label: 'Occurrences',
                data: keywords.data,
                backgroundColor: 'rgba(6, 182, 212, 0.7)',
                borderColor: '#06b6d4',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#111827',
                    borderColor: '#233044',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(35, 48, 68, 0.6)' },
                    ticks: { precision: 0, font: { size: 10 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 11, family: "'JetBrains Mono', monospace" } }
                }
            }
        }
    });
}

// 4. Most Common URL Indicators
function renderUrlIndicatorsChart(urlIndicators) {
    const ctx = document.getElementById('urlIndicatorsChart');
    if (!ctx) return;

    if (urlIndicatorsChartInstance) urlIndicatorsChartInstance.destroy();

    urlIndicatorsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: urlIndicators.labels,
            datasets: [{
                label: 'Detections',
                data: urlIndicators.data,
                backgroundColor: 'rgba(245, 158, 11, 0.7)',
                borderColor: '#f59e0b',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#111827',
                    borderColor: '#233044',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(35, 48, 68, 0.6)' },
                    ticks: { precision: 0, font: { size: 10 } }
                }
            }
        }
    });
}

// Modal Inspector
function setupInspectModal() {
    document.querySelectorAll('.btn-inspect').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.getAttribute('data-id');
            await openInspectModal(id);
        });
    });
}

async function openInspectModal(id) {
    const modal = document.getElementById('inspectModal');
    const content = document.getElementById('modalContent');
    const title = document.getElementById('modalTitle');
    
    modal.classList.add('active');
    content.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--text-dim);">
            <i class="fa-solid fa-spinner fa-spin" style="font-size: 1.5rem;"></i>
            <p style="margin-top: 10px;">Loading telemetry details...</p>
        </div>
    `;

    try {
        const res = await fetch(`/api/history/${id}`);
        if (!res.ok) throw new Error('Record not found');
        const data = await res.json();

        title.textContent = `Telemetry Incident #${data.id}: ${data.prediction}`;

        const isPhishing = data.prediction === 'PHISHING';
        const badgeClass = isPhishing ? 'badge-phishing' : 'badge-safe';
        const riskClass = `badge-${data.risk_level.toLowerCase()}`;

        let keywordsHtml = '';
        if (data.detected_keywords && data.detected_keywords.length > 0) {
            keywordsHtml = data.detected_keywords.map(k => `
                <span class="chip chip-danger"><i class="fa-solid fa-check"></i> ${k.keyword} (${k.count})</span>
            `).join(' ');
        } else {
            keywordsHtml = '<span style="color: var(--text-dim); font-size: 0.8rem;">No suspicious keywords detected</span>';
        }

        let explanationHtml = '';
        if (data.explanation && data.explanation.length > 0) {
            explanationHtml = data.explanation.map(exp => `
                <div class="explanation-item ${isPhishing ? 'flagged' : 'safe-point'}">
                    <i class="fa-solid ${isPhishing ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
                    <span>${exp}</span>
                </div>
            `).join('');
        }

        content.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border-color);">
                <div>
                    <span class="badge ${badgeClass}" style="font-size: 0.85rem; padding: 6px 14px;">
                        <i class="fa-solid ${isPhishing ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
                        ${data.prediction}
                    </span>
                    <span class="badge ${riskClass}" style="margin-left: 8px;">
                        Risk: ${data.risk_level} (${data.risk_score}/100)
                    </span>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase;">ML Confidence</div>
                    <strong style="font-size: 1.2rem; color: #fff;">${data.confidence}%</strong>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
                <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: var(--radius-sm);">
                    <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Sender</div>
                    <div class="mono" style="font-size: 0.82rem; color: #fff; margin-top: 4px;">${data.sender || 'Unknown'}</div>
                </div>
                <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: var(--radius-sm);">
                    <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Subject</div>
                    <div style="font-size: 0.82rem; color: #fff; margin-top: 4px; font-weight: 500;">${data.subject || '(No Subject)'}</div>
                </div>
            </div>

            <div style="margin-bottom: 20px;">
                <div style="font-size: 0.8rem; font-weight: 600; color: #fff; margin-bottom: 8px;">
                    <i class="fa-solid fa-list-check" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                    SOC Reasoning & Indicators
                </div>
                <div class="explanation-list">
                    ${explanationHtml}
                </div>
            </div>

            <div style="margin-bottom: 20px;">
                <div style="font-size: 0.8rem; font-weight: 600; color: #fff; margin-bottom: 8px;">
                    <i class="fa-solid fa-key" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                    Detected Keywords
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                    ${keywordsHtml}
                </div>
            </div>

            <div>
                <div style="font-size: 0.8rem; font-weight: 600; color: #fff; margin-bottom: 8px;">
                    <i class="fa-solid fa-file-lines" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                    Body Snippet
                </div>
                <pre class="mono" style="background-color: var(--bg-base); border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-sm); font-size: 0.78rem; white-space: pre-wrap; color: #94a3b8; max-height: 140px; overflow-y: auto;">${data.body_snippet || ''}</pre>
            </div>
        `;
    } catch (err) {
        content.innerHTML = `<div class="alert-box alert-danger">Error retrieving telemetry: ${err.message}</div>`;
    }
}

function closeInspectModal() {
    const modal = document.getElementById('inspectModal');
    if (modal) modal.classList.remove('active');
}

window.addEventListener('click', (e) => {
    const modal = document.getElementById('inspectModal');
    if (e.target === modal) closeInspectModal();
});
