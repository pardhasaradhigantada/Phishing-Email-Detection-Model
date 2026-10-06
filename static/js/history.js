// ==========================================================================
// SentinelMail History Log - Inspection Modal & Forensics
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.btn-inspect-history').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.getAttribute('data-id');
            await openInspectModal(id);
        });
    });
});

async function openInspectModal(id) {
    const modal = document.getElementById('inspectModal');
    const content = document.getElementById('modalContent');
    const title = document.getElementById('modalTitle');
    
    modal.classList.add('active');
    content.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--text-dim);">
            <i class="fa-solid fa-spinner fa-spin" style="font-size: 1.5rem;"></i>
            <p style="margin-top: 10px;">Retrieving forensic telemetry record...</p>
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

        // Keywords
        let keywordsHtml = '';
        if (data.detected_keywords && data.detected_keywords.length > 0) {
            keywordsHtml = data.detected_keywords.map(k => `
                <span class="chip chip-danger"><i class="fa-solid fa-check"></i> ${k.keyword} (${k.count})</span>
            `).join(' ');
        } else {
            keywordsHtml = '<span style="color: var(--text-dim); font-size: 0.8rem;">No suspicious trigger keywords identified</span>';
        }

        // Explanations
        let explanationHtml = '';
        if (data.explanation && data.explanation.length > 0) {
            explanationHtml = data.explanation.map(exp => `
                <div class="explanation-item ${isPhishing ? 'flagged' : 'safe-point'}">
                    <i class="fa-solid ${isPhishing ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
                    <span>${exp}</span>
                </div>
            `).join('');
        }

        // URLs
        let urlHtml = '';
        if (data.url_analysis && data.url_analysis.urls_found > 0) {
            urlHtml = `
                <div style="margin-bottom: 20px;">
                    <div style="font-size: 0.8rem; font-weight: 600; color: #fff; margin-bottom: 8px;">
                        <i class="fa-solid fa-link" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                        URLs Found (${data.url_analysis.urls_found})
                    </div>
                    <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 8px;">
                        Suspicious: ${data.url_analysis.suspicious_urls} | HTTPS: ${data.url_analysis.https_urls} | HTTP: ${data.url_analysis.http_urls} | IP-based: ${data.url_analysis.ip_based_urls}
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 6px;">
                        ${(data.url_analysis.details || []).map(u => `
                            <div style="background-color: var(--bg-surface-elevated); padding: 8px 12px; border-radius: 4px; font-size: 0.75rem; display: flex; justify-content: space-between;">
                                <span class="mono" style="color: #38bdf8; word-break: break-all;">${u.url}</span>
                                <span class="badge ${u.is_suspicious ? 'badge-phishing' : 'badge-safe'}" style="font-size: 0.62rem;">${u.is_suspicious ? 'Suspicious' : 'Clean'}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
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
                    <div style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase;">Confidence</div>
                    <strong style="font-size: 1.25rem; color: #fff;">${data.confidence}%</strong>
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

            ${urlHtml}

            <div>
                <div style="font-size: 0.8rem; font-weight: 600; color: #fff; margin-bottom: 8px;">
                    <i class="fa-solid fa-file-lines" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                    Body Content Snippet
                </div>
                <pre class="mono" style="background-color: var(--bg-base); border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-sm); font-size: 0.78rem; white-space: pre-wrap; color: #94a3b8; max-height: 140px; overflow-y: auto;">${data.body_snippet || ''}</pre>
            </div>
        `;
    } catch (err) {
        content.innerHTML = `<div class="alert-box alert-danger">Failed to load record: ${err.message}</div>`;
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
