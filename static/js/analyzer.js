// ==========================================================================
// SentinelMail Analyzer - Live Inspection & Scenario Templates
// ==========================================================================

const SAMPLE_SCENARIOS = {
    phish_paypal: {
        sender: "security-alert@paypal-account-verify.com",
        subject: "Urgent: Verify Your Account - Access Suspended",
        body: `Dear customer,\n\nYour account has been suspended due to suspicious unauthorized login attempts.\n\nClick the link below immediately to verify your account:\nhttp://192.168.1.100/verify-login\n\nEnter your username and password to restore full access. Failure to confirm your identity within 24 hours will lead to permanent account deactivation.\n\nThank you.\nPayPal Security Center`
    },
    phish_o365: {
        sender: "it-support@corp-sso-gateway.info",
        subject: "ACTION REQUIRED: Your Office 365 password expires in 2 hours",
        body: `Attention Employee,\n\nYour Office 365 network login password will expire today. To avoid disruption to your corporate email, VPN, and SSO access, click the link below to keep your current credentials:\n\nhttp://bit.ly/sso-update-token\n\nDo not share your password with anyone.\n\nCorporate IT Helpdesk`
    },
    phish_customs: {
        sender: "delivery-tracking@track-package-update.com",
        subject: "Delivery Alert: Package #918290 held at customs",
        body: `Dear recipient,\n\nYour package cannot be delivered due to an incorrect shipping address and unpaid customs fee of $2.99.\n\nUpdate your delivery address and pay the fee here:\nhttp://203.0.113.88/postal/verify\n\nYour parcel will be returned to sender if unclaimed within 48 hours.\n\nCustomer Delivery Center`
    },
    phish_invoice: {
        sender: "billing-notice@invoice-dispute-portal.net",
        subject: "Invoice #581920 Overdue - Immediate Payment Required",
        body: `Hello,\n\nPlease find attached invoice #581920 for your recent purchase totaling $850.00. If you did not authorize this transaction, dispute the charges immediately at:\n\nhttp://invoice-dispute-portal.net/cancel-payment?id=581920\n\nEnter your banking credentials to cancel the pending wire transfer.\n\nBilling Department`
    },
    safe_sprint: {
        sender: "alex.rivera@acme-corp.com",
        subject: "Sprint planning notes & roadmap update for Q3",
        body: `Hi team,\n\nThanks everyone for joining today's roadmap review. I have attached the meeting notes and updated Jira backlog links.\n\nPlease review the tickets assigned to your sprint milestone before Wednesday's standup:\nhttps://jira.atlassian.com/browse/PROJ-412\n\nLet me know if there are any blockers or questions.\n\nBest regards,\nAlex Rivera`
    },
    safe_receipt: {
        sender: "billing@saasplatform.com",
        subject: "Monthly Subscription Invoice and Payment Receipt",
        body: `Dear valued subscriber,\n\nYour monthly subscription payment of $49.00 has been processed successfully. Your updated receipt is ready. View your billing history in your authenticated dashboard at:\n\nhttps://saasplatform.com/account/billing\n\nThank you for choosing our platform.\n\nCustomer Success Team`
    },
    safe_zoom: {
        sender: "no-reply@zoom.us",
        subject: "Invitation: Architecture Review - Phishing Defense Pipeline",
        body: `When: Thursday, 2:00 PM - 3:00 PM EST\nWhere: Google Meet Conference Room 4B\n\nAgenda:\n1. Model evaluation metrics review\n2. Infrastructure scaling for incoming telemetry\n3. Q&A and next sprint backlog grooming\n\nVideo link: https://zoom.us/j/912839129\n\nLooking forward to speaking then,\nSarah Jenkins`
    }
};

document.addEventListener('DOMContentLoaded', () => {
    const bodyInput = document.getElementById('body');
    const charCount = document.getElementById('charCount');
    const sampleSelect = document.getElementById('sampleEmailSelect');
    const form = document.getElementById('emailAnalyzeForm');
    const btnClear = document.getElementById('btnClear');

    // Live character counter
    if (bodyInput && charCount) {
        const updateCount = () => {
            charCount.textContent = `${bodyInput.value.length} chars`;
        };
        bodyInput.addEventListener('input', updateCount);
        updateCount();
    }

    // Sample selection dropdown
    if (sampleSelect) {
        sampleSelect.addEventListener('change', (e) => {
            const key = e.target.value;
            if (key && SAMPLE_SCENARIOS[key]) {
                loadSample(key);
            }
        });
    }

    // Clear form button
    if (btnClear) {
        btnClear.addEventListener('click', () => {
            document.getElementById('sender').value = '';
            document.getElementById('subject').value = '';
            if (bodyInput) {
                bodyInput.value = '';
                charCount.textContent = '0 chars';
            }
            if (sampleSelect) sampleSelect.value = '';
        });
    }

    // AJAX analysis form submission
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await performAjaxAnalysis();
        });
    }
});

function loadSample(key) {
    const data = SAMPLE_SCENARIOS[key];
    if (!data) return;

    document.getElementById('sender').value = data.sender;
    document.getElementById('subject').value = data.subject;
    const bodyInput = document.getElementById('body');
    bodyInput.value = data.body;
    
    const charCount = document.getElementById('charCount');
    if (charCount) charCount.textContent = `${data.body.length} chars`;

    const sampleSelect = document.getElementById('sampleEmailSelect');
    if (sampleSelect) sampleSelect.value = key;
}

async function performAjaxAnalysis() {
    const btnAnalyze = document.getElementById('btnAnalyze');
    const resultsContainer = document.getElementById('resultsContainer');
    const sender = document.getElementById('sender').value.trim();
    const subject = document.getElementById('subject').value.trim();
    const body = document.getElementById('body').value.trim();

    if (!body && !subject) {
        alert('Please provide email body text or a subject line to analyze.');
        return;
    }

    // Loading State
    const originalBtnHtml = btnAnalyze.innerHTML;
    btnAnalyze.disabled = true;
    btnAnalyze.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING PAYLOAD...';

    resultsContainer.innerHTML = `
        <div class="soc-card" style="text-align: center; padding: 60px 30px;">
            <div style="width: 72px; height: 72px; border-radius: 50%; background-color: var(--bg-surface-elevated); margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; color: var(--accent-cyan);">
                <i class="fa-solid fa-microchip fa-spin"></i>
            </div>
            <h3 style="font-size: 1.15rem; color: #fff; font-weight: 700;">Running Deep Threat Analysis</h3>
            <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 10px;">
                Extracting TF-IDF n-grams, evaluating URL security signals, and calculating composite risk scores...
            </p>
        </div>
    `;

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sender, subject, body })
        });

        const resData = await response.json();
        if (!response.ok || resData.status !== 'success') {
            throw new Error(resData.message || resData.error || 'Server analysis error');
        }

        renderResultCard(resData.data);
    } catch (err) {
        resultsContainer.innerHTML = `
            <div class="soc-card" style="padding: 24px;">
                <div class="alert-box alert-danger">
                    <span><i class="fa-solid fa-circle-exclamation" style="margin-right: 8px;"></i>${err.message}</span>
                </div>
            </div>
        `;
    } finally {
        btnAnalyze.disabled = false;
        btnAnalyze.innerHTML = originalBtnHtml;
    }
}

function renderResultCard(result) {
    const isPhishing = result.prediction === 'PHISHING';
    const bannerClass = isPhishing ? 'phishing' : 'safe';
    const iconClass = isPhishing ? 'fa-triangle-exclamation' : 'fa-shield-check';
    const titleText = isPhishing ? '⚠ PHISHING DETECTED' : '✓ SAFE EMAIL';
    const riskClass = result.risk_level.toLowerCase();

    // Risk level text color
    let riskColor = '#34d399';
    if (result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH') riskColor = '#f87171';
    else if (result.risk_level === 'MEDIUM') riskColor = '#fbbf24';

    // Explanations HTML
    const explanationsHtml = result.explanation.map(exp => `
        <li class="explanation-item ${isPhishing ? 'flagged' : 'safe-point'}">
            <i class="fa-solid ${isPhishing ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
            <span>${exp}</span>
        </li>
    `).join('');

    // Keywords HTML
    let keywordsHtml = '';
    if (result.detected_keywords && result.detected_keywords.length > 0) {
        keywordsHtml = result.detected_keywords.map(kw => `
            <span class="chip chip-danger" style="font-size: 0.8rem; padding: 4px 10px;">
                <i class="fa-solid fa-check" style="color: var(--danger);"></i>
                <strong>${kw.keyword}</strong>
                <span style="color: var(--text-dim); font-size: 0.7rem;">(${kw.count})</span>
            </span>
        `).join('');
    } else {
        keywordsHtml = `
            <div style="font-size: 0.82rem; color: var(--text-dim); background-color: var(--bg-surface-elevated); padding: 10px; border-radius: var(--radius-sm);">
                <i class="fa-solid fa-shield-check" style="color: var(--success); margin-right: 6px;"></i>
                No high-risk suspicious trigger keywords identified.
            </div>
        `;
    }

    // URL Details HTML
    let urlDetailsHtml = '';
    if (result.url_analysis.details && result.url_analysis.details.length > 0) {
        urlDetailsHtml = result.url_analysis.details.map(u => `
            <div style="background-color: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 0.8rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span class="mono" style="color: #38bdf8; word-break: break-all;">${u.url}</span>
                    <span class="badge ${u.is_suspicious ? 'badge-phishing' : 'badge-safe'}" style="font-size: 0.65rem;">
                        ${u.is_suspicious ? 'Flagged' : 'Clean'}
                    </span>
                </div>
                <div style="display: flex; gap: 12px; font-size: 0.72rem; color: var(--text-muted); flex-wrap: wrap;">
                    <span>Protocol: <strong>${u.is_https ? 'HTTPS' : 'HTTP'}</strong></span>
                    ${u.is_ip ? '<span style="color: #f87171;"><strong>• Raw IP Host</strong></span>' : ''}
                    ${u.is_shortener ? '<span style="color: #fbbf24;"><strong>• URL Shortener</strong></span>' : ''}
                    ${u.is_long_url ? `<span>• Length: ${u.url_length} chars</span>` : ''}
                    ${u.has_at_symbol ? '<span style="color: #f87171;">• Contains \'@\' Redirect</span>' : ''}
                </div>
            </div>
        `).join('');
    }

    const html = `
        <div class="soc-card" style="margin-bottom: 24px; animation: fadeIn 0.4s ease;">
            <!-- Large Result Banner -->
            <div class="result-banner ${bannerClass}">
                <div class="result-header">
                    <div class="result-icon-circle">
                        <i class="fa-solid ${iconClass}"></i>
                    </div>
                    <div>
                        <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1.5px; opacity: 0.8; font-weight: 700;">
                            Automated SOC Assessment
                        </div>
                        <div class="result-title-text">${titleText}</div>
                    </div>
                </div>

                <div class="result-metrics-row">
                    <div class="metric-pill">
                        <span class="metric-pill-label">ML Confidence</span>
                        <span class="metric-pill-val" style="color: #fff;">${result.confidence}%</span>
                    </div>
                    <div class="metric-pill">
                        <span class="metric-pill-label">Risk Level</span>
                        <span class="metric-pill-val" style="color: ${riskColor};">${result.risk_level}</span>
                    </div>
                </div>
            </div>

            <div class="card-body">
                <!-- Risk Score Bar -->
                <div style="margin-bottom: 24px; background-color: var(--bg-surface-elevated); padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-size: 0.8rem; font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: 0.5px;">
                            <i class="fa-solid fa-gauge-high" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                            Calculated Threat Risk Score
                        </span>
                        <span style="font-size: 0.95rem; font-weight: 800; color: #fff;">
                            ${result.risk_score} <span style="font-size: 0.75rem; color: var(--text-dim);">/ 100</span>
                        </span>
                    </div>
                    
                    <div class="risk-meter">
                        <div class="risk-fill ${riskClass}" style="width: ${result.risk_score}%;"></div>
                    </div>
                    
                    <div style="display: flex; justify-content: space-between; font-size: 0.7rem; color: var(--text-dim); margin-top: 4px;">
                        <span>0-30: LOW</span>
                        <span>31-60: MEDIUM</span>
                        <span>61-80: HIGH</span>
                        <span>81-100: CRITICAL</span>
                    </div>
                    <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 8px; border-top: 1px dashed var(--border-color); padding-top: 6px;">
                        <i class="fa-solid fa-circle-info" style="color: var(--accent-cyan); margin-right: 4px;"></i>
                        <em>ML Confidence reflects text vector alignment, while Risk Score integrates structural & static URL heuristics.</em>
                    </div>
                </div>

                <!-- Explanation System -->
                <div style="margin-bottom: 24px;">
                    <div style="font-size: 0.88rem; font-weight: 700; color: #fff; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between;">
                        <span>
                            <i class="fa-solid fa-clipboard-question" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                            ${isPhishing ? 'Why this email was flagged:' : 'Why this email appears safe:'}
                        </span>
                        <span style="font-size: 0.72rem; font-weight: normal; color: var(--text-dim);">Static SOC Heuristics</span>
                    </div>
                    <ul class="explanation-list">
                        ${explanationsHtml}
                    </ul>
                    <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 6px;">
                        * Note: Indicators represent static risk factors, not definitive proof of intent.
                    </div>
                </div>

                <!-- Suspicious Keywords -->
                <div style="margin-bottom: 24px;">
                    <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 10px;">
                        <i class="fa-solid fa-key" style="color: var(--warning); margin-right: 6px;"></i>
                        Suspicious Keywords Detected
                    </div>
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                        ${keywordsHtml}
                    </div>
                </div>

                <!-- URL Analysis -->
                <div style="margin-bottom: 24px;">
                    <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                        <span>
                            <i class="fa-solid fa-link" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                            Static URL Analysis
                        </span>
                        <span class="chip" style="font-size: 0.7rem;">No Outbound Requests</span>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-bottom: 14px;">
                        <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: var(--radius-sm); text-align: center;">
                            <div style="font-size: 0.68rem; color: var(--text-dim); text-transform: uppercase;">URLs Found</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #fff;">${result.url_analysis.urls_found}</div>
                        </div>
                        <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: var(--radius-sm); text-align: center;">
                            <div style="font-size: 0.68rem; color: var(--text-dim); text-transform: uppercase;">Suspicious</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: ${result.url_analysis.suspicious_urls > 0 ? '#f87171' : '#fff'};">
                                ${result.url_analysis.suspicious_urls}
                            </div>
                        </div>
                        <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: var(--radius-sm); text-align: center;">
                            <div style="font-size: 0.68rem; color: var(--text-dim); text-transform: uppercase;">HTTPS Secure</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #34d399;">${result.url_analysis.https_urls}</div>
                        </div>
                        <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: var(--radius-sm); text-align: center;">
                            <div style="font-size: 0.68rem; color: var(--text-dim); text-transform: uppercase;">HTTP Plain</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: ${result.url_analysis.http_urls > 0 ? '#fbbf24' : '#fff'};">
                                ${result.url_analysis.http_urls}
                            </div>
                        </div>
                        <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: var(--radius-sm); text-align: center;">
                            <div style="font-size: 0.68rem; color: var(--text-dim); text-transform: uppercase;">IP Hosts</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: ${result.url_analysis.ip_based_urls > 0 ? '#f87171' : '#fff'};">
                                ${result.url_analysis.ip_based_urls}
                            </div>
                        </div>
                    </div>

                    ${urlDetailsHtml ? `<div style="display: flex; flex-direction: column; gap: 8px;">${urlDetailsHtml}</div>` : ''}
                </div>

                <!-- Structural & Sender Analysis -->
                <div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 10px;">
                        <i class="fa-solid fa-code-compare" style="color: var(--accent-cyan); margin-right: 6px;"></i>
                        Email Structural & Header Telemetry
                    </div>
                    <div style="background-color: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 14px;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.8rem;">
                            <div>
                                <span style="color: var(--text-dim);">Sender Domain:</span>
                                <strong class="mono" style="color: #fff; margin-left: 6px;">${result.structural_analysis.sender_domain || 'None'}</strong>
                            </div>
                            <div>
                                <span style="color: var(--text-dim);">Domain Status:</span>
                                <span style="margin-left: 6px; color: ${result.structural_analysis.domain_suspicious ? '#f87171' : '#34d399'}; font-weight: 600;">
                                    ${result.structural_analysis.domain_based_indicators}
                                </span>
                            </div>
                            <div>
                                <span style="color: var(--text-dim);">Subject Urgency:</span>
                                <strong style="margin-left: 6px; color: ${result.structural_analysis.subject_urgency ? '#f87171' : '#94a3b8'};">
                                    ${result.structural_analysis.subject_urgency ? 'DETECTED' : 'Normal'}
                                </strong>
                            </div>
                            <div>
                                <span style="color: var(--text-dim);">Word / Sentence:</span>
                                <strong style="color: #fff; margin-left: 6px;">${result.structural_analysis.word_count} words / ${result.structural_analysis.sentence_count} sent.</strong>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.getElementById('resultsContainer').innerHTML = html;
}
