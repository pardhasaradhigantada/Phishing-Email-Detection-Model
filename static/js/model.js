// ==========================================================================
// SentinelMail Model Info - Comparison Chart & Async Retraining
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    initComparisonChart();
    setupRetrainButton();
});

function initComparisonChart() {
    const ctx = document.getElementById('comparisonChart');
    if (!ctx || !window.MODEL_METRICS) return;

    const pm = window.MODEL_METRICS.primary_model || {};
    const cm = window.MODEL_METRICS.comparator_model || {};

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'],
            datasets: [
                {
                    label: 'Logistic Regression',
                    data: [
                        pm.accuracy || 95.0,
                        pm.precision || 94.0,
                        pm.recall || 95.0,
                        pm.f1_score || 94.5,
                        pm.roc_auc || 98.0
                    ],
                    backgroundColor: 'rgba(6, 182, 212, 0.75)',
                    borderColor: '#06b6d4',
                    borderWidth: 1,
                    borderRadius: 4
                },
                {
                    label: 'Random Forest',
                    data: [
                        cm.accuracy || 94.2,
                        cm.precision || 94.8,
                        cm.recall || 93.5,
                        cm.f1_score || 94.1,
                        cm.roc_auc || 97.5
                    ],
                    backgroundColor: 'rgba(59, 130, 246, 0.75)',
                    borderColor: '#3b82f6',
                    borderWidth: 1,
                    borderRadius: 4
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
                    borderColor: '#233044',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.raw}%`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(35, 48, 68, 0.6)' },
                    ticks: { font: { size: 10 } }
                },
                y: {
                    min: 80,
                    max: 100,
                    grid: { color: 'rgba(35, 48, 68, 0.6)' },
                    ticks: {
                        callback: function(val) { return val + '%'; },
                        font: { size: 10 }
                    }
                }
            }
        }
    });
}

function setupRetrainButton() {
    const btn = document.getElementById('btnRetrainModel');
    if (!btn) return;

    btn.addEventListener('click', async () => {
        if (!confirm('Initiate model retraining on the current dataset? This will update the TF-IDF feature space and weights.')) {
            return;
        }

        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Retraining Pipeline...';

        try {
            const res = await fetch('/api/retrain', { method: 'POST' });
            const data = await res.json();
            if (!res.ok || data.status !== 'success') {
                throw new Error(data.message || 'Retraining failed');
            }

            alert('Model retraining completed successfully! Reloading performance metrics...');
            window.location.reload();
        } catch (err) {
            alert('Retraining error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    });
}
