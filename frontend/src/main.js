import './style.css';

const BASE_URL = '';

let currentDid = '';
let anomalyInterval = null;

// ─── Elementos del DOM ────────────────────────────────────────────────────────

const loginScreen    = document.getElementById('login-screen');
const dashboardScreen = document.getElementById('dashboard-screen');
const didInput       = document.getElementById('did-input');
const btnLogin       = document.getElementById('btn-login');
const currentUserEl  = document.getElementById('current-user');
const anomalyScoreEl = document.getElementById('anomaly-score');
const anomalyDetailsEl = document.getElementById('anomaly-details');
const accessResultEl = document.getElementById('access-result');
const revokeInputEl  = document.getElementById('revoke-input');
const btnRevoke      = document.getElementById('btn-revoke');
const revokeResultEl = document.getElementById('revoke-result');
const anomalyFill    = document.getElementById('anomaly-fill');
const metricMetaEl   = document.getElementById('metric-meta');

// ─── Login ────────────────────────────────────────────────────────────────────

btnLogin.addEventListener('click', handleLogin);
didInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleLogin(); });

function handleLogin() {
  const val = didInput.value.trim();
  if (!val) {
    didInput.classList.add('shake');
    setTimeout(() => didInput.classList.remove('shake'), 500);
    return;
  }
  currentDid = val;
  currentUserEl.textContent = currentDid;
  loginScreen.classList.add('fade-out');
  setTimeout(() => {
    loginScreen.style.display = 'none';
    loginScreen.classList.remove('fade-out');
    dashboardScreen.style.display = 'flex';
    dashboardScreen.classList.add('fade-in');
    setTimeout(() => dashboardScreen.classList.remove('fade-in'), 500);
  }, 350);

  fetchAnomalyScore();
  if (anomalyInterval) clearInterval(anomalyInterval);
  anomalyInterval = setInterval(fetchAnomalyScore, 3000);
}

// ─── Anomaly Score ────────────────────────────────────────────────────────────

async function fetchAnomalyScore() {
  try {
    const res = await fetch(
      `${BASE_URL}/v1/anomaly_score?user=${encodeURIComponent(currentDid)}&metric=avg_latency`
    );
    if (!res.ok) { setScoreError('API Error ' + res.status); return; }
    const data = await res.json();

    const score = parseFloat(data.anomaly_score ?? 0);
    const pct   = Math.round(score * 100);

    // Barra circular
    const circumference = 2 * Math.PI * 54; // r=54
    const offset = circumference - (pct / 100) * circumference;
    anomalyFill.style.strokeDashoffset = offset;

    // Color dinámico
    let color = '#22c55e'; // verde
    if (score > 0.5)  color = '#f59e0b'; // naranja
    if (score > 0.8)  color = '#ef4444'; // rojo
    anomalyFill.style.stroke = color;

    anomalyScoreEl.textContent   = pct + '%';
    anomalyScoreEl.style.color   = color;

    const eventCount = data.event_count ?? '—';
    const baselineMean = data.baseline_mean != null ? data.baseline_mean.toFixed(1) : '—';
    const stdDev = data.std_dev != null ? data.std_dev.toFixed(1) : '—';

    if (data.is_anomaly || data.is_outlier) {
      anomalyDetailsEl.textContent = '⚠ Anomalía detectada — Comportamiento fuera de la norma';
      anomalyDetailsEl.className   = 'metric-badge badge-danger';
    } else {
      anomalyDetailsEl.textContent = '✓ Comportamiento dentro del patrón normal';
      anomalyDetailsEl.className   = 'metric-badge badge-ok';
    }

    metricMetaEl.innerHTML = `
      <span>Eventos analizados: <strong>${eventCount}</strong></span>
      <span>Media base: <strong>${baselineMean} ms</strong></span>
      <span>Desv. estándar: <strong>${stdDev} ms</strong></span>
    `;
  } catch (err) {
    setScoreError('Sin conexión con el servidor');
  }
}

function setScoreError(msg) {
  anomalyScoreEl.textContent = '—';
  anomalyDetailsEl.textContent = msg;
  anomalyDetailsEl.className = 'metric-badge badge-warn';
}

// ─── Access Control ───────────────────────────────────────────────────────────

document.getElementById('btn-resource-public').addEventListener('click', () => {
  requestAccess('res:public-docs', 'public');
});
document.getElementById('btn-resource-restricted').addEventListener('click', () => {
  requestAccess('res:internal-reports', 'restricted');
});
document.getElementById('btn-resource-secret').addEventListener('click', () => {
  requestAccess('res:admin-panel', 'top_secret');
});

async function requestAccess(resourceId, classification) {
  accessResultEl.innerHTML = `<div class="spinner"></div><span>Evaluando política Zero Trust...</span>`;
  accessResultEl.className = 'result-card loading';

  const clearance = { public: 1, restricted: 3, top_secret: 5 }[classification] ?? 1;

  const payload = {
    subject: {
      did: currentDid,
      clearance_level: clearance,
      roles: ['user'],
    },
    resource: {
      id: resourceId,
      classification,
      owner: 'system',
    },
    context: {
      device_id: 'dev-axiom-demo',
      ip_address: '10.0.0.' + Math.floor(Math.random() * 254 + 1),
      geolocation: 'ES',
      time_of_day: new Date().toTimeString().slice(0, 8),
      distance_km: Math.floor(Math.random() * 50),
    },
    device: {
      trust_score: 0.85,
    },
    session: {
      session_id: 'sess-' + Date.now(),
      device_trust_score: 85,
      mfa_verified: false,
      biometric_verified: false,
    },
  };

  try {
    const res = await fetch(`${BASE_URL}/v1/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const decision = await res.json();
    const allow    = decision.allow;
    const needs2fa = decision.requires_2fa;
    const blocked  = decision.block;

    let statusClass, statusIcon, statusText;
    if (blocked || !allow) {
      statusClass = 'deny';
      statusIcon  = '✗';
      statusText  = 'ACCESO DENEGADO';
    } else if (needs2fa) {
      statusClass = 'challenge';
      statusIcon  = '⚡';
      statusText  = 'REQUIERE VERIFICACIÓN';
    } else {
      statusClass = 'allow';
      statusIcon  = '✓';
      statusText  = 'ACCESO PERMITIDO';
    }

    accessResultEl.className = `result-card ${statusClass}`;
    accessResultEl.innerHTML = `
      <div class="result-header">
        <span class="result-icon">${statusIcon}</span>
        <span class="result-status">${statusText}</span>
      </div>
      <div class="result-details">
        <div class="detail-row">
          <span class="detail-label">Recurso</span>
          <span class="detail-value">${resourceId}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Clasificación</span>
          <span class="detail-value classification-${classification}">${classification.replace('_', ' ').toUpperCase()}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">2FA requerido</span>
          <span class="detail-value">${needs2fa ? 'Sí' : 'No'}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Bloqueo activo</span>
          <span class="detail-value">${blocked ? 'Sí' : 'No'}</span>
        </div>
      </div>
    `;
  } catch (err) {
    accessResultEl.className = 'result-card error';
    accessResultEl.innerHTML = `<div class="result-header"><span class="result-icon">!</span><span class="result-status">ERROR DE RED</span></div>`;
  }
}

// ─── Revocación P2P ───────────────────────────────────────────────────────────

btnRevoke.addEventListener('click', async () => {
  const credId = revokeInputEl.value.trim();
  if (!credId) {
    revokeInputEl.classList.add('shake');
    setTimeout(() => revokeInputEl.classList.remove('shake'), 500);
    return;
  }

  btnRevoke.disabled = true;
  btnRevoke.textContent = 'Propagando...';
  revokeResultEl.className = 'revoke-badge badge-loading';
  revokeResultEl.textContent = 'Enviando a la red P2P Gossipsub...';

  try {
    const adminToken = 'secret-admin-token';
    const res = await fetch(`${BASE_URL}/v1/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ credential_id: credId }),
    });

    if (res.ok) {
      revokeResultEl.className = 'revoke-badge badge-ok';
      revokeResultEl.textContent = `✓ Revocación de "${credId}" inyectada en la red CRDT`;
    } else {
      const text = await res.text();
      revokeResultEl.className = 'revoke-badge badge-danger';
      revokeResultEl.textContent = `✗ Error: ${text}`;
    }
  } catch (err) {
    revokeResultEl.className = 'revoke-badge badge-danger';
    revokeResultEl.textContent = `✗ Sin conexión con el servidor`;
  } finally {
    btnRevoke.disabled = false;
    btnRevoke.textContent = 'Revocar Credencial';
  }
});
