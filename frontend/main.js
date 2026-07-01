// Haremos las llamadas HTTP directas para evitar depender del empaquetado del SDK para este vanilla demo
// aunque podríamos instalarlo localmente en Vite.

const BASE_URL = ""; // Mismo host, se servirá desde Rust

let currentDid = "";

// Elementos del DOM
const loginScreen = document.getElementById("login-screen");
const dashboardScreen = document.getElementById("dashboard-screen");
const didInput = document.getElementById("did-input");
const btnLogin = document.getElementById("btn-login");
const currentUserSpan = document.getElementById("current-user");
const anomalyScoreDiv = document.getElementById("anomaly-score");
const anomalyDetailsDiv = document.getElementById("anomaly-details");
const accessResultDiv = document.getElementById("access-result");

btnLogin.addEventListener("click", () => {
  currentDid = didInput.value;
  if (!currentDid) return;
  currentUserSpan.textContent = currentDid;
  loginScreen.classList.remove("active");
  dashboardScreen.classList.active = "active";
  dashboardScreen.style.display = "block"; // override vanilla css
  
  // Iniciar polling del anomaly score
  fetchAnomalyScore();
  setInterval(fetchAnomalyScore, 2000);
});

async function fetchAnomalyScore() {
  try {
    const res = await fetch(`${BASE_URL}/v1/anomaly_score?user_did=${encodeURIComponent(currentDid)}&metric=avg_latency`);
    if (!res.ok) return;
    const data = await res.json();
    
    // Mostrar
    const scoreVal = parseFloat(data.anomaly_score).toFixed(2);
    anomalyScoreDiv.textContent = scoreVal;
    
    if (data.is_anomaly) {
      anomalyScoreDiv.className = "score high";
      anomalyDetailsDiv.textContent = `¡Anomalía detectada! Z-Score: ${data.z_score.toFixed(2)}`;
    } else {
      anomalyScoreDiv.className = "score low";
      anomalyDetailsDiv.textContent = `Comportamiento normal. Media base: ${data.event_count} eventos`;
    }
  } catch (err) {
    console.error("Error fetching score", err);
  }
}

async function requestAccess(resourceId, classification) {
  accessResultDiv.innerHTML = "Evaluando...";
  const payload = {
    subject: {
      did: currentDid,
      clearance_level: classification === "public" ? 1 : 5,
      roles: ["user"]
    },
    resource: {
      id: resourceId,
      classification: classification,
      owner: "system"
    },
    context: {
      device_id: "dev-123",
      ip_address: "192.168.1.100",
      geolocation: "US",
      time_of_day: "14:00:00"
    },
    session: {
      session_id: "demo-sess",
      device_trust_score: 90,
      mfa_verified: false,
      biometric_verified: false
    }
  };

  try {
    const res = await fetch(`${BASE_URL}/v1/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    
    const decision = await res.json();
    const isAllow = decision.allow;
    accessResultDiv.innerHTML = `
      <h3 style="color: ${isAllow ? 'green' : 'red'}">${isAllow ? '✅ ALLOW' : '❌ DENY'}</h3>
      <p>Requiere 2FA: ${decision.requires_2fa}</p>
      <p>Bloquear: ${decision.block}</p>
    `;
  } catch (err) {
    accessResultDiv.innerHTML = `<p style="color:red">Error en red.</p>`;
  }
}

document.getElementById("btn-resource-a").addEventListener("click", () => {
  requestAccess("res:public-docs", "public");
});

document.getElementById("btn-resource-admin").addEventListener("click", () => {
  requestAccess("res:admin-panel", "top_secret");
});
