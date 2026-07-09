/**
 * axiom.js — Capa de API centralizada para AXIOM
 * Todas las llamadas fetch al backend pasan por aquí.
 */

const BASE_URL = '';

// ─── Anomaly Score ────────────────────────────────────────────────────────────

/**
 * Obtiene el anomaly score de un usuario para una métrica dada.
 * @param {string} did - DID del usuario (e.g. "did:axiom:test_42")
 * @param {string} [metric="avg_latency"] - Métrica a consultar
 * @returns {Promise<Object>} Datos de anomalía
 */
export async function getAnomalyScore(did, metric = 'avg_latency') {
  const res = await fetch(
    `${BASE_URL}/v1/anomaly_score?user=${encodeURIComponent(did)}&metric=${encodeURIComponent(metric)}`
  );
  if (!res.ok) throw new Error(`API Error ${res.status}`);
  return res.json();
}

// ─── Access Control ───────────────────────────────────────────────────────────

/**
 * Evalúa una decisión de acceso Zero Trust contra la política OPA/Rego.
 * @param {string} did - DID del sujeto
 * @param {string} resourceId - ID del recurso (e.g. "res:public-docs")
 * @param {string} classification - Clasificación del recurso ("public" | "restricted" | "top_secret")
 * @returns {Promise<{allow: boolean, requires_2fa: boolean, block: boolean}>}
 */
export async function evaluateAccess(did, resourceId, classification) {
  const clearance = { public: 1, restricted: 3, top_secret: 5 }[classification] ?? 1;

  const payload = {
    subject: {
      did,
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

  const res = await fetch(`${BASE_URL}/v1/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) throw new Error(`API Error ${res.status}`);
  return res.json();
}

// ─── Revocación P2P ───────────────────────────────────────────────────────────

/**
 * Revoca una credencial propagándola por la red P2P Gossipsub + CRDT Automerge.
 * @param {string} credentialId - ID de la credencial a revocar
 * @returns {Promise<void>}
 */
export async function revokeCredential(credentialId) {
  // NOTE: En producción, el token debería venir de un sistema de auth real.
  const adminToken = 'secret-admin-token';

  const res = await fetch(`${BASE_URL}/v1/revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({ credential_id: credentialId }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Error ${res.status}`);
  }
}
