import { useState, useEffect, useRef } from 'react';
import { getAnomalyScore } from '../api/axiom';

const BASE_URL = '';

/**
 * useAnomalyScore — Hook de anomaly score con SSE y fallback a polling.
 *
 * Estrategia de conexión (Zero Polling First):
 *   1. Intenta abrir una conexión SSE a /v1/anomaly_score/stream?user=<did>
 *   2. Si el servidor responde con text/event-stream → modo LIVE (SSE activo)
 *   3. Si SSE falla (404, CORS, timeout) → fallback silencioso a polling cada intervalMs
 *   4. Al desmontar → cierra EventSource O clearInterval según modo activo
 *
 * @param {string} did - DID del usuario activo
 * @param {number} [intervalMs=3000] - Frecuencia de polling en fallback mode
 * @returns {{
 *   score: number|null,
 *   pct: number,
 *   color: string,
 *   isAnomaly: boolean,
 *   eventCount: number|null,
 *   baselineMean: number|null,
 *   stdDev: number|null,
 *   error: string|null,
 *   isLive: boolean,   // true = SSE activo; false = polling fallback
 * }}
 */
export function useAnomalyScore(did, intervalMs = 3000) {
  const [state, setState] = useState({
    score: null,
    pct: 0,
    color: '#22c55e',
    isAnomaly: false,
    eventCount: null,
    baselineMean: null,
    stdDev: null,
    error: null,
    isLive: false,
  });

  const esRef          = useRef(null); // EventSource ref
  const intervalRef    = useRef(null); // fallback polling interval ref
  const sseFailedRef   = useRef(false); // true si SSE ya falló, no reintentar

  // ─── Parser compartido: convierte datos del servidor al estado del hook ────
  const parseData = (data) => {
    const score = parseFloat(data.anomaly_score ?? 0);
    const pct   = Math.round(score * 100);

    let color = '#22c55e'; // verde
    if (score > 0.5) color = '#f59e0b'; // naranja
    if (score > 0.8) color = '#ef4444'; // rojo

    return {
      score,
      pct,
      color,
      isAnomaly:    !!(data.is_anomaly || data.is_outlier),
      eventCount:   data.event_count   ?? null,
      baselineMean: data.baseline_mean ?? null,
      stdDev:       data.std_dev       ?? null,
      error:        null,
    };
  };

  // ─── Polling fallback ─────────────────────────────────────────────────────
  const startPolling = () => {
    if (intervalRef.current) return; // ya corriendo

    const fetchScore = async () => {
      if (!did) return;
      try {
        const data = await getAnomalyScore(did, 'avg_latency');
        setState((prev) => ({ ...prev, ...parseData(data), isLive: false }));
      } catch (err) {
        setState((prev) => ({
          ...prev,
          error: err.message || 'Sin conexión con el servidor',
          isLive: false,
        }));
      }
    };

    fetchScore(); // fetch inmediato
    intervalRef.current = setInterval(fetchScore, intervalMs);
  };

  // ─── SSE connection ───────────────────────────────────────────────────────
  const startSSE = (userDid) => {
    if (!('EventSource' in window) || sseFailedRef.current) {
      // Browser no soporta SSE o ya falló → directo a polling
      startPolling();
      return;
    }

    const url = `${BASE_URL}/v1/anomaly_score/stream?user=${encodeURIComponent(userDid)}&metric=avg_latency`;
    const es  = new EventSource(url);
    esRef.current = es;

    // Timeout: si en 2.5s no hay mensaje → asumir que el servidor no soporta SSE
    const sseTimeout = setTimeout(() => {
      if (esRef.current && esRef.current.readyState !== EventSource.OPEN) {
        sseFailedRef.current = true;
        es.close();
        esRef.current = null;
        startPolling();
      }
    }, 2500);

    es.onopen = () => {
      clearTimeout(sseTimeout);
      setState((prev) => ({ ...prev, isLive: true, error: null }));
    };

    es.onmessage = (event) => {
      clearTimeout(sseTimeout);
      try {
        const data = JSON.parse(event.data);
        setState((prev) => ({ ...prev, ...parseData(data), isLive: true }));
      } catch {
        // mensaje malformado — ignorar
      }
    };

    // Evento específico 'anomaly_score' (algunos backends usan named events)
    es.addEventListener('anomaly_score', (event) => {
      clearTimeout(sseTimeout);
      try {
        const data = JSON.parse(event.data);
        setState((prev) => ({ ...prev, ...parseData(data), isLive: true }));
      } catch {
        // ignorar
      }
    });

    es.onerror = () => {
      clearTimeout(sseTimeout);
      // SSE error → cerrar y caer a polling
      sseFailedRef.current = true;
      es.close();
      esRef.current = null;
      startPolling();
    };
  };

  // ─── Effect principal ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!did) return;

    sseFailedRef.current = false; // reset al cambiar DID

    startSSE(did);

    return () => {
      // Cleanup SSE
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      // Cleanup polling
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [did, intervalMs]); // eslint-disable-line react-hooks/exhaustive-deps

  return state;
}
