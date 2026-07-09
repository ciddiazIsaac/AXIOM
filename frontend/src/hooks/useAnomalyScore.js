import { useState, useEffect, useRef } from 'react';
import { getAnomalyScore } from '../api/axiom';

/**
 * useAnomalyScore — Custom hook para polling del anomaly score.
 *
 * Hace polling cada `intervalMs` ms mientras el DID esté definido.
 * Limpia el intervalo automáticamente al desmontar o cuando cambia el DID.
 *
 * @param {string} did - DID del usuario activo
 * @param {number} [intervalMs=3000] - Frecuencia de polling en ms
 * @returns {{ score: number|null, pct: number, color: string, details: Object, meta: Object, error: string|null }}
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
  });

  const intervalRef = useRef(null);

  const fetchScore = async () => {
    if (!did) return;
    try {
      const data = await getAnomalyScore(did, 'avg_latency');
      const score = parseFloat(data.anomaly_score ?? 0);
      const pct = Math.round(score * 100);

      let color = '#22c55e'; // verde
      if (score > 0.5) color = '#f59e0b'; // naranja
      if (score > 0.8) color = '#ef4444'; // rojo

      setState({
        score,
        pct,
        color,
        isAnomaly: !!(data.is_anomaly || data.is_outlier),
        eventCount: data.event_count ?? null,
        baselineMean: data.baseline_mean ?? null,
        stdDev: data.std_dev ?? null,
        error: null,
      });
    } catch (err) {
      setState((prev) => ({ ...prev, error: err.message || 'Sin conexión con el servidor' }));
    }
  };

  useEffect(() => {
    if (!did) return;

    // Fetch inmediato al montar / cambiar DID
    fetchScore();

    // Polling periódico
    intervalRef.current = setInterval(fetchScore, intervalMs);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [did, intervalMs]); // eslint-disable-line react-hooks/exhaustive-deps

  return state;
}
