import { useAnomalyScore } from '../../hooks/useAnomalyScore';
import styles from './ScoreWidget.module.css';

const CIRCUMFERENCE = 2 * Math.PI * 54; // r=54

/**
 * ScoreWidget — Visualizador del Anomaly Score en tiempo real.
 * Hace polling automático cada 3s usando el hook useAnomalyScore.
 *
 * @param {{ did: string }} props
 */
export default function ScoreWidget({ did }) {
  const { pct, color, isAnomaly, eventCount, baselineMean, stdDev, error } =
    useAnomalyScore(did);

  const strokeOffset = error
    ? CIRCUMFERENCE
    : CIRCUMFERENCE - (pct / 100) * CIRCUMFERENCE;

  const badgeClass = error
    ? 'badge-warn'
    : isAnomaly
    ? 'badge-danger'
    : 'badge-ok';

  const badgeText = error
    ? error
    : isAnomaly
    ? '⚠ Anomalía detectada — Comportamiento fuera de la norma'
    : '✓ Comportamiento dentro del patrón normal';

  return (
    <section className={`glass-card ${styles.widget}`}>
      <p className="section-title">Anomaly Score · Tiempo Real</p>

      <div className={styles.ringContainer}>
        {/* SVG Ring */}
        <div className={styles.svgWrapper}>
          <svg width="140" height="140" viewBox="0 0 140 140">
            {/* Track */}
            <circle
              cx="70" cy="70" r="54"
              fill="none"
              stroke="rgba(148,163,184,0.1)"
              strokeWidth="10"
            />
            {/* Progress */}
            <circle
              cx="70" cy="70" r="54"
              fill="none"
              stroke={error ? 'rgba(148,163,184,0.2)' : color}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={strokeOffset}
              style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1), stroke 0.5s' }}
            />
          </svg>

          {/* Overlay text */}
          <div className={styles.textOverlay}>
            <span
              className={styles.scoreValue}
              style={{ color: error ? 'var(--text-dim)' : color }}
            >
              {error ? '—' : `${pct}%`}
            </span>
            <span className={styles.scoreLabel}>Riesgo</span>
          </div>
        </div>

        {/* Status badge */}
        <span className={`metric-badge ${badgeClass}`}>{badgeText}</span>
      </div>

      {/* Metric metadata */}
      {!error && eventCount !== null && (
        <div className={styles.meta}>
          <span>
            Eventos analizados: <strong>{eventCount}</strong>
          </span>
          <span>
            Media base:{' '}
            <strong>{baselineMean != null ? `${baselineMean.toFixed(1)} ms` : '—'}</strong>
          </span>
          <span>
            Desv. estándar:{' '}
            <strong>{stdDev != null ? `${stdDev.toFixed(1)} ms` : '—'}</strong>
          </span>
        </div>
      )}
    </section>
  );
}
