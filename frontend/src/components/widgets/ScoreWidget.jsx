import { motion, AnimatePresence } from 'framer-motion';
import { useAnomalyScore } from '../../hooks/useAnomalyScore';
import styles from './ScoreWidget.module.css';

const CIRCUMFERENCE = 2 * Math.PI * 54; // r=54

// ─── Variantes de animación ───────────────────────────────────────────────────

const widgetVariants = {
  hidden:  { opacity: 0, y: 20 },
  visible: {
    opacity: 1, y: 0,
    transition: { type: 'spring', stiffness: 260, damping: 28 },
  },
};

const anomalyPulse = {
  initial:  { scale: 1, opacity: 1 },
  animate:  {
    scale:   [1, 1.04, 1],
    opacity: [1, 0.75, 1],
    transition: { duration: 1.8, repeat: Infinity, ease: 'easeInOut' },
  },
};

/**
 * ScoreWidget — Visualizador del Anomaly Score con SSE en tiempo real.
 * Muestra badge "● LIVE" cuando la conexión SSE está activa.
 * Usa Framer Motion para interpolar el anillo SVG y animar estados de anomalía.
 *
 * @param {{ did: string }} props
 */
export default function ScoreWidget({ did }) {
  const { pct, color, isAnomaly, eventCount, baselineMean, stdDev, error, isLive } =
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
    <motion.section
      className={`glass-card ${styles.widget}`}
      variants={widgetVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Header: título + badge LIVE */}
      <div className={styles.header}>
        <p className="section-title" style={{ margin: 0 }}>Anomaly Score · Tiempo Real</p>
        <AnimatePresence>
          {isLive && (
            <motion.span
              className={styles.liveBadge}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            >
              <span className={styles.liveDot} />
              LIVE
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      <div className={styles.ringContainer}>
        {/* SVG Ring con animación Framer Motion */}
        <motion.div
          className={styles.svgWrapper}
          animate={isAnomaly && !error ? anomalyPulse.animate : anomalyPulse.initial}
        >
          <svg width="140" height="140" viewBox="0 0 140 140">
            {/* Track */}
            <circle
              cx="70" cy="70" r="54"
              fill="none"
              stroke="rgba(148,163,184,0.1)"
              strokeWidth="10"
            />
            {/* Progress — animado via CSS transition + Framer spring en color */}
            <motion.circle
              cx="70" cy="70" r="54"
              fill="none"
              stroke={error ? 'rgba(148,163,184,0.2)' : color}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={strokeOffset}
              animate={{
                strokeDashoffset: strokeOffset,
                stroke: error ? 'rgba(148,163,184,0.2)' : color,
              }}
              transition={{ type: 'spring', stiffness: 60, damping: 18 }}
            />
          </svg>

          {/* Overlay text */}
          <div className={styles.textOverlay}>
            <motion.span
              className={styles.scoreValue}
              style={{ color: error ? 'var(--text-dim)' : color }}
              key={pct}
              initial={{ scale: 0.85, opacity: 0.5 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ type: 'spring', stiffness: 320, damping: 22 }}
            >
              {error ? '—' : `${pct}%`}
            </motion.span>
            <span className={styles.scoreLabel}>Riesgo</span>
          </div>
        </motion.div>

        {/* Status badge */}
        <AnimatePresence mode="wait">
          <motion.span
            key={badgeClass + badgeText.slice(0, 10)}
            className={`metric-badge ${badgeClass}`}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.25 }}
          >
            {badgeText}
          </motion.span>
        </AnimatePresence>
      </div>

      {/* Metric metadata */}
      <AnimatePresence>
        {!error && eventCount !== null && (
          <motion.div
            className={styles.meta}
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
          >
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
          </motion.div>
        )}
      </AnimatePresence>
    </motion.section>
  );
}
