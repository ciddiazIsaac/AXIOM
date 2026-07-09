import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { evaluateAccess } from '../../api/axiom';
import ResourceButton from './ResourceButton';
import styles from './AccessPanel.module.css';

const RESOURCES = [
  { id: 'btn-resource-public',     resourceId: 'res:public-docs',      icon: '📄', name: 'Documentos Públicos', classification: 'public' },
  { id: 'btn-resource-restricted', resourceId: 'res:internal-reports',  icon: '🔒', name: 'Reportes Internos',   classification: 'restricted' },
  { id: 'btn-resource-secret',     resourceId: 'res:admin-panel',       icon: '🔐', name: 'Panel Admin',         classification: 'top_secret' },
];

// ─── Variantes de animación ───────────────────────────────────────────────────

const resultCardVariants = {
  hidden:  { opacity: 0, y: 12, scale: 0.98 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { type: 'spring', stiffness: 300, damping: 28 },
  },
  exit: {
    opacity: 0, y: -8, scale: 0.97,
    transition: { duration: 0.18 },
  },
};

const detailRowVariants = {
  hidden:  { opacity: 0, x: -8 },
  visible: { opacity: 1, x: 0, transition: { type: 'spring', stiffness: 260, damping: 24 } },
};

const staggerDetails = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.06, delayChildren: 0.1 } },
};

/**
 * AccessPanel — Consola de control de acceso Zero Trust.
 * Muestra los recursos disponibles y evalúa la política OPA/Rego al hacer clic.
 * Usa AnimatePresence para animar entradas/salidas del resultado de evaluación.
 *
 * @param {{ did: string }} props
 */
export default function AccessPanel({ did }) {
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);

  const handleRequest = async (resourceId, classification) => {
    setLoading(true);
    setResult(null);

    try {
      const decision = await evaluateAccess(did, resourceId, classification);
      setResult({
        ok: true,
        resourceId,
        classification,
        allow:       decision.allow,
        requires2fa: decision.requires_2fa,
        block:       decision.block,
      });
    } catch {
      setResult({ ok: false, resourceId, classification });
    } finally {
      setLoading(false);
    }
  };

  // Determine decision state
  let statusClass = '';
  let statusIcon  = '';
  let statusText  = '';

  if (result?.ok) {
    if (result.block || !result.allow) {
      statusClass = styles.deny;
      statusIcon  = '✗';
      statusText  = 'ACCESO DENEGADO';
    } else if (result.requires2fa) {
      statusClass = styles.challenge;
      statusIcon  = '⚡';
      statusText  = 'REQUIERE VERIFICACIÓN';
    } else {
      statusClass = styles.allow;
      statusIcon  = '✓';
      statusText  = 'ACCESO PERMITIDO';
    }
  }

  return (
    <section className={`glass-card ${styles.panel}`}>
      <p className="section-title">Consola de Control de Acceso · Política Zero Trust</p>

      {/* Resource grid */}
      <div className={styles.grid}>
        {RESOURCES.map(({ id, resourceId, icon, name, classification }) => (
          <ResourceButton
            key={id}
            icon={icon}
            name={name}
            classification={classification}
            onClick={() => handleRequest(resourceId, classification)}
          />
        ))}
      </div>

      {/* Result card — AnimatePresence para entrada/salida fluida */}
      <div className={styles.resultArea}>
        <AnimatePresence mode="wait">
          {/* Placeholder */}
          {!result && !loading && (
            <motion.div
              key="placeholder"
              className={`${styles.resultCard}`}
              variants={resultCardVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
            >
              <div className={styles.placeholder}>
                Selecciona un recurso para evaluar la política OPA/Rego →
              </div>
            </motion.div>
          )}

          {/* Loading */}
          {loading && (
            <motion.div
              key="loading"
              className={`${styles.resultCard} ${styles.loading}`}
              variants={resultCardVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
            >
              <div className="spinner" />
              <span>Evaluando política Zero Trust...</span>
            </motion.div>
          )}

          {/* Result — éxito */}
          {result && !loading && result.ok && (
            <motion.div
              key={`result-${result.resourceId}-${Date.now()}`}
              className={`${styles.resultCard} ${statusClass}`}
              variants={resultCardVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
            >
              <div className={styles.resultHeader}>
                <motion.span
                  className={`${styles.resultIcon} ${statusClass}`}
                  initial={{ scale: 0, rotate: -20 }}
                  animate={{ scale: 1, rotate: 0 }}
                  transition={{ type: 'spring', stiffness: 400, damping: 20, delay: 0.1 }}
                >
                  {statusIcon}
                </motion.span>
                <span className={`${styles.resultStatus} ${statusClass}`}>{statusText}</span>
              </div>

              <motion.div
                className={styles.details}
                variants={staggerDetails}
                initial="hidden"
                animate="visible"
              >
                {[
                  ['Recurso',        result.resourceId],
                  ['Clasificación',  result.classification.replace('_', ' ').toUpperCase()],
                  ['2FA requerido',  result.requires2fa ? 'Sí' : 'No'],
                  ['Bloqueo activo', result.block ? 'Sí' : 'No'],
                ].map(([label, value], i) => (
                  <motion.div
                    key={label}
                    className={styles.detailRow}
                    variants={detailRowVariants}
                  >
                    <span className={styles.detailLabel}>{label}</span>
                    <span className={`${styles.detailValue} ${i === 1 ? styles[`class_${result.classification}`] : ''}`}>
                      {value}
                    </span>
                  </motion.div>
                ))}
              </motion.div>
            </motion.div>
          )}

          {/* Result — error de red */}
          {result && !loading && !result.ok && (
            <motion.div
              key="error"
              className={`${styles.resultCard} ${styles.error}`}
              variants={resultCardVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
            >
              <div className={styles.resultHeader}>
                <span className={styles.resultIcon}>!</span>
                <span className={styles.resultStatus}>ERROR DE RED</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
