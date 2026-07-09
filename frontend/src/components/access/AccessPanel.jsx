import { useState } from 'react';
import { evaluateAccess } from '../../api/axiom';
import ResourceButton from './ResourceButton';
import styles from './AccessPanel.module.css';

const RESOURCES = [
  { id: 'btn-resource-public',     resourceId: 'res:public-docs',      icon: '📄', name: 'Documentos Públicos', classification: 'public' },
  { id: 'btn-resource-restricted', resourceId: 'res:internal-reports',  icon: '🔒', name: 'Reportes Internos',   classification: 'restricted' },
  { id: 'btn-resource-secret',     resourceId: 'res:admin-panel',       icon: '🔐', name: 'Panel Admin',         classification: 'top_secret' },
];

/**
 * AccessPanel — Consola de control de acceso Zero Trust.
 * Muestra los recursos disponibles y evalúa la política OPA/Rego al hacer clic.
 *
 * @param {{ did: string }} props
 */
export default function AccessPanel({ did }) {
  const [result, setResult] = useState(null); // null | { status, resourceId, classification, allow, requires2fa, block }
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
        allow: decision.allow,
        requires2fa: decision.requires_2fa,
        block: decision.block,
      });
    } catch {
      setResult({ ok: false, resourceId, classification });
    } finally {
      setLoading(false);
    }
  };

  // Determine decision state
  let statusClass = '';
  let statusIcon = '';
  let statusText = '';

  if (result?.ok) {
    if (result.block || !result.allow) {
      statusClass = styles.deny;
      statusIcon = '✗';
      statusText = 'ACCESO DENEGADO';
    } else if (result.requires2fa) {
      statusClass = styles.challenge;
      statusIcon = '⚡';
      statusText = 'REQUIERE VERIFICACIÓN';
    } else {
      statusClass = styles.allow;
      statusIcon = '✓';
      statusText = 'ACCESO PERMITIDO';
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

      {/* Result card */}
      <div
        className={`${styles.resultCard} ${
          loading ? styles.loading : result ? (result.ok ? statusClass : styles.error) : ''
        }`}
      >
        {!result && !loading && (
          <div className={styles.placeholder}>
            Selecciona un recurso para evaluar la política OPA/Rego →
          </div>
        )}

        {loading && (
          <>
            <div className="spinner" />
            <span>Evaluando política Zero Trust...</span>
          </>
        )}

        {result && !loading && result.ok && (
          <>
            <div className={styles.resultHeader}>
              <span className={`${styles.resultIcon} ${statusClass}`}>{statusIcon}</span>
              <span className={`${styles.resultStatus} ${statusClass}`}>{statusText}</span>
            </div>
            <div className={styles.details}>
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>Recurso</span>
                <span className={styles.detailValue}>{result.resourceId}</span>
              </div>
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>Clasificación</span>
                <span className={`${styles.detailValue} ${styles[`class_${result.classification}`]}`}>
                  {result.classification.replace('_', ' ').toUpperCase()}
                </span>
              </div>
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>2FA requerido</span>
                <span className={styles.detailValue}>{result.requires2fa ? 'Sí' : 'No'}</span>
              </div>
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>Bloqueo activo</span>
                <span className={styles.detailValue}>{result.block ? 'Sí' : 'No'}</span>
              </div>
            </div>
          </>
        )}

        {result && !loading && !result.ok && (
          <div className={styles.resultHeader}>
            <span className={styles.resultIcon}>!</span>
            <span className={styles.resultStatus}>ERROR DE RED</span>
          </div>
        )}
      </div>
    </section>
  );
}
