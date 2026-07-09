import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { revokeCredential } from '../../api/axiom';
import styles from './RevocationPanel.module.css';

/**
 * RevocationPanel — Panel de revocación P2P via CRDT Automerge + Gossipsub.
 * Usa AnimatePresence de Framer Motion para animar la aparición/salida del badge de estado.
 *
 * @param {{ did: string }} props
 */
export default function RevocationPanel({ did }) {
  const [credId, setCredId] = useState('');
  const [status, setStatus] = useState(null); // null | 'loading' | 'ok' | 'error'
  const [message, setMessage] = useState('');
  const [shake, setShake] = useState(false);

  const handleRevoke = async () => {
    const trimmed = credId.trim();
    if (!trimmed) {
      setShake(true);
      setTimeout(() => setShake(false), 500);
      return;
    }

    setStatus('loading');
    setMessage('Enviando a la red P2P Gossipsub...');

    try {
      await revokeCredential(trimmed);
      setStatus('ok');
      setMessage(`✓ Revocación de "${trimmed}" inyectada en la red CRDT`);
    } catch (err) {
      setStatus('error');
      setMessage(`✗ Error: ${err.message}`);
    }
  };

  const badgeClass =
    status === 'loading' ? 'badge-loading'
    : status === 'ok'    ? 'badge-ok'
    : status === 'error' ? 'badge-danger'
    : '';

  return (
    <section className={`glass-card ${styles.panel}`}>
      <p className="section-title">Revocación P2P · CRDT Automerge + Gossipsub</p>

      <div className={styles.form}>
        <div className="input-group">
          <label htmlFor="revoke-input">ID de Credencial a Revocar</label>
          <input
            id="revoke-input"
            type="text"
            placeholder="vc:axiom:credential:abc123..."
            value={credId}
            onChange={(e) => setCredId(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleRevoke()}
            className={shake ? 'shake' : ''}
            autoComplete="off"
            spellCheck="false"
          />
        </div>

        <motion.button
          className="btn-danger"
          onClick={handleRevoke}
          disabled={status === 'loading'}
          whileHover={{ scale: 1.015 }}
          whileTap={{ scale: 0.985 }}
          transition={{ type: 'spring', stiffness: 400, damping: 25 }}
        >
          ⚡ {status === 'loading' ? 'Propagando...' : 'Revocar Credencial'}
        </motion.button>

        {/* AnimatePresence: el badge entra/sale con spring */}
        <AnimatePresence mode="wait">
          {status && (
            <motion.div
              key={`revoke-${status}-${message.slice(0, 20)}`}
              className={`${styles.badge} metric-badge ${badgeClass}`}
              initial={{ opacity: 0, y: -8, scale: 0.95 }}
              animate={{ opacity: 1, y: 0,  scale: 1 }}
              exit={{    opacity: 0, y:  8,  scale: 0.95 }}
              transition={{ type: 'spring', stiffness: 320, damping: 26 }}
            >
              {message}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
