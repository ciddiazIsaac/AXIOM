import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { usePasskey } from '../hooks/usePasskey';
import styles from './LoginPage.module.css';


// ─── Variantes de animación ───────────────────────────────────────────────────

const cardVariants = {
  hidden:  { opacity: 0, y: 40, scale: 0.97 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { type: 'spring', stiffness: 280, damping: 28, delay: 0.05 },
  },
};

const itemVariants = {
  hidden:  { opacity: 0, y: 14 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 320, damping: 30 } },
};

const staggerContainer = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.07, delayChildren: 0.15 } },
};

const passkeySections = {
  hidden:  { opacity: 0, height: 0, marginBottom: 0 },
  visible: { opacity: 1, height: 'auto', marginBottom: '0.5rem', transition: { duration: 0.3, ease: 'easeOut' } },
  exit:    { opacity: 0, height: 0, marginBottom: 0,             transition: { duration: 0.2 } },
};

/**
 * LoginPage — Pantalla de autenticación DID con soporte Passkeys (WebAuthn/FIDO2).
 *
 * Flujo:
 *   1. El usuario puede autenticarse con su Passkey biométrica (Face ID / Windows Hello)
 *      haciendo clic en "Continuar con Passkey".
 *   2. O bien, ingresar su DID manualmente y simular firma Ed25519.
 *
 * @param {{ onLogin: (did: string) => void }} props
 */
export default function LoginPage({ onLogin }) {
  const [did, setDid]     = useState('did:axiom:test_42');
  const [shake, setShake] = useState(false);

  const { status, message, isSupported, authenticate, register } = usePasskey();

  const isPasskeyBusy = status === 'registering' || status === 'authenticating';

  // ─── Handlers ───────────────────────────────────────────────────────────────

  const handleSubmit = () => {
    const trimmed = did.trim();
    if (!trimmed) {
      setShake(true);
      setTimeout(() => setShake(false), 500);
      return;
    }
    onLogin(trimmed);
  };

  const handlePasskeyAuth = () => {
    const trimmed = did.trim() || 'did:axiom:passkey_user';
    authenticate(trimmed, onLogin);
  };

  const handlePasskeyRegister = () => {
    const trimmed = did.trim() || 'did:axiom:passkey_user';
    register(trimmed);
  };

  // ─── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className={styles.screen}>
      <motion.div
        className={styles.card}
        variants={cardVariants}
        initial="hidden"
        animate="visible"
      >
        <motion.div variants={staggerContainer} initial="hidden" animate="visible">

          {/* Logo */}
          <motion.div className={styles.logo} variants={itemVariants}>
            <div className={styles.logoMark}>AX</div>
            <h1 className={styles.logoTitle}>AXIOM</h1>
            <p className={styles.logoSub}>Zero Trust Architecture</p>
          </motion.div>

          {/* Passkeys section — solo si el browser lo soporta */}
          {isSupported && (
            <motion.div variants={itemVariants}>
              <button
                id="btn-passkey-auth"
                className={styles.btnPasskey}
                onClick={handlePasskeyAuth}
                disabled={isPasskeyBusy}
              >
                <span className={styles.biometricIcon}>
                  {isPasskeyBusy ? (
                    <span className="spinner" style={{ width: 18, height: 18 }} />
                  ) : (
                    '⬡'
                  )}
                </span>
                <span>
                  {status === 'authenticating'
                    ? 'Verificando identidad...'
                    : 'Continuar con Passkey / Biometría'}
                </span>
              </button>

              {/* Feedback de passkey */}
              <AnimatePresence mode="wait">
                {status !== 'idle' && message && (
                  <motion.div
                    key={`pk-msg-${status}`}
                    className={`metric-badge ${
                      status === 'success' ? 'badge-ok'
                      : status === 'error'   ? 'badge-danger'
                      : 'badge-loading'
                    } ${styles.passKeyBadge}`}
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 6 }}
                    transition={{ duration: 0.22 }}
                  >
                    {message}
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Botón de registro (la primera vez) */}
              <AnimatePresence>
                {status === 'error' && message.includes('reconocida') && (
                  <motion.button
                    className={styles.btnPasskeySecondary}
                    onClick={handlePasskeyRegister}
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.25 }}
                  >
                    Registrar nuevo Passkey para este DID
                  </motion.button>
                )}
              </AnimatePresence>

              {/* Separador */}
              <motion.div className={styles.separator} variants={itemVariants}>
                <span />
                <span className={styles.separatorText}>o continuar con DID</span>
                <span />
              </motion.div>
            </motion.div>
          )}

          {/* Auth title */}
          <motion.h2 className={styles.authTitle} variants={itemVariants}>
            Autenticación DID
          </motion.h2>

          {/* DID input */}
          <motion.div className="input-group" variants={itemVariants}>
            <label htmlFor="did-input">Identidad Descentralizada (DID)</label>
            <input
              id="did-input"
              type="text"
              placeholder="did:axiom:z6MkfaywSN..."
              value={did}
              onChange={(e) => setDid(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
              className={shake ? 'shake' : ''}
              autoComplete="off"
              spellCheck="false"
            />
          </motion.div>

          {/* Submit button */}
          <motion.button
            id="btn-login"
            className="btn-primary"
            onClick={handleSubmit}
            variants={itemVariants}
            whileHover={{ scale: 1.015, boxShadow: '0 8px 32px rgba(59,130,246,0.5)' }}
            whileTap={{ scale: 0.985 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
          >
            <span>Simular Firma Ed25519</span>
            <span>→</span>
          </motion.button>

          {/* WebAuthn not supported notice */}
          {!isSupported && (
            <motion.p className={styles.noPasskeyNotice} variants={itemVariants}>
              Passkeys no disponibles en este navegador
            </motion.p>
          )}
        </motion.div>
      </motion.div>
    </div>
  );
}
