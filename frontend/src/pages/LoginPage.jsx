import { useState } from 'react';
import styles from './LoginPage.module.css';

/**
 * LoginPage — Pantalla de autenticación DID simulada.
 *
 * @param {{ onLogin: (did: string) => void }} props
 */
export default function LoginPage({ onLogin }) {
  const [did, setDid] = useState('did:axiom:test_42');
  const [shake, setShake] = useState(false);

  const handleSubmit = () => {
    const trimmed = did.trim();
    if (!trimmed) {
      setShake(true);
      setTimeout(() => setShake(false), 500);
      return;
    }
    onLogin(trimmed);
  };

  return (
    <div className={styles.screen}>
      <div className={styles.card}>
        {/* Logo */}
        <div className={styles.logo}>
          <div className={styles.logoMark}>AX</div>
          <h1 className={styles.logoTitle}>AXIOM</h1>
          <p className={styles.logoSub}>Zero Trust Architecture</p>
        </div>

        <h2 className={styles.authTitle}>Autenticación DID</h2>

        <div className="input-group">
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
        </div>

        <button id="btn-login" className="btn-primary" onClick={handleSubmit}>
          <span>Simular Firma Ed25519</span>
          <span>→</span>
        </button>
      </div>
    </div>
  );
}
