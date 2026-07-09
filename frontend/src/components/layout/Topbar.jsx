import styles from './Topbar.module.css';

/**
 * Topbar — Barra superior pegajosa con logo AXIOM e identidad del usuario.
 *
 * @param {{ did: string }} props
 */
export default function Topbar({ did }) {
  return (
    <header className={styles.topbar}>
      <div className={styles.logo}>
        <div className={styles.logoBadge}>AX</div>
        <span>AXIOM</span>
      </div>
      <div className={styles.identity}>
        <span className={styles.identityDot} />
        <span className={styles.identityText}>{did || '—'}</span>
      </div>
    </header>
  );
}
