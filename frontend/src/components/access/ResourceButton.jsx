import styles from './ResourceButton.module.css';

const classMap = {
  public:     { label: 'PUBLIC',     className: styles.classPublic },
  restricted: { label: 'RESTRICTED', className: styles.classRestricted },
  top_secret: { label: 'TOP SECRET', className: styles.classTopSecret },
};

/**
 * ResourceButton — Tarjeta clickeable para solicitar acceso a un recurso.
 *
 * @param {{ icon: string, name: string, classification: string, onClick: () => void }} props
 */
export default function ResourceButton({ icon, name, classification, onClick }) {
  const { label, className } = classMap[classification] ?? classMap.public;

  return (
    <button className={styles.btn} onClick={onClick}>
      <span className={styles.icon}>{icon}</span>
      <span className={styles.name}>{name}</span>
      <span className={`${styles.class} ${className}`}>{label}</span>
    </button>
  );
}
