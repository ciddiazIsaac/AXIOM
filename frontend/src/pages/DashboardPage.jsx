import Topbar from '../components/layout/Topbar';
import ScoreWidget from '../components/widgets/ScoreWidget';
import RevocationPanel from '../components/widgets/RevocationPanel';
import AccessPanel from '../components/access/AccessPanel';
import styles from './DashboardPage.module.css';

/**
 * DashboardPage — Layout principal del dashboard Zero Trust.
 * Orquesta los widgets en un CSS Grid de dos columnas.
 *
 * @param {{ did: string }} props
 */
export default function DashboardPage({ did }) {
  return (
    <div className={styles.page}>
      <Topbar did={did} />

      <main className={styles.content}>
        {/* Columna izquierda: Score + Revocación */}
        <ScoreWidget did={did} />
        <RevocationPanel did={did} />

        {/* Columna derecha: Access Control (ocupa 2 filas) */}
        <AccessPanel did={did} />
      </main>
    </div>
  );
}
