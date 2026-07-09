import { motion } from 'framer-motion';
import Topbar from '../components/layout/Topbar';
import ScoreWidget from '../components/widgets/ScoreWidget';
import RevocationPanel from '../components/widgets/RevocationPanel';
import AccessPanel from '../components/access/AccessPanel';
import styles from './DashboardPage.module.css';

// ─── Variantes de animación ───────────────────────────────────────────────────

/** Contenedor del grid: dispara stagger a los hijos */
const gridVariants = {
  hidden:  {},
  visible: {
    transition: {
      staggerChildren:  0.08,
      delayChildren:    0.1,
    },
  },
};

/** Variante compartida para cada widget hijo */
export const widgetItemVariants = {
  hidden:  { opacity: 0, y: 24, scale: 0.98 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { type: 'spring', stiffness: 260, damping: 28 },
  },
};

/**
 * DashboardPage — Layout principal del dashboard Zero Trust.
 * Orquesta los widgets en un CSS Grid de dos columnas con stagger Framer Motion.
 *
 * @param {{ did: string }} props
 */
export default function DashboardPage({ did }) {
  return (
    <div className={styles.page}>
      <Topbar did={did} />

      <motion.main
        className={styles.content}
        variants={gridVariants}
        initial="hidden"
        animate="visible"
      >
        {/* Columna izquierda: Score + Revocación */}
        <motion.div variants={widgetItemVariants}>
          <ScoreWidget did={did} />
        </motion.div>

        <motion.div variants={widgetItemVariants}>
          <RevocationPanel did={did} />
        </motion.div>

        {/* Columna derecha: Access Control (ocupa 2 filas) */}
        <motion.div variants={widgetItemVariants} style={{ gridColumn: 2, gridRow: '1 / 3' }}>
          <AccessPanel did={did} />
        </motion.div>
      </motion.main>
    </div>
  );
}
