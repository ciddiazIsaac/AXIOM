import { useState } from 'react';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';

/**
 * App — Root component que gestiona el estado de autenticación DID.
 * Renderiza LoginPage o DashboardPage según si el usuario está autenticado.
 */
export default function App() {
  const [currentDid, setCurrentDid] = useState(null);

  const handleLogin = (did) => {
    setCurrentDid(did);
  };

  if (!currentDid) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return <DashboardPage did={currentDid} />;
}
