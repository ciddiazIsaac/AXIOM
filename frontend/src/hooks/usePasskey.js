import { useState, useCallback } from 'react';
import {
  isPasskeySupported,
  startPasskeyRegistration,
  startPasskeyAuthentication,
} from '../api/webauthn';

/**
 * usePasskey — Hook para gestionar el flujo WebAuthn / FIDO2.
 *
 * Encapsula registro y autenticación con Passkeys, exponiendo estado
 * reactivo para que la UI refleje cada fase del flujo biométrico.
 *
 * @returns {{
 *   status: 'idle'|'registering'|'authenticating'|'success'|'error',
 *   message: string,
 *   isSupported: boolean,
 *   register: (did: string) => Promise<void>,
 *   authenticate: (did: string, onSuccess: (did: string) => void) => Promise<void>,
 *   reset: () => void,
 * }}
 */
export function usePasskey() {
  const [status, setStatus]   = useState('idle');
  const [message, setMessage] = useState('');

  const isSupported = isPasskeySupported();

  /**
   * Registra un nuevo Passkey para el DID dado.
   * Muestra el diálogo nativo del OS para crear la credencial biométrica.
   */
  const register = useCallback(async (did) => {
    if (!did) return;
    setStatus('registering');
    setMessage('Abriendo gestor de claves del sistema...');
    try {
      const { credentialId } = await startPasskeyRegistration(did);
      setStatus('success');
      setMessage(`✓ Passkey registrada · ID: ${credentialId.slice(0, 16)}…`);
    } catch (err) {
      // NotAllowedError → usuario canceló el diálogo del OS
      const userCancelled = err?.name === 'NotAllowedError';
      setStatus('error');
      setMessage(
        userCancelled
          ? 'Operación cancelada por el usuario'
          : (err.message || 'Error al registrar Passkey')
      );
    }
  }, []);

  /**
   * Autentica al usuario con su Passkey existente.
   * Muestra el diálogo nativo del OS para verificación biométrica.
   * Si tiene éxito, llama a onSuccess(did) para completar el login en la app.
   *
   * @param {string} did - DID del usuario
   * @param {(did: string) => void} onSuccess - Callback al completar autenticación
   */
  const authenticate = useCallback(async (did, onSuccess) => {
    if (!did) return;
    setStatus('authenticating');
    setMessage('Verificando identidad con biometría...');
    try {
      const { did: verifiedDid } = await startPasskeyAuthentication(did);
      setStatus('success');
      setMessage('✓ Autenticación biométrica exitosa');
      // Pequeño delay para que el usuario vea el feedback antes de redirigir
      setTimeout(() => onSuccess(verifiedDid), 600);
    } catch (err) {
      const userCancelled = err?.name === 'NotAllowedError';
      setStatus('error');
      setMessage(
        userCancelled
          ? 'Operación cancelada por el usuario'
          : (err.message || 'Error en autenticación biométrica')
      );
    }
  }, []);

  /** Resetea el estado al idle inicial */
  const reset = useCallback(() => {
    setStatus('idle');
    setMessage('');
  }, []);

  return { status, message, isSupported, register, authenticate, reset };
}
