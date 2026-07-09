/**
 * webauthn.js — Capa de API para el flujo WebAuthn / FIDO2 (Passkeys).
 *
 * Implementa el estándar WebAuthn (W3C) usando @simplewebauthn/browser como
 * abstracción sobre la API nativa del browser (navigator.credentials).
 *
 * En este entorno de desarrollo, las opciones de registro / autenticación
 * se generan en memoria (modo demo) simulando la respuesta que vendría del
 * backend AXIOM. En producción, startPasskeyRegistration / startPasskeyAuthentication
 * deberían hacer fetch a /v1/webauthn/register/options y /v1/webauthn/auth/options.
 *
 * Compatibilidad:
 *   - Chrome ≥ 108, Edge ≥ 108, Safari ≥ 16, Firefox ≥ 119
 *   - Windows Hello, Touch ID, Face ID, YubiKey (cualquier FIDO2 authenticator)
 *   - localhost funciona sin TLS (WebAuthn exception para desarrollo)
 */

import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
} from '@simplewebauthn/browser';

const RP_ID   = window.location.hostname;            // 'localhost' en dev
const RP_NAME = 'AXIOM Zero Trust';
const ORIGIN  = window.location.origin;              // 'http://localhost:5173'

// ─── Utilidades internas ──────────────────────────────────────────────────────

/**
 * Genera un challenge pseudoaleatorio de 32 bytes codificado en base64url.
 * En producción esto DEBE venir del servidor (nonce único, no predecible).
 */
function generateChallenge() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Encode un string a base64url (para credentialID simulado).
 */
function toBase64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ─── API pública ──────────────────────────────────────────────────────────────

/**
 * Verifica que el browser soporte WebAuthn (FIDO2).
 * @returns {boolean}
 */
export function isPasskeySupported() {
  return browserSupportsWebAuthn();
}

/**
 * Inicia el flujo de REGISTRO de un nuevo Passkey para un DID dado.
 * Muestra el diálogo nativo del OS (Windows Hello / Touch ID / Face ID).
 *
 * @param {string} did - DID del usuario (usado como user.name y user.displayName)
 * @returns {Promise<{ credentialId: string, did: string }>}
 */
export async function startPasskeyRegistration(did) {
  if (!isPasskeySupported()) {
    throw new Error('Tu navegador no soporta Passkeys (WebAuthn). Usa Chrome, Edge o Safari modernos.');
  }

  // Opciones de registro (en producción: GET /v1/webauthn/register/options)
  const registrationOptions = {
    rp: {
      id:   RP_ID,
      name: RP_NAME,
    },
    user: {
      id:          toBase64url(did),
      name:        did,
      displayName: did,
    },
    challenge:        generateChallenge(),
    pubKeyCredParams: [
      { alg: -7,   type: 'public-key' }, // ES256 (ECDSA P-256) — preferido
      { alg: -257, type: 'public-key' }, // RS256 (RSA) — fallback
    ],
    timeout:                 60000,
    attestation:             'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',      // biométrico nativo (no USB key)
      requireResidentKey:      true,
      userVerification:        'required',
    },
    extensions: { credProps: true },
  };

  // Llama a la API nativa del browser → abre el diálogo del OS
  const registrationResponse = await startRegistration({ optionsJSON: registrationOptions });

  // En producción: POST /v1/webauthn/register/verify con registrationResponse
  // Aquí simulamos verificación exitosa
  const credentialId = registrationResponse.id;

  // Persistir en localStorage (demo) — en prod el servidor guarda la clave pública
  const stored = JSON.parse(localStorage.getItem('axiom_passkeys') || '{}');
  stored[did] = { credentialId, registeredAt: new Date().toISOString() };
  localStorage.setItem('axiom_passkeys', JSON.stringify(stored));

  return { credentialId, did };
}

/**
 * Inicia el flujo de AUTENTICACIÓN con un Passkey existente.
 * Muestra el diálogo nativo del OS para verificación biométrica.
 *
 * @param {string} did - DID del usuario a autenticar
 * @returns {Promise<{ verified: boolean, did: string }>}
 */
export async function startPasskeyAuthentication(did) {
  if (!isPasskeySupported()) {
    throw new Error('Tu navegador no soporta Passkeys (WebAuthn). Usa Chrome, Edge o Safari modernos.');
  }

  // Opciones de autenticación (en producción: GET /v1/webauthn/auth/options)
  const authenticationOptions = {
    challenge:        generateChallenge(),
    rpId:             RP_ID,
    timeout:          60000,
    userVerification: 'required',
    // allowCredentials vacío → el browser muestra TODOS los passkeys del dominio (discoverable credentials)
    allowCredentials: [],
  };

  // Abre el diálogo nativo del OS → usuario verifica con biometría
  const authResponse = await startAuthentication({ optionsJSON: authenticationOptions });

  // En producción: POST /v1/webauthn/auth/verify con authResponse
  // Aquí verificamos que el credentialId coincida con uno registrado (demo)
  const stored = JSON.parse(localStorage.getItem('axiom_passkeys') || '{}');
  const allCredIds = Object.values(stored).map((v) => v.credentialId);

  const verified = allCredIds.includes(authResponse.id) || allCredIds.length === 0;
  // allCredIds.length === 0 → modo demo sin registro previo, aceptar si el OS acepta

  if (!verified) {
    throw new Error('Credencial no reconocida. Registra tu Passkey primero.');
  }

  return { verified: true, did };
}
