//! Contenedor de bytes con borrado seguro garantizado.
//!
//! `SecureBytes` wrappea un `Vec<u8>` con `Zeroize` y `ZeroizeOnDrop`,
//! asegurando que el contenido sensible (claves privadas, secretos compartidos)
//! se sobreescriba con ceros cuando el valor es dropeado o cuando se llama
//! explícitamente a `zeroize()`.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Buffer de bytes con borrado seguro garantizado al salir de scope.
///
/// Úsalo para almacenar cualquier material criptográfico sensible que
/// eventualmente puedas necesitar como slice de bytes raw.
///
/// # Garantías de Seguridad
/// - Implementa `ZeroizeOnDrop`: la memoria se sobreescribe con ceros en `Drop`
/// - No implementa `Clone` — previene copias accidentales de material sensible
/// - No implementa `Debug` con contenido — previene logging de claves privadas
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    /// Crea un nuevo `SecureBytes` desde un vector de bytes.
    ///
    /// El vector será zerizado al hacer drop de este objeto.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Acceso de solo lectura al contenido en bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Longitud del buffer en bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Retorna `true` si el buffer está vacío.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `Debug` muestra `[REDACTED]` — nunca el contenido real.
impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED {} bytes])", self.0.len())
    }
}

/// `Display` también redactado.
impl std::fmt::Display for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// SecureBytes NO implementa Clone intencionalmente.
// SecureBytes NO implementa Serialize intencionalmente.
// SecureBytes NO implementa PartialEq intencionalmente (evita timing attacks via ==).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_bytes_debug_is_redacted() {
        let secret = SecureBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug_str = format!("{:?}", secret);
        // NUNCA debe aparecer el contenido real
        assert!(!debug_str.contains("DE"));
        assert!(!debug_str.contains("AD"));
        assert!(!debug_str.contains("BE"));
        assert!(!debug_str.contains("EF"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn secure_bytes_display_is_redacted() {
        let secret = SecureBytes::new(vec![0x01, 0x02, 0x03]);
        let display_str = format!("{}", secret);
        assert_eq!(display_str, "[REDACTED]");
    }

    #[test]
    fn secure_bytes_len_works() {
        let sb = SecureBytes::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(sb.len(), 5);
        assert!(!sb.is_empty());
    }

    #[test]
    fn secure_bytes_empty() {
        let sb = SecureBytes::new(vec![]);
        assert!(sb.is_empty());
        assert_eq!(sb.len(), 0);
    }
}
