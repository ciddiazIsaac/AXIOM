# ADR 005: Comportamiento explícito del PDP ante caída de Redis

## Contexto
El ZeroTrustEngine evalúa políticas (Rego) en memoria y decide autorizaciones sin consultar a Redis. Sin embargo, los eventos de auditoría (AuditEvents) son enviados a Redis Streams de manera asíncrona para no penalizar la latencia ("Fire and forget").
El problema surge cuando Redis deja de estar disponible. ¿Qué sucede con las peticiones legítimas (Fail-Open vs Fail-Closed)? ¿Dónde se almacenan los eventos temporalmente? ¿Cómo evitamos perder eventos o agotar recursos locales?

## Decisión
Adoptamos un modelo híbrido escalonado (Normal → Degradado → Pánico) para el comportamiento de auditoría del PDP:

1. **Modo Normal**: 
   - El PDP evalúa políticas.
   - El `AuditSpooler` inserta los eventos asíncronamente en Redis Streams.

2. **Modo Degradado (Fail-Open)**: 
   - **Condición**: Redis inalcanzable.
   - **Comportamiento**: El PDP continúa evaluando y permitiendo tráfico legítimo (Fail-Open). 
   - **Almacenamiento**: El `AuditSpooler` desvía los eventos a una base de datos local SQLite (`/audit/audit_buffer.db`). 
   - **Aislamiento**: Esta DB utiliza un archivo y conexión independiente al CRDT, aislando los bloqueos de escritura y evitando contiendas. Se monta en un PVC dedicado en `/audit` para evitar que otros procesos saturen el espacio de disco e impidan persistir la auditoría.

3. **Modo Pánico (Fail-Closed)**: 
   - **Condición**: Se superan 10,000 eventos en el buffer local SQLite, O se registran 5 minutos continuos sin conexión a Redis, O el volumen de auditoría se queda sin espacio libre (lo que ocurra primero).
   - **Comportamiento**: El PDP entra en estado de pánico y rechaza *todo* el tráfico por seguridad, retornando `AuditDecision::Deny`.
   - **Registro de denegaciones**: Las decisiones `Deny` generadas intrínsecamente por el Modo Pánico se registrarán en `audit_buffer.db` con el flag `denied_by_panic_mode: true`.

4. **Histéresis (Recuperación)**:
   - El sistema solo retornará al Modo Normal o Degradado si:
     - El buffer local se vacía por debajo de los 2,000 eventos.
     - Y la conexión a Redis reporta estabilidad continua por al menos 30 segundos.
   - Esto evita un efecto "flapping" de la red o intermitencias que saturen el PDP con constantes caídas y reconexiones.

5. **Aislamiento y Tamaño del PVC**:
   - Se utilizará un PVC dedicado para el buffer.
   - **Cálculo**: El tamaño promedio de un `AuditEvent` es de 500-1000 bytes. `10,000 eventos × 1000 bytes = 10 MB`. Usaremos un margen de seguridad de 3x, pero los aprovisionadores K8s por lo general recomiendan `1Gi` como mínimo manejable, lo que sobra para albergar fluctuaciones en el tamaño del payload y denegaciones.

6. **Métricas**:
   - `axiom_degraded_mode_active`
   - `axiom_audit_buffer_size`
   - `axiom_audit_buffer_disk_bytes`

## Consecuencias
- **Positivas**: Evitamos perder eventos críticos de auditoría. Mantenemos el SLA para los clientes ante caídas transitorias de infraestructura. Mitigamos el riesgo legal/seguridad cerrando el paso si la caída es prolongada (Fail-Closed).
- **Negativas**: Mayor complejidad lógica en el componente `AuditSpooler`. El `axiom-node` requiere ahora persistencia (PVC) si sufre un reinicio para no perder el buffer temporal de `audit_buffer.db` en medio de un modo degradado.
