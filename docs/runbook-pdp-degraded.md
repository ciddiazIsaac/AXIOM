# Runbook: PDP en Modo Degradado o Pánico

## Descripción
Este runbook detalla los procedimientos de respuesta cuando el Motor Zero Trust (PDP) de AXIOM entra en Modo Degradado o Modo Pánico. 

El PDP envía asíncronamente eventos de auditoría a Redis. Si Redis falla, el PDP amortigua los eventos localmente (SQLite en `/audit/audit_buffer.db`).

## Estados
- **Modo Degradado**: Redis inalcanzable. El tráfico se sigue permitiendo (Fail-Open), los eventos se guardan en buffer.
- **Modo Pánico**: 10,000 eventos en buffer, 5 minutos de desconexión continua de Redis, o disco PVC lleno. El PDP retorna `Deny` (Fail-Closed) para *todas* las peticiones para evitar riesgo de pérdida de auditoría o ataques de evasión.

## Alertas
- `AxiomDegradedModeActive`: Se dispara cuando el nodo lleva más de 1 minuto en Modo Degradado.
- `AxiomAuditPanicMode`: Se dispara cuando el buffer local llega a su límite y el sistema deniega todo.

## Diagnóstico Inicial
1. **Verificar el estado de Redis**:
   ```bash
   kubectl exec -it deployment/redis-sentinel -- redis-cli -p 26380 ping
   ```
2. **Revisar métricas y logs del PDP**:
   ```bash
   kubectl logs statefulset/axiom-node | grep -i panic
   kubectl logs statefulset/axiom-node | grep -i redis
   ```
3. **Comprobar espacio del PVC** (Modo Pánico por disco lleno):
   ```bash
   kubectl exec -it statefulset/axiom-node -- df -h /audit
   ```

## Resolución
### 1. Restaurar conexión a Redis
La mayoría de los incidentes se resuelven restaurando la disponibilidad de Redis. El `AuditSpooler` tiene un mecanismo de histéresis: una vez reconectado a Redis de forma estable (30 segundos seguidos), drenará automáticamente el SQLite hacia Redis Streams (batching), y saldrá del Modo Pánico/Degradado cuando el buffer baje de los 2,000 eventos.

### 2. Aumento de Capacidad del Buffer (Emergencia)
Si Redis está caído por un largo periodo y el negocio requiere reabrir el acceso (y asumir el riesgo de pérdida si el disco se daña):
1. Ampliar el PVC `audit-volume` en K8s.
2. Modificar temporalmente el umbral de eventos (si está configurado por ENV) y reiniciar los pods.

### 3. Recuperación de registros de denegación en pánico
Mientras estuvo en Modo Pánico, las denegaciones se aislaron en `/audit/panic_denials.ndjson`.
Extraiga este fichero para análisis post-mortem de impacto a usuarios:
```bash
kubectl exec -it axiom-node-0 -- cat /audit/panic_denials.ndjson > local_panic_denials.ndjson
```
Comunique a los usuarios afectados basándose en el campo `user_did` y `session_id`.

## Post-mortem
- Documentar el tiempo de indisponibilidad.
- Listar los `session_id` denegados erróneamente debido al modo pánico.
- Ajustar capacidad o umbrales según el rendimiento observado.
