# ADR 006: Estrategia de Conectividad para Redis HA (Sentinel)

## Contexto

El stack de AXIOM en producción cuenta con un cluster Redis de Alta Disponibilidad desplegado mediante StatefulSet (1 Master, 2 Réplicas) y 3 Sentinels que gestionan el failover.
Por diseño de Sentinel, la IP del master puede cambiar sin previo aviso si el master original muere y una réplica es promovida a master.

Teníamos el problema de que los servicios (como `axiom-ingestor`, `axiom-core` y `axiom-node`) estaban intentando conectarse a un host fijo (`redis:6379`), el cual no correspondía con ningún Service de Kubernetes real, causando fallos de conexión. Además, conectarse de manera estática al servicio `redis-master:6379` (el "Camino corto") implica que tras un failover, las conexiones activas se caen y, sin un manejo dinámico del reconectado, los pods clientes de Redis podrían quedar permanentemente rotos o requerir reinicios manuales para resolver el nuevo endpoint.

## Decisión

Hemos decidido optar por la integración nativa y dinámica de Redis Sentinel ("Camino correcto") en los componentes críticos de Rust (`axiom-ingestor` y `axiom-core/audit.rs`).

1. Se añadió la feature `sentinel` al crate `redis` en las dependencias.
2. Se reemplazó el uso básico de `redis::Client::open()` por lógica que:
   - Detecta el esquema `redis+sentinel://`.
   - Inicializa dinámicamente un `redis::sentinel::SentinelClient`.
   - Obtiene la conexión al master en tiempo real al arrancar el servicio.
3. Se implementó un bucle de **auto-reconexión** frente a desconexiones (`e.is_connection_dropped() || e.is_io_error()`) que, al fallar una operación de streams (`xadd` o `xreadgroup`), vuelve a invocar `sentinel.get_async_connection()` para descubrir el nuevo master de manera transparente, sin requerir reinicios en Kubernetes.
4. Las variables de entorno `REDIS_URL` en los manifiestos de Kubernetes de `axiom-node` y `axiom-bootstrap` se actualizaron a `redis+sentinel://redis-sentinel:26379/mymaster/0`.
5. Se modificó el liveness probe (`/health`) en `axiom-node` para comprobar de manera robusta la accesibilidad de Redis y ClickHouse.
6. **Excepción**: Para el componente en Python (`axiom-analytics-ml`), hemos asignado temporalmente la ruta estática `redis://redis-master:6379/` debido a que la reescritura de su loop de streams a nivel de Python (usando la API Sentinel) excede el scope crítico actual, asumiendo un potencial reinicio del pod si ocurriese un failover de Redis.

## Consecuencias

- **Positivas:** 
  - La infraestructura Rust (nodos AXIOM) ahora toleran caídas de Redis Master y rotaciones sin interrupciones del servicio a largo plazo, logrando una verdadera resiliencia.
  - El sistema detecta failovers en ~2-5 segundos y se reconecta automáticamente sin intervención manual.
  - La latencia extra en el establecimiento inicial de la conexión al pasar por los Sentinels es imperceptible en tiempo de ejecución.
  
- **Negativas:** 
  - Incremento en la complejidad del código del ingestor y la cola de auditoría (el uso directo de `SentinelClient` requiere re-adquirir conexiones manualmente).
  - El servicio de Machine Learning (`axiom-analytics-ml`) es vulnerable temporalmente a failovers y requerirá reinicio (o delegarlo al scheduler de K8s tras fallar el check).
