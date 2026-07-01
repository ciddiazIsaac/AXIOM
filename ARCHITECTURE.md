# AXIOM Architecture

El proyecto AXIOM se compone de un monolito modular diseñado bajo un enfoque "Shared-Nothing" que orquesta distintos subsistemas de forma concurrente, usando `tokio::spawn`.

## Subsistemas Principales

1. **Policy Decision Point (PDP)**
   - Un motor embebido que interpreta políticas `.rego` mediante `regorus`.
   - Ofrece el endpoint REST `/v1/evaluate`.
   - Extrae métricas clave para Prometheus (`pdp_decision_total`, `pdp_latency_seconds`).
   
2. **Sistema de Auditoría & Ingesta**
   - Las decisiones se escriben de manera asíncrona a `Redis Streams` para no penalizar la latencia HTTP.
   - Un worker secundario (Ingestor) consume en lotes y deposita los datos de telemetría en **ClickHouse**.
   
3. **Módulo de Analítica y Detección de Anomalías**
   - El endpoint `/v1/anomaly_score` realiza consultas OLAP (Online Analytical Processing) a ClickHouse.
   - Analiza el Z-Score basado en un historial en tiempo real sin entrenar modelos pesados, garantizando tiempos de respuesta ultrarrápidos para la validación contextual.
   
4. **Red P2P (Revocaciones con CRDT)**
   - Utiliza `libp2p` y Gossipsub para interconectar múltiples nodos AXIOM.
   - Implementa un CRDT LWW-Register para resolver conflictos en revocaciones descentralizadas, prescindiendo de una Blockchain central o lenta.

## Elecciones Arquitectónicas (ADRs)
Para mayor contexto, revisa:
- [001: CRDT sobre Blockchain](docs/adr/001-crdt-over-blockchain.md)
- [002: ClickHouse sobre Elasticsearch](docs/adr/002-clickhouse-over-elasticsearch.md)
- [003: Endpoint de anomalías estadístico sobre ML](docs/adr/003-statistical-anomaly-over-ml.md)
