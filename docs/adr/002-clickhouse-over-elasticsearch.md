# ADR 002: ClickHouse sobre Elasticsearch para Auditoría Analítica

## Contexto
Todos los eventos de acceso y evaluaciones del motor OPA deben persistirse para proveer una capa de auditoría y servir como base para calcular el *Anomaly Score* del usuario en tiempo real.

## Decisión
Seleccionamos **ClickHouse** (almacenamiento en columnas OLAP) en lugar de un motor de búsqueda de texto completo como **Elasticsearch** u OpenSearch.

## Razones
1. **Ingesta Batch Masiva**: AXIOM usa Redis Streams como buffer y ClickHouse brilla insertando enormes lotes asíncronos con ínfima carga de CPU.
2. **Queries Analíticas (Z-Score)**: Calcular varianzas y percentiles (p99) en tiempo real es nativo y órdenes de magnitud más rápido en ClickHouse debido a la vectorización.
3. **Eficiencia en Almacenamiento**: Al estar orientado a columnas, la compresión de millones de auditorías reduce agresivamente los costos de disco.

## Consecuencias
- La búsqueda difusa (*fuzzy matching*) de texto en los campos de contexto no es tan potente como en Elasticsearch, pero no es un requisito del MVP.
