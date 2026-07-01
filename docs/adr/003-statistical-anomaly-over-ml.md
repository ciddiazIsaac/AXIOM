# ADR 003: Endpoint Estadístico sobre ML Computacional

## Contexto
Para el `Anomaly Score`, requerimos que el sistema responda al `PDP` en menos de 10ms. Inicialmente se consideró utilizar modelos de Machine Learning (Isolation Forests o Autoencoders) invocados vía API.

## Decisión
Implementamos un enfoque estadístico directo calculado en la base de datos (Z-Score y Percentiles) en lugar de una inferencia de ML para el MVP.

## Razones
1. **Latencia**: Un modelo de ML en Python añade un cuello de botella HTTP de latencia inaceptable para autorizaciones síncronas de Zero Trust.
2. **Explicabilidad**: El Z-Score (Desviaciones estándar de la media) es transparente, fácil de depurar en los logs, y cumple normativas estrictas de auditoría.
3. **Cero Complejidad de Infraestructura**: No se necesitan GPUs, servidores dedicados como Triton/TorchServe ni pipelines de reentrenamiento.

## Consecuencias
- Los atacantes con patrones no lineales podrían evadir esta estadística básica si se mantienen justo en el borde de la desviación estándar.
- **Plan de Migración:** Cuando existan los recursos, se implementará un modelo de ML entrenado offline, pero compilado a WebAssembly (Wasm) o embebido en Rust (Tract/ONNX) para mantener tiempos sub-milisegundo en la misma capa de la aplicación.
