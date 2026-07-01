# AXIOM: Zero Trust Architecture

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

AXIOM es un sistema de control de acceso Zero Trust de alto rendimiento diseñado para entornos distribuidos. Integra la evaluación de políticas mediante OPA (Rego), almacenamiento analítico con ClickHouse, y una red P2P (Gossip) apoyada en CRDTs para una propagación veloz de revocaciones.

## 🚀 Arquitectura

```mermaid
graph TD
    A[Usuario / SDK] -->|Autentica & Solicita| B(AXIOM Node - PDP)
    B -->|Evalúa Regla| C{OPA Engine}
    C -->|Permite / Deniega| B
    B -->|Spool Evento| D[(Redis Streams)]
    D -->|Ingesta Batch| E[(ClickHouse)]
    B -->|Consulta Anomalía| E
    B -->|Gossip Revocación| F((Red P2P CRDT))
    G[Grafana] -->|Scrape / Consulta| B
    G -->|Consulta SQL| E
```

## 🎥 Demostración (SPA)

![AXIOM Frontend Demo](/frontend_demo.gif)

## 🛠️ Instalación y Uso

Instrucciones literales para levantar el proyecto:

1. Clona el repositorio.
2. Ejecuta:
   ```bash
   docker-compose up -d --build
   ```
3. Ve a [http://localhost:3000](http://localhost:3000) para ver la SPA en funcionamiento.
4. Ve a [http://localhost:3001](http://localhost:3001) para explorar el Dashboard de Grafana con métricas en tiempo real.

Para ejecutar una prueba de estrés (1000 RPS):
```bash
python load_test.py
```

## 📚 Documentación

Revisa la [Arquitectura](ARCHITECTURE.md) detallada y nuestros [Architecture Decision Records (ADRs)](docs/adr/).
