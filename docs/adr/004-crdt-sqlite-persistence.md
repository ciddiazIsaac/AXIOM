# 4. CRDT Persistence with SQLite

Date: 2026-07-02

## Status
Accepted

## Context
El estado global de las revocaciones está gestionado por un CRDT (Automerge). Si los nodos no persisten su estado en disco, al reiniciar deben recuperar todo el estado de la red (lo que puede ser lento e ineficiente si la base de datos crece o si hay particiones de red). Necesitábamos un almacenamiento local para que los reinicios fuesen rápidos y seguros.
RocksDB fue considerado, pero debido a la complejidad de compilación en ciertos entornos (requiere Clang/LLVM), decidimos optar por una base de datos más simple pero robusta.

## Decision
Utilizaremos **SQLite** (a través del crate `rusqlite` con el feature `bundled`) para persistir el estado local de Automerge.

El esquema usado será muy simple:
```sql
CREATE TABLE IF NOT EXISTS crdt_state (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL,
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);
```
Insertaremos el estado completo con `key = 'doc_state'`.

En caso de que el archivo SQLite esté corrupto o vacío en el arranque, en lugar de crashear, el nodo registrará un warning y continuará con un CRDT en blanco, recuperando posteriormente el estado mediante el protocolo de Gossip.

## Consequences
* **Pros:** 
  * `rusqlite bundled` funciona "out of the box" en Windows, Linux y macOS sin requerir instalación de dependencias externas en el sistema operativo.
  * SQLite es robusto, transaccional y suficientemente rápido para nuestro caso de uso.
* **Cons (y mitigaciones a futuro):** 
  * La librería `rusqlite` es síncrona. Si hacemos llamadas a la base de datos en el event loop de `tokio` (ej. cuando llega un mensaje de Gossipsub), bloquearemos el thread, impactando el rendimiento asíncrono del nodo.
  * **Mitigación (FASE 2):** En la siguiente fase de optimización, todas las operaciones de disco (particularmente `self.persist()`) deberán envolverse en `tokio::task::spawn_blocking` para no afectar la responsividad de la red P2P.
