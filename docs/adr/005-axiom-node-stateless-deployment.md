# ADR-005: axiom-node como Deployment stateless con emptyDir (vs StatefulSet con PVC)

Date: 2026-07-10

## Status

Accepted

---

## Contexto

`axiom-node` es el proceso worker que evalúa políticas Zero Trust (`/v1/evaluate`) y
participa en la red P2P de gossip de revocaciones. Internamente arranca un
`RevocationCrdt` (Automerge) que abre un archivo SQLite en `/data/crdt_{hostname}.db`
para persistir su estado local entre reinicios.

Esto crea una aparente contradicción con los `axiom-bootstrap` (StatefulSet + PVC):

- **`axiom-bootstrap`**: StatefulSet, `volumeClaimTemplates` (1 Gi PVC), `CRDT_DB_PATH`
  apuntando al PVC → estado CRDT persiste entre reinicios. ✅
- **`axiom-node`**: Deployment, `emptyDir: {}` → estado CRDT se pierde al reiniciar.

La pregunta es si la segunda opción es un descuido o una decisión.

---

## Evidencia técnica que resuelve la contradicción

El protocolo P2P tiene un mecanismo de resincronización **diseñado a propósito**,
no un efecto secundario accidental. Las referencias exactas al código:

### 1. `needs_sync: bool` — flag de arranque en frío

```rust
// axiom-p2p/src/node.rs:84
needs_sync: true,  // Al arrancar, necesitamos sync
```

Seteado a `true` en cada `ValidatorNode::new()`. El nodo sabe que no tiene estado
al arrancar y debe pedirlo.

### 2. `request_full_sync()` — disparado al descubrir el primer peer

```rust
// axiom-p2p/src/node.rs:189 (evento mDNS)
if self.needs_sync && discovered_any {
    self.request_full_sync();
}

// axiom-p2p/src/node.rs:211 (evento Identify)
if self.needs_sync {
    self.request_full_sync();
}
```

En cuanto el nodo descubre un peer (via mDNS local o Identify en las dial addresses
configuradas), publica `GossipPayload::SyncRequest` en el topic
`"axiom/revocations/1.0.0"`.

### 3. El handshake SyncRequest → SyncResponse

```rust
// axiom-p2p/src/node.rs:344-372 (handle_gossipsub_message)
Ok(GossipPayload::SyncRequest) => {
    let full_state = self.crdt.save_full();           // automerge serializado
    let response = GossipPayload::SyncResponse(full_state);
    self.publish_payload(&response);
}
Ok(GossipPayload::SyncResponse(full_bytes)) => {
    self.crdt.merge_full(&full_bytes).await;
    self.needs_sync = false;                          // sync completado
}
```

Cualquier bootnode que recibe el `SyncRequest` responde con el estado completo
(`AutoCommit::save()`). El worker lo fusiona (`AutoCommit::merge()`) y baja el flag.
Automerge garantiza convergencia idempotente sin importar el orden.

### 4. Los bootnodes son la fuente autoritativa

Los `axiom-bootstrap` están en StatefulSet + PVC precisamente porque son la fuente
de verdad del CRDT. Tienen PeerId estable (clave ed25519 en Secret) para que otros
nodos los puedan localizar de forma determinista al arrancar.

Los workers no necesitan PeerId estable: el Kademlia DHT y mDNS los redescubren
automáticamente. Forzar PeerId estable en workers no añade valor.

---

## Decisión

Mantener `axiom-node` como **Deployment con `emptyDir: {}`**.

La arquitectura es:
```
axiom-bootstrap (StatefulSet + PVC)  ← fuente autoritativa del CRDT
         │  SyncResponse (estado completo)
         ▼
axiom-node (Deployment + emptyDir)   ← cliente del gossip, stateless por diseño
         │  SyncRequest al arrancar
         └─ needs_sync = true → request_full_sync() → merge_full() → needs_sync = false
```

---

## Alternativa rechazada: StatefulSet + PVC para axiom-node

**Opción B** implicaría:
- `volumeClaimTemplates` por cada réplica (N pods × 1 Gi PVC)
- `PodManagementPolicy: OrderedReady` (deploys más lentos)
- `storageClass` requerida en el cluster de staging/prod
- Escalar horizontalmente pasa de `kubectl scale deployment --replicas=N` a
  aprovisionar PVCs nuevos → mayor fricción operativa

**Beneficio neto**: eliminar los segundos de resync al reiniciar un pod.

**Conclusión**: el costo operativo supera el beneficio en el rango actual de
uso. La Opción B se activa solo si la Condición de Revisión se dispara (ver abajo).

---

## Consecuencias

### Pros
- Rolling updates simples, sin `PodManagementPolicy`
- `kubectl scale deployment axiom-node --replicas=N` sin fricción
- No requiere `storageClass` para los workers (solo para bootstrap y Redis/ClickHouse)
- Coherente con el uso documentado en `docker-compose.yml` (`--scale axiom-node=50`)

### Contras y mitigaciones
- **Latencia de arranque**: cada reinicio de pod dispara un SyncRequest/SyncResponse.
  El tiempo depende del tamaño del documento Automerge serializado (`save_full()`).
  Con datasets pequeños/medianos (<100k revocaciones) es sub-segundo en LAN.
  **No medido en el peor caso** (ver Validación Pendiente).
- **Ventana sin datos**: el pod no sirve `/v1/evaluate` con datos actualizados hasta
  que `merge_full()` termina. Esto está mitigado por la `readinessProbe` en `/metrics`
  que retiene tráfico hasta que el pod esté `Ready` — pero `merge_full()` actualiza
  el CRDT en memoria, no expone un endpoint separado de "sync completo". El pod
  podría entrar en `Ready` antes de terminar el sync si el readinessProbe no incluye
  una verificación de `needs_sync`.

  **Mitigación futura**: exponer `/ready` que devuelva 503 mientras `needs_sync == true`.

---

## Validación pendiente

> ⚠️ Esta decisión es correcta en diseño pero **no verificada en el peor caso**.
>
> **Pregunta abierta**: ¿cuánto tarda `request_full_sync()` → `merge_full()` cuando
> el dataset de revocaciones tiene miles o millones de entradas?
>
> El tamaño del payload es `automerge::AutoCommit::save()`. Automerge almacena el
> historial de cambios (no solo el estado actual), así que el documento crece con
> el número de operaciones, no solo con el número de entradas únicas.
>
> **Medición requerida antes de ir a producción con carga real**:
> ```rust
> // En crdt.rs o en un benchmark:
> let bytes = crdt.save_full();
> tracing::info!("save_full() size: {} bytes ({} KB)", bytes.len(), bytes.len() / 1024);
> ```
>
> **Condición de revisión de esta decisión**:
> Si `save_full()` supera ~10 MB, o si el tiempo de resync (desde `SyncRequest` enviado
> hasta `needs_sync = false`) supera el SLA de arranque del pod (e.g., 30 s), revisar
> migración a StatefulSet + PVC para workers.

---

## Referencias

- [axiom-p2p/src/node.rs](../../axiom-p2p/src/node.rs) — `needs_sync`, `request_full_sync()`, handshake SyncRequest/SyncResponse
- [axiom-p2p/src/crdt.rs](../../axiom-p2p/src/crdt.rs) — `save_full()`, `merge_full()`
- [k8s/base/axiom-node.yaml](../../k8s/base/axiom-node.yaml) — manifiesto con `emptyDir`
- [k8s/base/axiom-bootstrap.yaml](../../k8s/base/axiom-bootstrap.yaml) — StatefulSet con PVC (fuente autoritativa)
- [ADR-001](001-crdt-over-blockchain.md) — decisión original de CRDT sobre blockchain
- [ADR-004](004-crdt-sqlite-persistence.md) — persistencia local SQLite + Automerge
