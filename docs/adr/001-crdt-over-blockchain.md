# ADR 001: CRDT sobre Blockchain para Revocación

## Contexto
El sistema AXIOM requiere propagar la revocación de acceso o credenciales a lo largo de un ecosistema distribuido (nodos Zero Trust) de la forma más rápida y resistente a particiones posible. Las blockchains ofrecen alta inmutabilidad pero conllevan altos costos de latencia (consenso PBFT o PoW/PoS) y consumo de recursos.

## Decisión
Hemos decidido implementar una red P2P basada en Gossipsub combinada con CRDTs (Conflict-free Replicated Data Types), específicamente un *Last-Writer-Wins Register* (LWW-Register).

## Razones
1. **Latencia Sub-milisegundo**: Las revocaciones son críticas y requieren bloqueo inmediato; no podemos esperar bloques de X segundos.
2. **Disponibilidad Total**: Tolerancia nativa a la partición de la red (CAP theorem - elegimos AP para propagación). El CRDT converge matemáticamente sin coordinación central.
3. **Simplicidad Arquitectónica**: No necesitamos un Ledger distribuido complejo con Smart Contracts para simplemente almacenar un estado de booleano `is_revoked`.

## Consecuencias
- Pérdida de "ordenamiento estricto global", lo cual es un compromiso aceptable siempre y cuando se respete el timestamp de la revocación final (LWW).
