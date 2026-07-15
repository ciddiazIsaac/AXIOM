# Runbook: TLS en Tránsito — Redis y ClickHouse (AXIOM)

> **Scope**: Redis (Sentinel + réplicas, puerto 6380) y ClickHouse (HTTPS, puerto 8443)  
> **CA**: CA interna namespace-scoped gestionada por cert-manager  
> **Fuera de scope**: TLS en `/v1/evaluate` (ingress), mTLS P2P/libp2p

---

## 1. Arquitectura de Certificados

```
cert-manager Issuer: axiom-ca-issuer (namespace-scoped)
  └─ axiom-ca-secret  (CA raíz interna, ~5 años)
       ├─ redis-tls-secret      (90 días, auto-renovado 30 días antes)
       └─ clickhouse-tls-secret (90 días, auto-renovado 30 días antes)
```

Todos los certs se almacenan como Kubernetes Secrets. cert-manager los renueva automáticamente; **no se requiere intervención manual para la rotación de certs de hoja**.

---

## 2. Rotación Automática (certs de hoja)

cert-manager renueva los Certificates antes de que expiren:

| Recurso | `duration` | `renewBefore` | Renovación |
|---|---|---|---|
| CA interna (`axiom-ca`) | 5 años | 1 año | **Manual** (ver §4) |
| `redis-tls` | 90 días | 30 días | **Automática** |
| `clickhouse-tls` | 90 días | 30 días | **Automática** |

Cuando cert-manager renueva un Secret, Kubernetes lo actualiza en disco (el volumen montado). Redis y ClickHouse necesitan un **reload** para cargar el nuevo cert:

```bash
# Forzar rolling restart después de una renovación de cert:
kubectl rollout restart statefulset/redis
kubectl rollout restart deployment/redis-sentinel
kubectl rollout restart statefulset/clickhouse
kubectl rollout restart statefulset/axiom-bootstrap
kubectl rollout restart deployment/axiom-node
```

> [!TIP]
> Puedes automatizar este restart con [stakater/Reloader](https://github.com/stakater/Reloader) anotando los Deployments/StatefulSets con `reloader.stakater.com/auto: "true"`. Así el reload es completamente automático.

---

## 3. Rotación Forzada de un Cert de Hoja

Si necesitas invalidar un cert de hoja inmediatamente (por ejemplo, sospecha de compromiso de la clave privada):

```bash
# 1. Borrar el Secret — cert-manager lo re-emite automáticamente en segundos
kubectl delete secret redis-tls-secret
# o
kubectl delete secret clickhouse-tls-secret

# 2. Verificar que cert-manager emitió el nuevo cert
kubectl get certificate redis-tls -w
# STATUS: Ready = True cuando el nuevo cert está listo

# 3. Rolling restart para cargar el nuevo cert
kubectl rollout restart statefulset/redis
kubectl rollout restart deployment/redis-sentinel
# (o statefulset/clickhouse según corresponda)
```

---

## 4. Rotación del CA (Escenario de Compromiso)

> [!CAUTION]
> Esta operación invalida **todos** los certs de hoja emitidos por la CA comprometida. Planifica una ventana de mantenimiento y ten preparado el rollback (escalar axiom-node a 0 para no recibir tráfico durante el corte).

### Pasos

**Paso 1 — Emitir nueva CA**

```bash
# Crear un Issuer temporal self-signed
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer-new
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: axiom-ca-new
spec:
  isCA: true
  commonName: axiom-internal-ca-v2
  secretName: axiom-ca-secret-new
  duration: 43800h
  renewBefore: 8760h
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer-new
    kind: Issuer
EOF

kubectl wait --for=condition=Ready certificate/axiom-ca-new --timeout=60s
```

**Paso 2 — Crear nuevo Issuer usando la nueva CA**

```bash
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: axiom-ca-issuer-new
spec:
  ca:
    secretName: axiom-ca-secret-new
EOF
```

**Paso 3 — Re-emitir todos los certs de hoja con la nueva CA**

```bash
# Parchear los Certificate resources para apuntar al nuevo Issuer
kubectl patch certificate redis-tls --type=merge \
  -p '{"spec":{"issuerRef":{"name":"axiom-ca-issuer-new"}}}'

kubectl patch certificate clickhouse-tls --type=merge \
  -p '{"spec":{"issuerRef":{"name":"axiom-ca-issuer-new"}}}'

# Forzar re-emisión inmediata borrando los Secrets actuales
kubectl delete secret redis-tls-secret clickhouse-tls-secret

# Esperar a que cert-manager emita los nuevos
kubectl get certificate -w
```

**Paso 4 — Rolling restart de todos los componentes**

```bash
kubectl rollout restart statefulset/redis
kubectl rollout restart deployment/redis-sentinel
kubectl rollout restart statefulset/clickhouse
kubectl rollout restart statefulset/axiom-bootstrap
kubectl rollout restart deployment/axiom-node

# Verificar que todos los pods arrancan correctamente
kubectl get pods -w
```

**Paso 5 — Limpiar la CA comprometida**

```bash
# Solo cuando TODOS los pods estén Running/Ready
kubectl delete issuer axiom-ca-issuer         # issuer viejo
kubectl delete secret axiom-ca-secret         # CA key comprometida — destruir inmediatamente
kubectl delete certificate axiom-ca           # cert viejo

# Renombrar el nuevo issuer al nombre canónico
kubectl patch issuer axiom-ca-issuer-new \
  --type=json -p '[{"op":"replace","path":"/metadata/name","value":"axiom-ca-issuer"}]'
# Nota: el patch de nombre no funciona en K8s; re-crear con el nombre correcto:
kubectl delete issuer axiom-ca-issuer-new
kubectl apply -f k8s/base/cert-manager.yaml   # recrear con el nuevo Secret
```

---

## 5. Verificar que el Tráfico está Cifrado

### tcpdump / ksniff

```bash
# En el nodo donde corre un pod Redis:
# (requiere acceso al nodo o usar ksniff)
kubectl sniff redis-0 -p 6380 -o redis_capture.pcap

# Abrir con Wireshark — debe mostrar TLS handshake, no texto plano
# Un PING en claro aparecería como "*1\r\n$4\r\nPING\r\n"
# Con TLS solo verás bytes cifrados (TLS Record Layer)
```

### Verificar certificado del servidor

```bash
# Desde dentro del cluster (pod debug)
kubectl run tls-check --image=alpine --rm -it -- sh

# Dentro del pod:
apk add openssl
# Redis:
openssl s_client -connect redis-master:6380 -CAfile /path/to/ca.crt
# ClickHouse:
openssl s_client -connect clickhouse:8443 -CAfile /path/to/ca.crt
# Debe mostrar: Verify return code: 0 (ok)
```

---

## 6. Probar Rechazo de Cert Inválido (Pod Intruso)

```bash
# Lanzar un pod sin acceso al CA cert
kubectl run intruder --image=curlimages/curl --rm -it \
  -- curl https://clickhouse:8443/ping
# Resultado esperado: SSL certificate problem: unable to get local issuer certificate
# (conexión rechazada — no se puede verificar el servidor)

# Probar sin TLS al puerto antiguo (debe estar cerrado por NetworkPolicy)
kubectl run intruder --image=redis:7.2-alpine --rm -it \
  -- redis-cli -h redis-master -p 6379 ping
# Resultado esperado: Could not connect to Redis — puerto cerrado
```

---

## 7. Verificar Healthchecks Post-Rotación

```bash
# Redis pods (debe mostrar READY con los probes TLS)
kubectl get pods -l app=redis
kubectl describe pod redis-0 | grep -A5 "Readiness"

# ClickHouse pods (probe via curl --cacert)
kubectl get pods -l app=clickhouse
kubectl describe pod clickhouse-0 | grep -A5 "Readiness"

# Todos los pods de la aplicación
kubectl get pods -l app=axiom-node
kubectl get pods -l app=axiom-bootstrap
```

---

## 8. Contactos y Escalación

| Rol | Responsabilidad |
|---|---|
| Platform / SRE | Rotación del CA, aplicar k8s/base/cert-manager.yaml |
| Dev Backend | Actualizar Cargo.toml features si se cambia el stack TLS |
| Security | Validar la CA comprometida, notificar a partes afectadas |

---

*Última actualización: generado durante implementación TLS en tránsito (ticket Redis+ClickHouse TLS).*
