# Etapa 1: Construcción
FROM rust:latest AS builder

WORKDIR /usr/src/app

# Copiar configuración del workspace
COPY Cargo.toml Cargo.lock ./

# Copiar el código fuente de todos los paquetes
COPY axiom-core ./axiom-core
COPY pdp-server ./pdp-server
COPY axiom-p2p ./axiom-p2p
COPY axiom-ingestor ./axiom-ingestor
COPY axiom-analytics ./axiom-analytics
COPY axiom-node ./axiom-node
COPY regorus-local ./regorus-local

# Compilar en modo release
RUN cargo build --release -p axiom-node

# Etapa 2: Imagen mínima distroless
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# Copiar binario compilado de la etapa builder
COPY --from=builder /usr/src/app/target/release/axiom-node .

# Copiar políticas de Rego si existen o se leen relativas
# El código asume "../axiom-core/policies/zero_trust.rego", vamos a replicar esa estructura.
# En distroless no hay `mkdir`, pero Docker COPY crea las carpetas si no existen.
COPY axiom-core/policies/zero_trust.rego /axiom-core/policies/

# Copiar el frontend compilado
COPY frontend/dist /app/frontend/dist

# Exponer el puerto del servidor HTTP y P2P
EXPOSE 3000

ENV PORT=3000

# Punto de entrada
CMD ["./axiom-node"]
