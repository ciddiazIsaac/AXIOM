# Etapa 1: Construcción del frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /usr/src/app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Etapa 2: Construcción del backend (Rust)
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

# Etapa 3: Imagen mínima distroless
FROM gcr.io/distroless/cc-debian12
WORKDIR /app

# Copiar binario compilado de la etapa builder
COPY --from=builder /usr/src/app/target/release/axiom-node .

# Copiar políticas de Rego si existen o se leen relativas
# El código asume "../axiom-core/policies/zero_trust.rego"
COPY axiom-core/policies/zero_trust.rego /axiom-core/policies/

# Copiar el frontend compilado desde la etapa frontend-builder
COPY --from=frontend-builder /usr/src/app/dist /app/frontend/dist

# Exponer el puerto del servidor HTTP y P2P
EXPOSE 3000

ENV PORT=3000

# Punto de entrada
CMD ["./axiom-node"]
