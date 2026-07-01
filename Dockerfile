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

# Etapa 2: Imagen mínima
FROM alpine:3.18

# Instalar dependencias dinámicas que rust necesita (como libgcc, libssl si se usa reqwest con openssl, etc.)
# Para compilar puramente estático habria que usar x86_64-unknown-linux-musl pero alpine base requiere glibc/libgcc compat
RUN apk add --no-cache ca-certificates libgcc libstdc++ gcc gcompat

WORKDIR /usr/local/bin

# Copiar binario compilado de la etapa builder
COPY --from=builder /usr/src/app/target/release/axiom-node .

# Copiar políticas de Rego si existen o se leen relativas
# El código asume "../axiom-core/policies/zero_trust.rego", vamos a replicar esa estructura.
RUN mkdir -p /usr/local/axiom-core/policies
COPY axiom-core/policies/zero_trust.rego /usr/local/axiom-core/policies/

# Copiar el frontend compilado
RUN mkdir -p /usr/local/frontend/dist
COPY frontend/dist /usr/local/frontend/dist

# Exponer el puerto del servidor HTTP y P2P (asumiendo que P2P escucha en algún lado)
EXPOSE 3000

ENV PORT=3000

# Punto de entrada
CMD ["./axiom-node"]
