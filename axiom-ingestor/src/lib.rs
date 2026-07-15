//! axiom-ingestor: Consumidor de Redis Streams → ClickHouse
//!
//! Lee eventos de auditoría del stream `axiom:audit:stream` usando
//! XREADGROUP (consumer group `axiom_consumers`) y los inserta en
//! ClickHouse usando su API HTTP nativa.
//!
//! ## Batch inserts
//! En lugar de hacer 1 INSERT por evento, acumula hasta `BATCH_SIZE` eventos
//! (env var, default 1000) y los vuelca en un único INSERT multi-VALUES.
//! Si el buffer lleva más de `FLUSH_INTERVAL_MS` ms sin vaciarse (env var,
//! default 500), se hace un flush anticipado aunque no se haya llenado.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

// ─── Configuración ────────────────────────────────────────────────────────────

const REDIS_STREAM: &str = "axiom:audit:stream";
const CONSUMER_GROUP: &str = "axiom_consumers";
const CONSUMER_NAME: &str = "ingestor-1";
const CLICKHOUSE_TABLE: &str = "audit_events";

/// Número máximo de eventos por batch INSERT (sobreescribible con BATCH_SIZE).
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Intervalo máximo entre flushes en milisegundos (sobreescribible con FLUSH_INTERVAL_MS).
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 500;

// ─── Esquema del evento ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
enum AuditDecision {
    Allow,
    Deny,
    Challenge,
}

impl std::fmt::Display for AuditDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditDecision::Allow => write!(f, "ALLOW"),
            AuditDecision::Deny => write!(f, "DENY"),
            AuditDecision::Challenge => write!(f, "CHALLENGE"),
        }
    }
}

/// Evento de auditoría tal como viene en el stream de Redis.
#[derive(Debug, Deserialize, Clone)]
struct AuditEvent {
    timestamp_ns: u128,
    session_id: String,
    user_did: String,
    resource_hash: String,
    decision: AuditDecision,
    risk_score: f32,
    /// El context_snapshot original es serde_json::Value;
    /// aquí lo aplanamos a Map<String, String> para ClickHouse.
    context_snapshot: serde_json::Value,
    latency_ms: f64,
}

// ─── Conversión de contexto ───────────────────────────────────────────────────

/// Aplana un serde_json::Value de primer nivel a Map(String, String)
/// tal como exige el esquema ClickHouse.
fn flatten_context(val: &serde_json::Value) -> HashMap<String, String> {
    match val.as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| {
                let str_val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.clone(), str_val)
            })
            .collect(),
        None => HashMap::new(),
    }
}

// ─── Formateo SQL ─────────────────────────────────────────────────────────────

/// Formatea el Map(String, String) de ClickHouse como literal SQL:
/// {'key1': 'val1', 'key2': 'val2'}
fn format_ch_map(map: &HashMap<String, String>) -> String {
    if map.is_empty() {
        return "{}".to_string();
    }
    let entries: Vec<String> = map
        .iter()
        .map(|(k, v)| {
            let ek = k.replace('\'', "\\'");
            let ev = v.replace('\'', "\\'");
            format!("'{ek}': '{ev}'")
        })
        .collect();
    format!("{{{}}}", entries.join(", "))
}

/// Genera la tupla VALUES para un evento:
/// (timestamp_ns, 'session_id', 'user_did', 'resource_hash', 'decision', risk_score, {context}, latency_ms)
fn event_to_values_row(event: &AuditEvent) -> String {
    let context_map = flatten_context(&event.context_snapshot);
    let ch_map = format_ch_map(&context_map);
    let decision_str = event.decision.to_string();

    format!(
        "({}, '{}', '{}', '{}', '{}', {}, {}, {})",
        event.timestamp_ns,
        event.session_id.replace('\'', "\\'"),
        event.user_did.replace('\'', "\\'"),
        event.resource_hash.replace('\'', "\\'"),
        decision_str,
        event.risk_score,
        ch_map,
        event.latency_ms,
    )
}

// ─── Inserción batch en ClickHouse ───────────────────────────────────────────

/// Inserta un batch de eventos en ClickHouse con un único INSERT multi-VALUES.
/// Devuelve Ok(()) si el INSERT tuvo éxito.
async fn flush_batch(
    client: &reqwest::Client,
    ch_url: &str,
    events: &[AuditEvent],
) -> anyhow::Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    // Construir el INSERT con todas las filas en un único statement
    let rows: Vec<String> = events.iter().map(event_to_values_row).collect();
    let query = format!(
        "INSERT INTO {CLICKHOUSE_TABLE} \
         (timestamp_ns, session_id, user_did, resource_hash, decision, risk_score, context, latency_ms) \
         VALUES {}",
        rows.join(", ")
    );

    let resp = client.post(ch_url).body(query).send().await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("ClickHouse batch INSERT fallido: {body}"));
    }

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

// ─── Helpers TLS ─────────────────────────────────────────────────────────────

/// Construye un `reqwest::Client` con CA cert custom si CLICKHOUSE_CA_CERT está definido.
/// En dev (sin la variable), devuelve un cliente normal que verificará CAs del sistema.
fn build_http_client(timeout: Duration) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(timeout);

    if let Ok(ca_path) = std::env::var("CLICKHOUSE_CA_CERT") {
        match std::fs::read(&ca_path) {
            Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    builder = builder.add_root_certificate(cert);
                    info!("Ingestor: CA cert de ClickHouse cargado desde {ca_path}");
                }
                Err(e) => warn!("Ingestor: cert PEM inválido en {ca_path}: {e}"),
            },
            Err(e) => warn!("Ingestor: no se pudo leer CLICKHOUSE_CA_CERT={ca_path}: {e}"),
        }
    }

    builder.build().expect("Error construyendo HTTP client")
}

/// Extrae el nodo Sentinel (host:port) y el nombre del master de la URL.
/// Soporta `redis+sentinel://` (plano) y `rediss+sentinel://` (TLS).
fn parse_sentinel_url(redis_url: &str) -> (String, String, bool) {
    let use_tls = redis_url.starts_with("rediss+sentinel://");
    let after_scheme = redis_url
        .trim_start_matches("rediss+sentinel://")
        .trim_start_matches("redis+sentinel://");
    // after_scheme = "host:port/mymaster/0"
    let parts: Vec<&str> = after_scheme.split('/').collect();
    let sentinel_node = parts[0].to_string(); // "host:port"
    let master_name = if parts.len() > 1 && !parts[1].is_empty() {
        parts[1].to_string()
    } else {
        "mymaster".to_string()
    };
    let scheme = if use_tls { "rediss" } else { "redis" };
    (format!("{scheme}://{sentinel_node}"), master_name, use_tls)
}

pub async fn run_ingestor() -> anyhow::Result<()> {
    // Inicializar logging estructurado
    tracing_subscriber::fmt()
        .with_env_filter("axiom_ingestor=info,warn")
        .init();

    // Leer configuración desde variables de entorno
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    let ch_url =
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://127.0.0.1:8123/".to_string());
    let batch_size: usize = std::env::var("BATCH_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BATCH_SIZE);
    let flush_interval_ms: u64 = std::env::var("FLUSH_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_FLUSH_INTERVAL_MS);

    info!("Iniciando axiom-ingestor (batch mode)...");
    info!("Redis: {redis_url}");
    info!("ClickHouse: {ch_url}");
    info!("BATCH_SIZE={batch_size}, FLUSH_INTERVAL_MS={flush_interval_ms}");

    // ── Conectar a Redis ──────────────────────────────────────────────────────
    // Soporta:
    //   redis+sentinel://    — Sentinel sin TLS (dev, docker-compose)
    //   rediss+sentinel://   — Sentinel con TLS (prod, Kubernetes)
    //   redis://             — conexión directa sin TLS
    //   rediss://            — conexión directa con TLS
    let is_sentinel =
        redis_url.starts_with("redis+sentinel://") || redis_url.starts_with("rediss+sentinel://");
    let mut sentinel_client_opt = None;
    let mut redis_client_opt = None;

    let mut redis_con = if is_sentinel {
        let (node_url, master_name, use_tls) = parse_sentinel_url(&redis_url);

        // TlsMode::Secure cuando el esquema es rediss+sentinel://
        let tls_params = if use_tls {
            Some(redis::sentinel::SentinelNodeConnectionInfo {
                tls_mode: Some(redis::TlsMode::Secure),
                redis_connection_info: None,
            })
        } else {
            None
        };

        let mut sentinel_client = redis::sentinel::SentinelClient::build(
            vec![node_url],
            master_name,
            tls_params,
            redis::sentinel::SentinelServerType::Master,
        )?;
        let con = sentinel_client.get_async_connection().await?;
        sentinel_client_opt = Some(sentinel_client);
        con
    } else {
        let redis_client = redis::Client::open(redis_url.as_str())?;
        let con = redis_client.get_multiplexed_async_connection().await?;
        redis_client_opt = Some(redis_client);
        con
    };

    // Crear el consumer group si no existe (MKSTREAM crea el stream si tampoco existe)
    let group_result: redis::RedisResult<()> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(REDIS_STREAM)
        .arg(CONSUMER_GROUP)
        .arg("$") // Solo mensajes nuevos
        .arg("MKSTREAM") // Crea el stream si no existe
        .query_async(&mut redis_con)
        .await;

    match group_result {
        Ok(_) => info!("Consumer group '{CONSUMER_GROUP}' creado."),
        Err(e) if e.to_string().contains("BUSYGROUP") => {
            info!("Consumer group '{CONSUMER_GROUP}' ya existe, continuando.");
        }
        Err(e) => return Err(e.into()),
    }

    // ── Cliente HTTP para ClickHouse (con CA cert si CLICKHOUSE_CA_CERT está definido) ─
    // En prod: CLICKHOUSE_CA_CERT=/tls/clickhouse/ca.crt + CLICKHOUSE_URL=https://...:8443/
    // En dev: sin la variable, verifica CAs del sistema (compatible con http://)
    let http_client = build_http_client(Duration::from_secs(30));

    info!("Escuchando en '{REDIS_STREAM}' (batch_size={batch_size})...");

    // ── Buffer de eventos pendientes de flush ─────────────────────────────────
    let mut event_buffer: Vec<AuditEvent> = Vec::with_capacity(batch_size);
    // IDs de Redis de los eventos en el buffer (para hacer XACK masivo)
    let mut id_buffer: Vec<String> = Vec::with_capacity(batch_size);
    let mut last_flush = Instant::now();
    let flush_interval = Duration::from_millis(flush_interval_ms);

    // ── Bucle principal de consumo ────────────────────────────────────────────
    loop {
        // XREADGROUP: leer hasta 500 mensajes por iteración para llenar el buffer rápido
        let results: redis::RedisResult<redis::streams::StreamReadReply> = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(CONSUMER_GROUP)
            .arg(CONSUMER_NAME)
            .arg("COUNT")
            .arg(500)
            .arg("BLOCK")
            .arg(200) // ms – timeout corto para poder flushear por tiempo aunque no lleguen mensajes
            .arg("STREAMS")
            .arg(REDIS_STREAM)
            .arg(">") // Solo mensajes no entregados
            .query_async(&mut redis_con)
            .await;

        match &results {
            Err(e) if e.is_connection_dropped() || e.is_io_error() => {
                warn!("Conexión con Redis perdida: {e}. Reconectando...");
                let mut reconnected = false;
                if let Some(sentinel) = sentinel_client_opt.as_mut() {
                    if let Ok(con) = sentinel.get_async_connection().await {
                        info!("Reconexión Sentinel exitosa.");
                        redis_con = con;
                        reconnected = true;
                    }
                } else if let Some(client) = redis_client_opt.as_ref() {
                    if let Ok(con) = client.get_multiplexed_async_connection().await {
                        info!("Reconexión Client exitosa.");
                        redis_con = con;
                        reconnected = true;
                    }
                }

                if !reconnected {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                continue;
            }
            _ => {}
        }

        // Procesar los mensajes recibidos (puede ser 0 si expiró el BLOCK timeout)
        if let Ok(reply) = results {
            for stream_key in reply.keys {
                for entry in stream_key.ids {
                    let msg_id = entry.id.clone();

                    // Extraer el campo "data" del mensaje
                    let Some(raw_data) = entry.map.get("data") else {
                        warn!("Mensaje {msg_id} sin campo 'data', haciendo ACK y saltando.");
                        let _: redis::RedisResult<()> = redis_con
                            .xack(REDIS_STREAM, CONSUMER_GROUP, &[&msg_id])
                            .await;
                        continue;
                    };

                    // Deserializar el JSON del evento
                    let json_str = match raw_data {
                        redis::Value::BulkString(bytes) => {
                            String::from_utf8_lossy(bytes).to_string()
                        }
                        other => format!("{other:?}"),
                    };

                    let event: AuditEvent = match serde_json::from_str(&json_str) {
                        Ok(e) => e,
                        Err(e) => {
                            error!("Fallo al parsear evento {msg_id}: {e}. Raw: {json_str}");
                            // ACK para no bloquear el stream con mensajes corruptos
                            let _: redis::RedisResult<()> = redis_con
                                .xack(REDIS_STREAM, CONSUMER_GROUP, &[&msg_id])
                                .await;
                            continue;
                        }
                    };

                    event_buffer.push(event);
                    id_buffer.push(msg_id);
                }
            }
        }

        // ── Decidir si hay que flushear ───────────────────────────────────────
        let should_flush_size = event_buffer.len() >= batch_size;
        let should_flush_time = !event_buffer.is_empty() && last_flush.elapsed() >= flush_interval;

        if should_flush_size || should_flush_time {
            let n = event_buffer.len();
            let reason = if should_flush_size { "size" } else { "timeout" };

            match flush_batch(&http_client, &ch_url, &event_buffer).await {
                Ok(()) => {
                    info!(
                        batch_size = n,
                        flush_reason = reason,
                        "Batch de {n} eventos insertado en ClickHouse."
                    );
                    // XACK masivo: confirmar todos los mensajes del batch de una vez
                    let ids: Vec<&str> = id_buffer.iter().map(String::as_str).collect();
                    let ack_result: redis::RedisResult<i64> =
                        redis_con.xack(REDIS_STREAM, CONSUMER_GROUP, &ids).await;
                    if let Err(e) = ack_result {
                        error!("Fallo en XACK masivo de {n} mensajes: {e}");
                    }
                    // Vaciar buffers tras flush exitoso
                    event_buffer.clear();
                    id_buffer.clear();
                    last_flush = Instant::now();
                }
                Err(e) => {
                    // NO limpiamos el buffer: reintentaremos en el próximo ciclo
                    error!(
                        batch_size = n,
                        "Fallo al insertar batch de {n} eventos en ClickHouse: {e}. \
                         Se reintentará en el próximo ciclo."
                    );
                }
            }
        }
    }
}
