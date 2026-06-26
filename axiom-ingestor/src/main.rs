//! axiom-ingestor: Consumidor de Redis Streams → ClickHouse
//!
//! Lee eventos de auditoría del stream `axiom:audit:stream` usando
//! XREADGROUP (consumer group `axiom_consumers`) y los inserta en
//! ClickHouse usando su API HTTP nativa.

use std::collections::HashMap;
use std::time::Duration;

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

// ─── Configuración ────────────────────────────────────────────────────────────

const REDIS_STREAM: &str = "axiom:audit:stream";
const CONSUMER_GROUP: &str = "axiom_consumers";
const CONSUMER_NAME: &str = "ingestor-1";
const CLICKHOUSE_TABLE: &str = "audit_events";

// ─── Esquema del evento (debe coincidir con audit.rs de axiom-core) ───────────

/// Decisión del PDP, deserializable desde el JSON del stream
#[derive(Debug, Deserialize, Serialize)]
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

/// Evento de auditoría tal como viene en el stream de Redis
#[derive(Debug, Deserialize)]
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

// ─── Inserción en ClickHouse ──────────────────────────────────────────────────

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

/// Inserta un evento en ClickHouse a través de su API HTTP (puerto 8123)
async fn insert_into_clickhouse(
    client: &reqwest::Client,
    ch_url: &str,
    event: &AuditEvent,
) -> anyhow::Result<()> {
    let context_map = flatten_context(&event.context_snapshot);
    let ch_map = format_ch_map(&context_map);
    let decision_str = event.decision.to_string();

    // Usamos la API HTTP de ClickHouse con formato VALUES
    let query = format!(
        "INSERT INTO {CLICKHOUSE_TABLE} \
         (timestamp_ns, session_id, user_did, resource_hash, decision, risk_score, context, latency_ms) \
         VALUES ({}, '{}', '{}', '{}', '{}', {}, {}, {})",
        event.timestamp_ns,
        event.session_id.replace('\'', "\\'"),
        event.user_did.replace('\'', "\\'"),
        event.resource_hash.replace('\'', "\\'"),
        decision_str,
        event.risk_score,
        ch_map,
        event.latency_ms,
    );

    let resp = client
        .post(ch_url)
        .body(query)
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("ClickHouse INSERT fallido: {body}"));
    }

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inicializar logging estructurado
    tracing_subscriber::fmt()
        .with_env_filter("axiom_ingestor=info,warn")
        .init();

    // Leer configuración desde variables de entorno (con valores por defecto para MVP)
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    let ch_url = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8123/".to_string());

    info!("Iniciando axiom-ingestor...");
    info!("Redis: {redis_url}");
    info!("ClickHouse: {ch_url}");

    // ── Conectar a Redis ──────────────────────────────────────────────────────
    let redis_client = redis::Client::open(redis_url.as_str())?;
    let mut redis_con = redis_client.get_multiplexed_async_connection().await?;

    // Crear el consumer group si no existe (MKSTREAM crea el stream si tampoco existe)
    let group_result: redis::RedisResult<()> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(REDIS_STREAM)
        .arg(CONSUMER_GROUP)
        .arg("$")         // Solo mensajes nuevos
        .arg("MKSTREAM")  // Crea el stream si no existe
        .query_async(&mut redis_con)
        .await;

    match group_result {
        Ok(_) => info!("Consumer group '{CONSUMER_GROUP}' creado."),
        Err(e) if e.to_string().contains("BUSYGROUP") => {
            info!("Consumer group '{CONSUMER_GROUP}' ya existe, continuando.");
        }
        Err(e) => return Err(e.into()),
    }

    // ── Cliente HTTP para ClickHouse ──────────────────────────────────────────
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    info!("Escuchando en '{REDIS_STREAM}'...");

    // ── Bucle principal de consumo ────────────────────────────────────────────
    loop {
        // XREADGROUP: leer hasta 10 mensajes, bloquear 2s si no hay nuevos
        let results: redis::RedisResult<redis::streams::StreamReadReply> = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(CONSUMER_GROUP)
            .arg(CONSUMER_NAME)
            .arg("COUNT")
            .arg(10)
            .arg("BLOCK")
            .arg(2000) // ms
            .arg("STREAMS")
            .arg(REDIS_STREAM)
            .arg(">") // Solo mensajes no entregados
            .query_async(&mut redis_con)
            .await;

        let reply = match results {
            Ok(r) => r,
            Err(e) => {
                warn!("Error leyendo Redis Stream: {e}. Reintentando en 2s...");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        for stream_key in reply.keys {
            for entry in stream_key.ids {
                let msg_id = &entry.id;

                // Extraer el campo "data" del mensaje
                let Some(raw_data) = entry.map.get("data") else {
                    warn!("Mensaje {msg_id} sin campo 'data', haciendo ACK y saltando.");
                    let _: redis::RedisResult<()> = redis_con
                        .xack(REDIS_STREAM, CONSUMER_GROUP, &[msg_id])
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
                        // ACK igual para no bloquear el stream con mensajes corruptos
                        let _: redis::RedisResult<()> = redis_con
                            .xack(REDIS_STREAM, CONSUMER_GROUP, &[msg_id])
                            .await;
                        continue;
                    }
                };

                // Insertar en ClickHouse
                match insert_into_clickhouse(&http_client, &ch_url, &event).await {
                    Ok(_) => {
                        info!(
                            msg_id = %msg_id,
                            user_did = %event.user_did,
                            decision = %event.decision,
                            latency_ms = event.latency_ms,
                            "Evento insertado en ClickHouse."
                        );
                        // ACK: confirmar al grupo que el mensaje fue procesado
                        let _: redis::RedisResult<()> = redis_con
                            .xack(REDIS_STREAM, CONSUMER_GROUP, &[msg_id])
                            .await;
                    }
                    Err(e) => {
                        // No hacer ACK para que otro consumidor o un retry lo intente
                        error!("Fallo al insertar evento {msg_id} en ClickHouse: {e}");
                    }
                }
            }
        }
    }
}
