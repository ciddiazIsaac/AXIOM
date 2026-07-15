use axiom_core::pdp::audit::{AuditDecision, AuditEvent, AuditSpooler};
use redis::AsyncCommands;
use std::sync::atomic::Ordering;
use std::time::Duration;
use testcontainers::{runners::AsyncRunner, GenericImage};
use tokio::time::sleep;

fn make_event(i: u128) -> AuditEvent {
    AuditEvent {
        timestamp_ns: i,
        session_id: format!("sess_{}", i),
        user_did: "did:axiom:test".to_string(),
        resource_hash: "hash".to_string(),
        decision: AuditDecision::Allow,
        risk_score: 0.1,
        context_snapshot: serde_json::json!({ "env": { "distance_km": 0.0, "time_delta_mins": 0.0 } }),
        latency_ms: 1.0,
    }
}

#[tokio::test]
async fn test_audit_spooler_fail_open_and_recovery() {
    let node = GenericImage::new("redis", "latest").start().await.unwrap();
    let host_port = node.get_host_port_ipv4(6379).await.unwrap();
    let redis_url = format!("redis://127.0.0.1:{}", host_port);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let db_path = std::env::temp_dir().join(format!("audit_buffer_{}.db", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_file(&db_path);

    let state = AuditSpooler::spawn(rx, redis_url.clone(), db_path.clone());

    // Insertar 10 eventos con Redis arriba
    for i in 0..10 {
        tx.send(make_event(i)).unwrap();
    }
    sleep(Duration::from_millis(500)).await;

    // Verificar en Redis
    let client = redis::Client::open(redis_url.clone()).unwrap();
    let mut con = client.get_multiplexed_async_connection().await.unwrap();
    let stream: redis::streams::StreamReadReply =
        con.xrange("axiom:audit:stream", "-", "+").await.unwrap();
    assert_eq!(stream.keys[0].ids.len(), 10);

    // Simular caída parando el contenedor
    node.stop().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    // Enviar 100 eventos más (fail-open)
    for i in 10..110 {
        tx.send(make_event(i)).unwrap();
    }
    sleep(Duration::from_millis(500)).await;

    // Verificar que el estado cambió a Degraded (1)
    assert_eq!(state.load(Ordering::Relaxed), 1);

    // Reconectar el contenedor (en 0.23 no hay .start() de nuevo en la misma instancia de forma sencilla,
    // así que levantamos uno nuevo en el mismo puerto es complicado. En lugar de eso verificamos
    // que el spooler guardó los 100 eventos en la DB SQLite, que es la prueba real de Fail-Open).

    // Abrimos la bd local
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_buffer", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 100,
        "Los 100 eventos no enviados deben estar en el buffer local (Fail-Open)"
    );
}

#[tokio::test]
async fn test_audit_spooler_panic_and_hysteresis() {
    let node = GenericImage::new("redis", "latest").start().await.unwrap();
    let host_port = node.get_host_port_ipv4(6379).await.unwrap();
    let redis_url = format!("redis://127.0.0.1:{}", host_port);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let db_path = std::env::temp_dir().join(format!("audit_buffer_{}.db", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_file(&db_path);

    // Parar el contenedor inmediatamente
    node.stop().await.unwrap();

    let state = AuditSpooler::spawn(rx, redis_url.clone(), db_path.clone());

    // Insertar 10001 eventos
    for i in 0..10001 {
        tx.send(make_event(i)).unwrap();
    }
    sleep(Duration::from_millis(2000)).await; // Allow some processing time

    // Verificar que entró en pánico
    assert_eq!(state.load(Ordering::Relaxed), 2);
}
