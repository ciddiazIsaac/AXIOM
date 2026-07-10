#![allow(warnings)]
//! axiom-bench: Prueba de Fuego del Stack Redis + ClickHouse
//!
//! Dispara N eventos/segundo de decisiones sintéticas contra Redis Streams.
//! Mide throughput real, latencia de XADD y detecta backpressure.
//!
//! Uso:
//!   cargo run --bin bench -- --rate 10000 --duration 30
//!   REDIS_URL=redis://127.0.0.1:6379 cargo run --release --bin bench

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redis::AsyncCommands;
use serde_json::json;
use tokio::time::interval;

// ─── Configuración del benchmark ─────────────────────────────────────────────

const REDIS_STREAM: &str = "axiom:audit:stream";

/// Parámetros leídos de argumentos o valores por defecto
struct Config {
    redis_url: String,
    target_rate: u64,   // eventos/segundo objetivo
    duration_secs: u64, // segundos que dura el benchmark
    concurrency: usize, // workers paralelos de XADD
}

impl Config {
    fn from_env_and_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let get_arg = |flag: &str, default: &str| -> String {
            args.windows(2)
                .find(|w| w[0] == flag)
                .map(|w| w[1].clone())
                .unwrap_or_else(|| default.to_string())
        };

        Config {
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string()),
            target_rate: get_arg("--rate", "10000").parse().unwrap_or(10_000),
            duration_secs: get_arg("--duration", "30").parse().unwrap_or(30),
            concurrency: get_arg("--concurrency", "8").parse().unwrap_or(8),
        }
    }
}

// ─── Generador de eventos sintéticos ─────────────────────────────────────────

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn decisions() -> [&'static str; 3] {
    ["ALLOW", "DENY", "CHALLENGE"]
}
fn geos() -> [&'static str; 5] {
    ["US-NYC", "DE-BER", "ES-MAD", "MX-CDM", "JP-TYO"]
}
fn device_types() -> [&'static str; 3] {
    ["mobile", "desktop", "server"]
}

/// Genera un AuditEvent JSON sintético con alta cardinalidad
fn synthetic_event(seq: u64) -> String {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let decision = decisions()[(seq % 3) as usize];
    let geo = geos()[(seq % 5) as usize];
    let device = device_types()[(seq % 3) as usize];
    let risk_score = ((seq % 100) as f32) / 100.0;

    json!({
        "timestamp_ns": now_ns,
        "session_id": format!("bench-session-{:08x}", seq % 0xFFFF),
        "user_did": format!("did:axiom:bench:{:06}", seq % 1000),
        "resource_hash": format!("sha256:{:064x}", seq),
        "decision": decision,
        "risk_score": risk_score,
        "context_snapshot": {
            "geo": geo,
            "device_type": device,
            "hour": format!("{:02}", (seq % 24)),
            "is_vpn": if seq.is_multiple_of(7) { "true" } else { "false" },
            "trust_level": format!("{}", seq % 5)
        },
        "latency_ms": (seq % 50) as f64 * 0.1 + 0.05
    })
    .to_string()
}

// ─── Contadores atómicos de métricas ─────────────────────────────────────────

struct Metrics {
    sent: AtomicU64,
    errors: AtomicU64,
    /// Latencia acumulada en µs (para calcular media)
    latency_us_total: AtomicU64,
    latency_samples: AtomicU64,
}

impl Metrics {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latency_us_total: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
        })
    }
}

// ─── Worker de publicación ────────────────────────────────────────────────────

/// Cada worker recibe un "token bucket" implícito: un canal donde el ticker
/// principal le envía el permiso de emitir N eventos por tick.
async fn publisher_worker(
    redis_url: String,
    metrics: Arc<Metrics>,
    mut rx: tokio::sync::mpsc::Receiver<u64>, // recibe el seq a publicar
) {
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Worker: no pudo conectar a Redis: {e}");
            return;
        }
    };

    let mut con = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Worker: no pudo obtener conexión: {e}");
            return;
        }
    };

    while let Some(seq) = rx.recv().await {
        let payload = synthetic_event(seq);
        let t0 = Instant::now();

        let result: redis::RedisResult<String> =
            con.xadd(REDIS_STREAM, "*", &[("data", &payload)]).await;

        let elapsed_us = t0.elapsed().as_micros() as u64;

        match result {
            Ok(_) => {
                metrics.sent.fetch_add(1, Ordering::Relaxed);
                metrics
                    .latency_us_total
                    .fetch_add(elapsed_us, Ordering::Relaxed);
                metrics.latency_samples.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Ordering::Relaxed);
                // Reconexión lazy: próxima llamada intentará de nuevo
            }
        }
    }
}

// ─── Reportero en tiempo real ─────────────────────────────────────────────────

async fn reporter(metrics: Arc<Metrics>, duration_secs: u64) {
    let mut ticker = interval(Duration::from_secs(1));
    let mut prev_sent = 0u64;
    let start = Instant::now();

    // Cabecera de la tabla
    println!();
    println!(
        "{:<6} {:>10} {:>10} {:>10} {:>10} {:>8}",
        "t(s)", "total", "rate/s", "errors", "avg_lat_µs", "status"
    );
    println!("{}", "─".repeat(62));

    loop {
        ticker.tick().await;
        let elapsed = start.elapsed().as_secs();

        let sent = metrics.sent.load(Ordering::Relaxed);
        let errors = metrics.errors.load(Ordering::Relaxed);
        let samples = metrics.latency_samples.load(Ordering::Relaxed);
        let lat_total = metrics.latency_us_total.load(Ordering::Relaxed);

        let rate = sent - prev_sent;
        prev_sent = sent;
        let avg_lat = if samples > 0 { lat_total / samples } else { 0 };

        let status = if errors == 0 { "✅ OK" } else { "⚠️  ERR" };

        println!(
            "{:<6} {:>10} {:>10} {:>10} {:>10} {:>8}",
            elapsed, sent, rate, errors, avg_lat, status
        );

        if elapsed >= duration_secs {
            break;
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cfg = Config::from_env_and_args();

    println!("╔══════════════════════════════════════════════════╗");
    println!("║         AXIOM — Prueba de Fuego Redis Stream      ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!("  Redis:       {}", cfg.redis_url);
    println!("  Objetivo:    {}/s", cfg.target_rate);
    println!("  Duración:    {}s", cfg.duration_secs);
    println!("  Workers:     {}", cfg.concurrency);
    println!(
        "  Total:       ~{} eventos",
        cfg.target_rate * cfg.duration_secs
    );
    println!();

    let metrics = Metrics::new();

    let mut worker_senders: Vec<tokio::sync::mpsc::Sender<u64>> = Vec::new();
    let mut worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    for _ in 0..cfg.concurrency {
        let (wtx, wrx) = tokio::sync::mpsc::channel::<u64>(2048);
        worker_senders.push(wtx);
        let url = cfg.redis_url.clone();
        let m = Arc::clone(&metrics);
        worker_handles.push(tokio::spawn(publisher_worker(url, m, wrx)));
    }

    // Reportero en background
    let m_report = Arc::clone(&metrics);
    let dur = cfg.duration_secs;
    let report_handle = tokio::spawn(reporter(m_report, dur));

    // ── Dispatcher con Token Bucket ───────────────────────────────────────────
    // Emite exactamente `target_rate` eventos/segundo distribuyendo entre workers
    let events_per_tick = cfg.target_rate.max(1);
    let tick_interval = Duration::from_secs(1);
    let mut ticker = interval(tick_interval);
    let bench_start = Instant::now();
    let mut worker_idx = 0usize;

    loop {
        ticker.tick().await;

        if bench_start.elapsed().as_secs() >= cfg.duration_secs {
            break;
        }

        // Emitir un "burst" de eventos_per_tick en este tick
        for _ in 0..events_per_tick {
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            // Round-robin entre workers (non-blocking: si el canal está lleno, descartamos)
            let sender = &worker_senders[worker_idx % cfg.concurrency];
            worker_idx += 1;
            let _ = sender.try_send(seq); // fire-and-forget; no bloqueamos el dispatcher
        }
    }

    // Señal de parada: cerrar todos los senders
    drop(worker_senders);

    // Esperar a que los workers terminen de procesar el buffer
    for h in worker_handles {
        let _ = h.await;
    }
    let _ = report_handle.await;

    // ── Resumen final ─────────────────────────────────────────────────────────
    let total_sent = metrics.sent.load(Ordering::Relaxed);
    let total_errors = metrics.errors.load(Ordering::Relaxed);
    let samples = metrics.latency_samples.load(Ordering::Relaxed);
    let lat_total = metrics.latency_us_total.load(Ordering::Relaxed);
    let avg_lat = if samples > 0 { lat_total / samples } else { 0 };
    let real_rate = total_sent / cfg.duration_secs.max(1);

    println!();
    println!("╔══════════════════════════════════════════════════╗");
    println!("║                  RESULTADO FINAL                  ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!(
        "║  Eventos enviados:   {:>10}                   ║",
        total_sent
    );
    println!(
        "║  Errores Redis:      {:>10}                   ║",
        total_errors
    );
    println!(
        "║  Rate real:          {:>8}/s                   ║",
        real_rate
    );
    println!(
        "║  Latencia avg XADD:  {:>8} µs                  ║",
        avg_lat
    );
    println!("╠══════════════════════════════════════════════════╣");
    if total_errors == 0 && real_rate >= cfg.target_rate * 80 / 100 {
        println!("║  ✅ PASADO — Stack listo para Semana 8            ║");
    } else if total_errors == 0 {
        println!("║  ⚠️  PARCIAL — Rate bajo objetivo, revisar workers ║");
    } else {
        println!("║  ❌ FALLIDO — Errores en Redis, revisar broker     ║");
    }
    println!("╚══════════════════════════════════════════════════╝");
}
