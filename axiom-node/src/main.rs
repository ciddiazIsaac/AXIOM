use axum::{
    routing::{get, post},
    Router, response::IntoResponse,
};
use tower_http::services::ServeDir;
use prometheus_client::registry::Registry;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::encoding::text::encode;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};

// Imports de otros subsistemas
use axiom_p2p::node::{ValidatorNode, NodeConfig};
use libp2p::identity::Keypair;
use pdp_server::{build_app_state, verify_request, AppState as PdpState};
use axiom_analytics::{anomaly_score, AppState as AnalyticsState};
use axiom_analytics::clickhouse::ClickHouseClient;

#[derive(Clone)]
struct MetricsState {
    registry: Arc<Registry>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inicializar logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!("Iniciando AXIOM Node - El Contenedor y la Integración");

    // 1. Inicializar métricas Prometheus
    let mut registry = Registry::default();
    
    // Configurar métricas (en una implementación real actualizaríamos estos contadores
    // dentro de los handlers, envolviéndolos o pasándolos en el estado)
    // Para simplificar, aquí solo los registramos
    let pdp_decision_total = Family::<Vec<(String, String)>, prometheus_client::metrics::counter::Counter>::default();
    registry.register("pdp_decision_total", "Total de decisiones del PDP", pdp_decision_total.clone());

    let pdp_latency_seconds = Histogram::new(vec![0.01, 0.05, 0.1, 0.5, 1.0].into_iter());
    registry.register("pdp_latency_seconds", "Latencia del PDP", pdp_latency_seconds.clone());

    let p2p_peers_connected = Gauge::<i64>::default();
    registry.register("p2p_peers_connected", "Peers P2P conectados", p2p_peers_connected.clone());

    let metrics_state = MetricsState {
        registry: Arc::new(registry),
    };

    // 2. Levantar el Ingestor en background
    tokio::spawn(async move {
        info!("Iniciando Ingestor...");
        if let Err(e) = axiom_ingestor::run_ingestor().await {
            error!("Error en el Ingestor: {}", e);
        }
    });

    // 3. Levantar el Nodo P2P en background
    // P2P_LISTEN_ADDR permite fijar un puerto predecible para que el segundo nodo pueda
    // conectarse. Default: tcp/4001 (puerto fijo, no efímero).
    let p2p_listen_addr: libp2p::Multiaddr = std::env::var("P2P_LISTEN_ADDR")
        .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_string())
        .parse()
        .expect("P2P_LISTEN_ADDR inválido");

    let (_tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(100);
    tokio::spawn(async move {
        info!("Iniciando Nodo P2P en {}", p2p_listen_addr);
        let local_key = Keypair::generate_ed25519();
        let config = NodeConfig {
            local_key,
            listen_addr: p2p_listen_addr,
            bootstrap_nodes: vec![],
        };
        let node = match ValidatorNode::new(config) {
            Ok(n) => n,
            Err(e) => {
                error!("Error inicializando Nodo P2P: {}", e);
                return;
            }
        };
        node.run(rx_p2p).await;
    });

    // 4. Levantar el Servidor HTTP unificado
    // Obtener estados
    let pdp_state = build_app_state().await;
    let clickhouse_url = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123/".to_string());
    let analytics_state = AnalyticsState {
        ch: Arc::new(ClickHouseClient::new(clickhouse_url)),
    };

    // Construir el Router principal
    // Fusionaremos los estados o pasaremos lo necesario. Como AppState de cada uno es distinto,
    // es más fácil usar closures o extraerlos de una tupla. Axum State soporta tuplas o structs.
    #[derive(Clone)]
    struct AppStateUnified {
        pdp: PdpState,
        analytics: AnalyticsState,
        metrics: MetricsState,
    }

    let unified_state = AppStateUnified {
        pdp: pdp_state,
        analytics: analytics_state,
        metrics: metrics_state,
    };

    let app = Router::new()
        // API Endpoints
        .route("/v1/evaluate", post(|axum::extract::State(state): axum::extract::State<AppStateUnified>, payload| async move {
            verify_request(axum::extract::State(state.pdp), payload).await
        }))
        .route("/v1/anomaly_score", get(|axum::extract::State(state): axum::extract::State<AppStateUnified>, query| async move {
            anomaly_score(axum::extract::State(state.analytics), query).await
        }))
        .route("/metrics", get(|axum::extract::State(state): axum::extract::State<AppStateUnified>| async move {
            let mut buffer = String::new();
            if let Err(e) = encode(&mut buffer, &state.metrics.registry) {
                error!("Error encoding metrics: {}", e);
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error encoding metrics").into_response();
            }
            buffer.into_response()
        }))
        // Frontend SPA servido desde la raíz.
        // FRONTEND_DIR permite sobrescribir la ruta en local vs Docker:
        //   - Local (cargo run desde /AXIOM): FRONTEND_DIR=./frontend/dist
        //   - Docker (binario en /usr/local/bin/): usa default ../frontend/dist
        .fallback_service(ServeDir::new(
            std::env::var("FRONTEND_DIR").unwrap_or_else(|_| "../frontend/dist".to_string())
        ))
        .with_state(unified_state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr).await.unwrap();
    
    info!("AXIOM Node unificado escuchando en http://{}", bind_addr);
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
