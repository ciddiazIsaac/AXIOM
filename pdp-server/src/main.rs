use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use axiom_core::pdp::{Decision, ZeroTrustEngine, ZeroTrustRequest};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    engine: Arc<ZeroTrustEngine>,
}

#[tokio::main]
async fn main() {
    let policy = std::fs::read_to_string("../axiom-core/policies/zero_trust.rego")
        .expect("Failed to read zero_trust.rego policy file");
        
    let engine = ZeroTrustEngine::new(&policy).expect("Failed to initialize PDP Engine");
    let state = AppState {
        engine: Arc::new(engine),
    };

    let app = Router::new()
        .route("/pdp/verify", post(verify_request))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("PDP Server running on http://127.0.0.1:8080");
    
    axum::serve(listener, app).await.unwrap();
}

async fn verify_request(
    State(state): State<AppState>,
    Json(payload): Json<ZeroTrustRequest>,
) -> Json<Decision> {
    // In a real scenario we'd handle errors properly and maybe return 403 or 400
    // But for fast evaluation we just unwrap or handle the error gracefully
    match state.engine.evaluate(&payload) {
        Ok(decision) => Json(decision),
        Err(e) => {
            eprintln!("Evaluation error: {}", e);
            // Default deny on error
            Json(Decision {
                allow: false,
                requires_2fa: true,
                requires_biometric: true,
                block: true,
                alert: true,
            })
        }
    }
}
