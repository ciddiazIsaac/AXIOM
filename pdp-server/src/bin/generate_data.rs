use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = redis::Client::open("redis://127.0.0.1:6379/")?;
    let mut con = client.get_multiplexed_async_connection().await?;

    let stream = "axiom:audit:stream";
    println!("Generating 100,000 events to Redis stream '{}'...", stream);

    let start = std::time::Instant::now();
    let mut pipe = redis::pipe();
    
    for i in 0..100_000 {
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
            
        // Generate random-ish data
        let user_id = format!("did:axiom:test_{}", i % 100); // 100 different users
        let latency_ms = 40.0 + (i % 20) as f64; // baseline around 40-60ms
        let distance_km = (i % 10) as f64 * 5.0; // baseline distance 0-45km
        
        let event = json!({
            "timestamp_ns": timestamp_ns,
            "session_id": format!("sess_{}", i),
            "user_did": user_id,
            "resource_hash": "hash_123",
            "decision": "ALLOW",
            "risk_score": 0.1,
            "context_snapshot": {
                "env": {
                    "distance_km": distance_km,
                    "time_delta_mins": 10.0
                },
                "device": {
                    "id": "dev_test"
                }
            },
            "latency_ms": latency_ms
        });

        let event_str = event.to_string();
        
        pipe.xadd(stream, "*", &vec![("data", event_str)]);
        
        // Execute pipeline every 1000 items
        if i % 1000 == 999 {
            let _: () = pipe.query_async(&mut con).await?;
            pipe = redis::pipe();
        }
    }
    
    // Some outliers for testing
    let outlier_event = json!({
        "timestamp_ns": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        "session_id": "sess_outlier",
        "user_did": "did:axiom:test_42",
        "resource_hash": "hash_outlier",
        "decision": "ALLOW",
        "risk_score": 0.9,
        "context_snapshot": {
            "env": {
                "distance_km": 500.0, // Outlier distance
                "time_delta_mins": 5.0
            },
            "device": { "id": "dev_test" }
        },
        "latency_ms": 250.0 // Outlier latency
    });
    
    let _: () = redis::cmd("XADD")
        .arg(stream)
        .arg("*")
        .arg("data")
        .arg(outlier_event.to_string())
        .query_async(&mut con)
        .await?;

    println!("Generated 100,001 events in {:?}", start.elapsed());
    Ok(())
}
