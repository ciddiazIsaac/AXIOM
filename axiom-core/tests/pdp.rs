#[cfg(test)]
mod tests {
    use axiom_core::pdp::{
        DeviceContext, EnvContext, ResourceContext, ZeroTrustEngine, ZeroTrustRequest,
    };

    const REGO_POLICY: &str = r#"
package axiom.pdp

default allow = false
default requires_2fa = false
default requires_biometric = false
default block = false
default alert = false

requires_2fa if {
    input.device.trust_score < 0.7
}

block if {
    input.context.distance_km > 1000
    input.context.time_delta_mins < 10
}

alert if {
    input.context.distance_km > 1000
    input.context.time_delta_mins < 10
}

requires_biometric if {
    input.resource.name == "Admin"
}

allow if {
    not block
}
"#;

    fn get_engine() -> ZeroTrustEngine {
        ZeroTrustEngine::new(REGO_POLICY).unwrap()
    }

    #[test]
    fn test_normal_access() {
        let engine = get_engine();
        let req = ZeroTrustRequest {
            session_id: "test-session".into(),
            user_did: "did:axiom:test".into(),
            device: DeviceContext {
                trust_score: 0.9,
                id: "dev-1".into(),
            },
            context: EnvContext {
                distance_km: 10.0,
                time_delta_mins: 60.0,
                anomaly_score: None,
            },
            resource: ResourceContext {
                name: "Dashboard".into(),
                hash: "test-hash".into(),
            },
        };

        let decision = engine.evaluate(&req).unwrap();
        assert!(decision.allow);
        assert!(!decision.requires_2fa);
        assert!(!decision.requires_biometric);
        assert!(!decision.block);
        assert!(!decision.alert);
    }

    #[test]
    fn test_low_trust_score_requires_2fa() {
        let engine = get_engine();
        let req = ZeroTrustRequest {
            session_id: "test-session".into(),
            user_did: "did:axiom:test".into(),
            device: DeviceContext {
                trust_score: 0.5,
                id: "dev-1".into(),
            },
            context: EnvContext {
                distance_km: 10.0,
                time_delta_mins: 60.0,
                anomaly_score: None,
            },
            resource: ResourceContext {
                name: "Dashboard".into(),
                hash: "test-hash".into(),
            },
        };

        let decision = engine.evaluate(&req).unwrap();
        assert!(decision.allow); // Still allowed, but requires 2FA
        assert!(decision.requires_2fa);
        assert!(!decision.requires_biometric);
        assert!(!decision.block);
    }

    #[test]
    fn test_impossible_travel_blocks_and_alerts() {
        let engine = get_engine();
        let req = ZeroTrustRequest {
            session_id: "test-session".into(),
            user_did: "did:axiom:test".into(),
            device: DeviceContext {
                trust_score: 0.9,
                id: "dev-1".into(),
            },
            context: EnvContext {
                distance_km: 5000.0,
                time_delta_mins: 5.0,
                anomaly_score: None,
            }, // 5000km in 5 minutes
            resource: ResourceContext {
                name: "Dashboard".into(),
                hash: "test-hash".into(),
            },
        };

        let decision = engine.evaluate(&req).unwrap();
        assert!(!decision.allow);
        assert!(decision.block);
        assert!(decision.alert);
    }

    #[test]
    fn test_admin_requires_biometric() {
        let engine = get_engine();
        let req = ZeroTrustRequest {
            session_id: "test-session".into(),
            user_did: "did:axiom:test".into(),
            device: DeviceContext {
                trust_score: 0.9,
                id: "dev-1".into(),
            },
            context: EnvContext {
                distance_km: 10.0,
                time_delta_mins: 60.0,
                anomaly_score: None,
            },
            resource: ResourceContext {
                name: "Admin".into(),
                hash: "test-hash".into(),
            },
        };

        let decision = engine.evaluate(&req).unwrap();
        assert!(decision.allow);
        assert!(decision.requires_biometric);
        assert!(!decision.block);
    }

    #[test]
    fn test_speed() {
        let engine = get_engine();
        let req = ZeroTrustRequest {
            session_id: "test-session".into(),
            user_did: "did:axiom:test".into(),
            device: DeviceContext {
                trust_score: 0.9,
                id: "dev-1".into(),
            },
            context: EnvContext {
                distance_km: 10.0,
                time_delta_mins: 60.0,
                anomaly_score: None,
            },
            resource: ResourceContext {
                name: "Dashboard".into(),
                hash: "test-hash".into(),
            },
        };

        let start = std::time::Instant::now();
        for _ in 0..100 {
            engine.evaluate(&req).unwrap();
        }
        let elapsed = start.elapsed();
        // Ensure that average evaluation time is well under 50ms (e.g. < 5ms)
        assert!(elapsed.as_millis() < 500);
    }
}
