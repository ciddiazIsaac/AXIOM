"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AxiomSDK = void 0;
class AxiomSDK {
    baseUrl;
    token = null;
    constructor(baseUrl = "http://localhost:3000") {
        this.baseUrl = baseUrl;
    }
    /**
     * Simulates authentication and session token retrieval.
     */
    async authenticate(did, signature) {
        // En el sistema real llamaría al endpoint de autenticación.
        // Para este MVP, simularemos que retorna un session token.
        this.token = "simulated_session_token";
        return this.token;
    }
    /**
     * Requests access to a resource based on context.
     */
    async requestAccess(userDid, resource, context) {
        const payload = {
            subject: {
                did: userDid,
                clearance_level: 3,
                roles: ["user"]
            },
            resource,
            context,
            session: {
                session_id: "demo-session-123",
                device_trust_score: 85,
                mfa_verified: false,
                biometric_verified: false
            }
        };
        const res = await fetch(`${this.baseUrl}/v1/evaluate`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            throw new Error(`Failed to request access: ${res.statusText}`);
        }
        return await res.json();
    }
    /**
     * Retrieves the anomaly score for a user.
     */
    async getAnomalyScore(userDid) {
        const res = await fetch(`${this.baseUrl}/v1/anomaly_score?user_did=${encodeURIComponent(userDid)}`, {
            method: "GET"
        });
        if (!res.ok) {
            throw new Error(`Failed to get anomaly score: ${res.statusText}`);
        }
        return await res.json();
    }
}
exports.AxiomSDK = AxiomSDK;
