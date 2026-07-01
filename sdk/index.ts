export interface Resource {
    id: string;
    classification: string;
    owner: string;
}

export interface Context {
    device_id: string;
    ip_address: string;
    geolocation: string;
    time_of_day: string;
}

export interface EvaluationResult {
    allow: boolean;
    requires_2fa: boolean;
    requires_biometric: boolean;
    block: boolean;
    alert: boolean;
}

export class AxiomSDK {
    private baseUrl: string;
    private token: string | null = null;

    constructor(baseUrl: string = "http://localhost:3000") {
        this.baseUrl = baseUrl;
    }

    /**
     * Simulates authentication and session token retrieval.
     */
    async authenticate(did: string, signature: string): Promise<string> {
        // En el sistema real llamaría al endpoint de autenticación.
        // Para este MVP, simularemos que retorna un session token.
        this.token = "simulated_session_token";
        return this.token;
    }

    /**
     * Requests access to a resource based on context.
     */
    async requestAccess(userDid: string, resource: Resource, context: Context): Promise<EvaluationResult> {
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

        return await res.json() as EvaluationResult;
    }

    /**
     * Retrieves the anomaly score for a user.
     */
    async getAnomalyScore(userDid: string): Promise<any> {
        const res = await fetch(`${this.baseUrl}/v1/anomaly_score?user_did=${encodeURIComponent(userDid)}`, {
            method: "GET"
        });

        if (!res.ok) {
            throw new Error(`Failed to get anomaly score: ${res.statusText}`);
        }

        return await res.json();
    }
}
