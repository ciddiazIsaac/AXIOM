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
export declare class AxiomSDK {
    private baseUrl;
    private token;
    constructor(baseUrl?: string);
    /**
     * Simulates authentication and session token retrieval.
     */
    authenticate(did: string, signature: string): Promise<string>;
    /**
     * Requests access to a resource based on context.
     */
    requestAccess(userDid: string, resource: Resource, context: Context): Promise<EvaluationResult>;
    /**
     * Retrieves the anomaly score for a user.
     */
    getAnomalyScore(userDid: string): Promise<any>;
}
