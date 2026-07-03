import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import requests
import os
import io

def fetch_data_from_clickhouse(url="http://localhost:8123/", days=7):
    query = f"""
    SELECT
        latency_ms,
        risk_score,
        distance_km,
        toHour(timestamp) AS hour_of_day,
        multiIf(
            decision = 'ALLOW', 0,
            decision = 'DENY', 1,
            decision = 'CHALLENGE', 2,
            0
        ) AS decision,
        device_trust_score
    FROM audit_events
    WHERE timestamp >= now() - INTERVAL {days} DAY
    LIMIT 100000
    FORMAT CSVWithNames
    """
    
    print(f"Obteniendo datos de los últimos {days} días desde ClickHouse ({url})...")
    try:
        response = requests.post(url, data=query.encode('utf-8'))
        response.raise_for_status()
        
        # Read CSV data directly into pandas DataFrame
        df = pd.read_csv(io.StringIO(response.text))
        print(f"Se obtuvieron {len(df)} registros exitosamente.")
        return df
    except Exception as e:
        print(f"Error al obtener datos de ClickHouse: {e}")
        return None

def train_and_export_model(df, output_path="anomaly_model.onnx"):
    if df.empty:
        print("El DataFrame está vacío. Abortando el reentrenamiento.")
        return

    # Handle nulls
    df = df.fillna(0)
    
    features = ['latency_ms', 'risk_score', 'distance_km', 'hour_of_day', 'decision', 'device_trust_score']
    
    print("Preparando características y convirtiendo a float32...")
    X = df[features].values.astype(np.float32)
    
    print("Entrenando el nuevo Isolation Forest...")
    # Using 1% expected contamination
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    model.fit(X)
    print("Entrenamiento completado.")
    
    print("Convirtiendo modelo a ONNX...")
    initial_type = [('float_input', FloatTensorType([None, len(features)]))]
    onnx_model = convert_sklearn(
        model, 
        initial_types=initial_type,
        target_opset={'': 15, 'ai.onnx.ml': 3}
    )
    
    # Save the model
    # To simulate uploading to an S3 bucket or saving to a known path, we'll write to the path expected by the Rust node
    # Writing to this file will trigger the hot-reload mechanism
    print(f"Guardando el nuevo modelo en {output_path}...")
    
    # Escribimos de manera atómica para evitar que el observador (notify) vea el archivo a medias.
    # En Windows os.replace es atómico.
    temp_path = output_path + ".tmp"
    with open(temp_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
        
    os.replace(temp_path, output_path)
    
    print(f"\n¡Éxito! Modelo exportado a '{output_path}'.")
    print("El nodo de Rust debería detectar el cambio y realizar el hot reload (Zero Downtime).")

def main():
    clickhouse_url = os.environ.get("CLICKHOUSE_URL", "http://localhost:8123/")
    
    df = fetch_data_from_clickhouse(clickhouse_url)
    if df is not None and not df.empty:
        train_and_export_model(df, "anomaly_model.onnx")
    else:
        print("No se encontraron suficientes datos nuevos para entrenar. Abortando.")

if __name__ == "__main__":
    main()
