import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import os

def main():
    csv_file = 'dataset_features.csv'
    
    print(f"Buscando archivo de datos '{csv_file}'...")
    
    # 1. Cargar datos
    if os.path.exists(csv_file):
        print("Cargando datos extraídos de ClickHouse...")
        df = pd.read_csv(csv_file)
    else:
        print(f"No se encontró el archivo '{csv_file}'.")
        print("Para comenzar rápido, se generarán 50,000 registros sintéticos...")
        
        # Generar datos sintéticos simulando logs para entrenar el modelo de prueba
        np.random.seed(42)
        n_samples = 50000
        df = pd.DataFrame({
            'latency_ms': np.random.exponential(scale=30, size=n_samples), # Latencia normal
            'risk_score': np.random.beta(a=2, b=8, size=n_samples) * 100,  # Mayoría puntajes bajos
            'distance_km': np.random.exponential(scale=150, size=n_samples),
            'hour_of_day': np.random.randint(0, 24, size=n_samples),
            'decision': np.random.choice([0, 1, 2], size=n_samples, p=[0.90, 0.05, 0.05]), # 0=ALLOW, 1=DENY, 2=CHALLENGE
            'device_trust_score': np.random.uniform(0, 100, size=n_samples)
        })
        
        # Inyectar algunas anomalías explícitas para que el Isolation Forest las aprenda
        n_anomalies = 500
        anomalies_indices = np.random.choice(df.index, n_anomalies, replace=False)
        df.loc[anomalies_indices, 'latency_ms'] = np.random.uniform(2000, 5000, size=n_anomalies)
        df.loc[anomalies_indices, 'risk_score'] = np.random.uniform(90, 100, size=n_anomalies)
        df.loc[anomalies_indices, 'distance_km'] = np.random.uniform(5000, 12000, size=n_anomalies)
    
    print(f"Datos listos. Total de registros: {len(df)}")
    
    # Manejar nulos por precaución
    df = df.fillna(0)
    
    # Definir características a utilizar
    features = ['latency_ms', 'risk_score', 'distance_km', 'hour_of_day', 'decision', 'device_trust_score']
    
    # Convertir a float32 ya que ONNX prefiere este tipo de datos
    X = df[features].values.astype(np.float32)
    
    # 2. Entrenar el modelo (Isolation Forest)
    print("Entrenando Isolation Forest...")
    # contamination es el % de outliers que esperamos.
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    model.fit(X)
    print("Entrenamiento completado.")
    
    # 3. Exportar a ONNX
    print("Convirtiendo el modelo a ONNX...")
    # Definir la forma de entrada esperada por el modelo (None significa que acepta batch size variable)
    initial_type = [('float_input', FloatTensorType([None, len(features)]))]
    
    # Convertir
    onnx_model = convert_sklearn(
        model, 
        initial_types=initial_type,
        target_opset={'': 15, 'ai.onnx.ml': 3} # target_opset solucionará el problema de compatibilidad
    )
    
    # Guardar en la raíz del proyecto
    onnx_filename = 'anomaly_model.onnx'
    with open(onnx_filename, "wb") as f:
        f.write(onnx_model.SerializeToString())
        
    print(f"\n¡Éxito! Modelo exportado a '{onnx_filename}'.")
    print("El modelo ahora puede ser cargado e inferido usando onnxruntime en cualquier lenguaje (Rust, Python, Node, etc.).")

if __name__ == "__main__":
    main()
