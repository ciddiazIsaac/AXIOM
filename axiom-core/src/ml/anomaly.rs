
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Tensor;
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use crate::error::AxiomError;

/// AnomalyDetector maneja la carga e inferencia síncrona del modelo ONNX.
#[derive(Clone)]
pub struct AnomalyDetector {
    // Usamos Arc<Mutex> porque run podría requerir acceso mutable
    session: Arc<Mutex<Session>>,
}

impl AnomalyDetector {
    /// Intenta cargar el modelo ONNX desde el disco.
    pub fn new(model_path: &str) -> Result<Self, AxiomError> {
        info!("Iniciando carga de modelo ONNX desde: {}", model_path);
        
        let session = Session::builder()
            .map_err(|e| AxiomError::InternalError(format!("Error creando ort builder: {}", e)))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| AxiomError::InternalError(format!("Error configurando opt_level: {}", e)))?
            .commit_from_file(model_path)
            .map_err(|e| AxiomError::InternalError(format!("Error cargando modelo de {}: {}", model_path, e)))?;
            
        info!("Modelo ONNX cargado exitosamente.");
        
        Ok(Self {
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// Realiza una inferencia bloqueante (síncrona).
    /// Devuelve el anomaly_score (0.0 = normal, 1.0 = anomalía extrema) o None en caso de error.
    pub fn predict(&self, features: Vec<f32>) -> Option<f32> {
        let n_features = features.len();
        
        // El IsolationForest de sklearn convertido a ONNX espera [batch_size, n_features]
        let shape = vec![1_usize, n_features];
        let tensor = Tensor::from_array((shape, features)).ok()?;
        
        // Ejecutamos la sesión. 
        // IsolationForest en ONNX normalmente retorna dos outputs: 'label' y 'scores'.
        let inputs = ort::inputs![tensor];
        let mut session_guard = self.session.lock().map_err(|e| {
            error!("Mutex envenenado: {}", e);
        }).ok()?;
        let outputs = session_guard.run(inputs).map_err(|e| {
            error!("Fallo en la inferencia ONNX: {}", e);
            e
        }).ok()?;
        
        // Extraemos los scores de la salida. (El nombre exacto de la salida puede variar, 
        // pero ort permite acceso indexado. Generalmente, output 1 es 'scores').
        if outputs.len() < 2 {
            error!("El modelo ONNX no retornó los outputs esperados.");
            return None;
        }

        // Recuperar el tensor de puntuaciones
        let score_tensor = outputs[1].try_extract_tensor::<f32>().map_err(|e| {
            error!("Fallo extrayendo tensor de scores: {}", e);
            e
        }).ok()?;
        
        // Extraer el primer score (para el único elemento del batch)
        // Scikit-learn Isolation Forest devuelve valores donde los inliers tienen scores positivos 
        // y los outliers negativos (basado en la función de decisión). 
        // Convertiremos esto a una escala [0, 1] donde 1 es más anómalo.
        let raw_score = score_tensor.1.first().copied()?;
        
        // Regla general:
        // raw_score < 0 => anomalía (valor negativo es anomalía en Isolation Forest estándar)
        // raw_score > 0 => inlier
        // Lo mapeamos a [0, 1]. Si es altamente negativo, es más anómalo.
        // Un mapeo simple con sigmoide invertida:
        let anomaly_probability = 1.0 / (1.0 + (raw_score).exp());
        
        Some(anomaly_probability)
    }
}
