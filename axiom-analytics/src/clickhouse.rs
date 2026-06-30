//! clickhouse.rs — Cliente ClickHouse HTTP minimalista
//!
//! Ejecuta queries SELECT y devuelve filas como Vec<serde_json::Value>
//! usando el formato JSONEachRow de ClickHouse.

use anyhow::Context;
use serde_json::Value;

/// Cliente ligero para la API HTTP de ClickHouse (puerto 8123).
#[derive(Clone)]
pub struct ClickHouseClient {
    http: reqwest::Client,
    url: String,
}

impl ClickHouseClient {
    /// Crea un nuevo cliente apuntando a `url` (ej. "http://127.0.0.1:8123/").
    pub fn new(url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("Failed to build reqwest client");
        Self { http, url: url.into() }
    }

    /// Ejecuta una query SELECT y devuelve cada fila como un JSON object.
    ///
    /// Usa el formato `JSONEachRow` de ClickHouse: una línea JSON por fila.
    pub async fn query_json_rows(&self, sql: &str) -> anyhow::Result<Vec<Value>> {
        // Añadir FORMAT JSONEachRow al final de la query
        let query_with_format = format!("{sql} FORMAT JSONEachRow");

        let resp = self
            .http
            .post(&self.url)
            .body(query_with_format)
            .send()
            .await
            .context("Error enviando query a ClickHouse")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("ClickHouse error {status}: {body}");
        }

        let body = resp.text().await.context("Error leyendo respuesta de ClickHouse")?;

        // JSONEachRow: una línea JSON por fila, parsear cada una individualmente
        let rows: Vec<Value> = body
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .with_context(|| format!("Error parseando fila JSON: {line}"))
            })
            .collect::<anyhow::Result<Vec<Value>>>()?;

        Ok(rows)
    }

    /// Ejecuta una query que devuelve exactamente una fila con columnas escalares.
    /// Devuelve `None` si no hay resultados.
    pub async fn query_single_row(&self, sql: &str) -> anyhow::Result<Option<Value>> {
        let mut rows = self.query_json_rows(sql).await?;
        Ok(rows.pop())
    }
}
