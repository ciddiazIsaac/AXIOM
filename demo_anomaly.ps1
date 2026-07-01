$ErrorActionPreference = "Stop"

Write-Host "Consultando Anomaly Score para did:axiom:test_42 (esperando outlier_event)"
$start = Get-Date

$response = Invoke-RestMethod -Uri "http://127.0.0.1:8080/anomaly_score?user=did:axiom:test_42" -Method Get

$end = Get-Date
$timeTaken = ($end - $start).TotalMilliseconds

Write-Host "`nRespuesta en ${timeTaken} ms"
Write-Host "Score: $($response.anomaly_score)"
Write-Host "Media Latencia (Baseline): $($response.baseline_mean)"
Write-Host "StdDev Latencia (Baseline): $($response.std_dev)"
Write-Host "Es Outlier: $($response.is_outlier)"

if ($timeTaken -lt 200) {
    Write-Host "`n[OK] Latencia menor a 200ms"
} else {
    Write-Host "`n[FAIL] Latencia mayor a 200ms"
}
