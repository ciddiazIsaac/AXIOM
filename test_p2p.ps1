$ErrorActionPreference = "Stop"

Write-Host "`n========================================"
Write-Host "  AXIOM P2P - Test E2E con auto-revoke"
Write-Host "========================================`n"

# 1. Build
Write-Host "[Build] Compilando axiom-p2p..."
cargo build -p axiom-p2p
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Fallo en la compilacion."
    exit 1
}
Write-Host "[Build] OK`n"

# 2. Arrancar Nodo 1 (con auto-revoke despues de 10 segundos)
Write-Host "[Nodo 1] Arrancando en puerto 8000 con auto-revoke 'cred-ps-test' en 10s..."
$node1 = Start-Process -FilePath "cargo" `
    -ArgumentList "run", "-p", "axiom-p2p", "--", "--port", "8000", "--name", "Node1", "--auto-revoke", "cred-ps-test:10" `
    -PassThru -RedirectStandardOutput "node1_out.txt" -RedirectStandardError "node1_err.txt"

# Esperar a que Nodo 1 arranque y obtener su Peer ID
Start-Sleep -Seconds 3

$output1 = Get-Content "node1_out.txt" -ErrorAction SilentlyContinue
$peerIdLine = $output1 | Where-Object { $_ -match "Peer ID: (.*)" }
if (-not $peerIdLine) {
    Write-Host "[ERROR] No se pudo obtener el Peer ID del Nodo 1"
    Write-Host "--- Stdout ---"
    Get-Content "node1_out.txt" -ErrorAction SilentlyContinue
    Write-Host "--- Stderr ---"
    Get-Content "node1_err.txt" -ErrorAction SilentlyContinue
    Stop-Process -Id $node1.Id -Force -ErrorAction SilentlyContinue
    exit 1
}
$peerId = ($peerIdLine -replace ".*Peer ID: (.*)", "`$1").Trim()
Write-Host "[Nodo 1] Peer ID: $peerId`n"

# 3. Arrancar Nodo 2 con bootstrap al Nodo 1
$bootstrapAddr = "/ip4/127.0.0.1/tcp/8000/p2p/$peerId"
Write-Host "[Nodo 2] Arrancando en puerto 8001, bootstrap: $bootstrapAddr"
$node2 = Start-Process -FilePath "cargo" `
    -ArgumentList "run", "-p", "axiom-p2p", "--", "--port", "8001", "--name", "Node2", "--bootstrap", "$bootstrapAddr" `
    -PassThru -RedirectStandardOutput "node2_out.txt" -RedirectStandardError "node2_err.txt"

# 4. Esperar a que la revocacion se propague (auto-revoke en 10s + propagacion)
Write-Host "`n[Test] Esperando 25 segundos para descubrimiento + auto-revoke + propagacion..."
Start-Sleep -Seconds 25

# 5. Verificar logs del Nodo 2
Write-Host "`n--- Nodo 2 Stdout ---"
$node2Out = Get-Content "node2_out.txt" -ErrorAction SilentlyContinue
$node2Out | ForEach-Object { Write-Host "  $_" }

Write-Host "`n--- Nodo 1 Stdout ---"
$node1Out = Get-Content "node1_out.txt" -ErrorAction SilentlyContinue
$node1Out | ForEach-Object { Write-Host "  $_" }

# 6. Buscar evidencia de que la revocacion llego al Nodo 2
$success = $node2Out | Where-Object { $_ -match "CRDT actualizado" }
$discovered = $node2Out | Where-Object { $_ -match "descubri" }

Write-Host "`n========================================"
if ($success) {
    Write-Host "  RESULTADO: PASS - Nodo 2 recibio la revocacion"
} elseif ($discovered) {
    Write-Host "  RESULTADO: PARCIAL - Nodos se descubrieron pero la revocacion no llego aun"
    Write-Host "  (Intenta aumentar el tiempo de espera)"
} else {
    Write-Host "  RESULTADO: FAIL - Los nodos no se descubrieron"
}
Write-Host "========================================`n"

# 7. Cleanup
Stop-Process -Id $node1.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $node2.Id -Force -ErrorAction SilentlyContinue
Remove-Item "node1_out.txt", "node1_err.txt", "node2_out.txt", "node2_err.txt" -ErrorAction SilentlyContinue

Write-Host "Procesos detenidos. Test completado."
