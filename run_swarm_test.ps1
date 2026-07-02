<#
.SYNOPSIS
    Orquestador del AXIOM Swarm Stress Test.
    
.DESCRIPTION
    Levanta N nodos AXIOM en Docker Compose, espera a que estén listos,
    lanza el script de carga y muestra el resumen final.
    
.PARAMETER Nodes
    Número de nodos axiom-node a escalar (default: 10).
    Recomendado: empezar con 10, luego 25, luego 50.
    
.PARAMETER Rps
    Revocaciones por segundo inyectadas al bootstrap (default: 100).
    
.PARAMETER Duration
    Duración del test de carga en segundos (default: 300 = 5 minutos).
    
.PARAMETER SkipBuild
    Si se especifica, omite el build de Docker y usa la imagen existente.
    
.PARAMETER OpenGrafana
    Abre Grafana en el browser al terminar (default: $true).
    
.EXAMPLE
    .\run_swarm_test.ps1 -Nodes 10 -Rps 100 -Duration 60
    .\run_swarm_test.ps1 -Nodes 50 -Rps 100 -Duration 300 -SkipBuild
#>

param(
    [int]   $Nodes       = 10,
    [int]   $Rps         = 100,
    [int]   $Duration    = 300,
    [switch]$SkipBuild   = $false,
    [switch]$OpenGrafana = $true
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Banner([string]$title) {
    $bar = "═" * ($title.Length + 4)
    Write-Host ""
    Write-Host "╔$bar╗" -ForegroundColor Cyan
    Write-Host "║  $title  ║" -ForegroundColor Cyan
    Write-Host "╚$bar╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host "  ▶ $msg" -ForegroundColor Yellow
}

function Write-OK([string]$msg) {
    Write-Host "  ✅ $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "  ⚠️  $msg" -ForegroundColor DarkYellow
}

function Write-Fail([string]$msg) {
    Write-Host "  ❌ $msg" -ForegroundColor Red
}

function Wait-ForHealthy([string]$url, [int]$maxAttempts = 30, [int]$intervalSecs = 5) {
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $resp = Invoke-WebRequest -Uri $url -TimeoutSec 3 -ErrorAction Stop
            if ($resp.StatusCode -lt 400) { return $true }
        } catch { <# noop #> }
        Write-Host "    Intento $i/$maxAttempts — esperando $intervalSecs s..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $intervalSecs
    }
    return $false
}

function Get-DockerStats() {
    $containers = docker ps --filter "name=axiom" --format "{{.Names}}\t{{.Status}}" 2>$null
    return $containers
}

# ─── Main ─────────────────────────────────────────────────────────────────────

Write-Banner "AXIOM Swarm Stress Test — $Nodes nodos | $Rps rev/s | ${Duration}s"

$projectDir = $PSScriptRoot
Push-Location $projectDir

# Asegurarse de que el directorio /data existe para los .db files
Write-Step "Preparando directorio ./data para los archivos SQLite..."
if (-not (Test-Path ".\data")) {
    New-Item -ItemType Directory -Path ".\data" | Out-Null
}
Write-OK "Directorio ./data listo"

# ─── Paso 1: Build ────────────────────────────────────────────────────────────

if (-not $SkipBuild) {
    Write-Banner "Paso 1/5: Build de la imagen Docker"
    Write-Step "Construyendo axiom-node (esto puede tardar 2-5 min en el primer build)..."
    Write-Host "  💡 Usa -SkipBuild la próxima vez para omitir este paso." -ForegroundColor DarkGray
    
    $buildStart = Get-Date
    docker-compose build axiom-node axiom-bootstrap
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "docker-compose build falló. Comprueba el Dockerfile y los logs arriba."
        exit 1
    }
    $buildTime = ((Get-Date) - $buildStart).TotalSeconds
    Write-OK "Build completado en $([math]::Round($buildTime))s"
} else {
    Write-Warn "Build omitido (-SkipBuild). Usando imagen existente."
}

# ─── Paso 2: Levantar infraestructura base ────────────────────────────────────

Write-Banner "Paso 2/5: Levantar Redis, ClickHouse, Prometheus, Grafana"
Write-Step "docker-compose up -d redis clickhouse prometheus grafana..."

docker-compose up -d redis clickhouse prometheus grafana
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Error levantando infraestructura base."
    exit 1
}

Write-Step "Esperando a que ClickHouse esté healthy (puede tardar hasta 60s)..."
$chHealthy = Wait-ForHealthy -url "http://localhost:8123/?query=SELECT+1" -maxAttempts 12 -intervalSecs 5
if (-not $chHealthy) {
    Write-Fail "ClickHouse no respondió en 60s. Revisar logs: docker-compose logs clickhouse"
    exit 1
}
Write-OK "ClickHouse healthy"

# ─── Paso 3: Levantar el swarm ────────────────────────────────────────────────

Write-Banner "Paso 3/5: Levantar Swarm ($Nodes nodos)"
Write-Step "docker-compose up -d axiom-bootstrap..."

docker-compose up -d axiom-bootstrap
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Error levantando axiom-bootstrap."
    exit 1
}

Write-Step "Esperando a que axiom-bootstrap esté healthy (hasta 90s)..."
$bsHealthy = Wait-ForHealthy -url "http://localhost:3000/metrics" -maxAttempts 18 -intervalSecs 5
if (-not $bsHealthy) {
    Write-Warn "axiom-bootstrap no respondió en 90s. Intentando continuar de todas formas..."
    Write-Host "  Logs del bootstrap:" -ForegroundColor DarkGray
    docker-compose logs --tail=20 axiom-bootstrap
} else {
    Write-OK "axiom-bootstrap healthy en http://localhost:3000"
}

if ($Nodes -gt 1) {
    Write-Step "Escalando axiom-node a $Nodes contenedores..."
    $workerCount = $Nodes - 1  # El bootstrap ya cuenta como nodo 1
    docker-compose up -d --scale axiom-node=$workerCount --no-recreate
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Error escalando axiom-node."
        exit 1
    }
    Write-OK "$workerCount workers axiom-node levantados (+ 1 bootstrap = $Nodes total)"
}

# Dar tiempo a los nodos para que hagan el peer discovery
Write-Step "Esperando 15s para que los nodos hagan peer discovery por Gossipsub..."
Start-Sleep -Seconds 15

Write-Host ""
Write-Host "  Estado actual del swarm:" -ForegroundColor White
Get-DockerStats | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

# ─── Paso 4: Script de carga ──────────────────────────────────────────────────

Write-Banner "Paso 4/5: Inyección de Carga ($Rps rev/s durante ${Duration}s)"

# Verificar que Python está disponible
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") {
            $pythonCmd = $cmd
            break
        }
    } catch { <# noop #> }
}

if ($null -eq $pythonCmd) {
    Write-Fail "Python 3 no encontrado. Instala Python 3 y añádelo al PATH."
    Write-Host "  Puedes lanzar manualmente:" -ForegroundColor DarkGray
    Write-Host "    python stress_swarm.py inject --rps $Rps --duration $Duration" -ForegroundColor DarkGray
    exit 1
}

# Verificar aiohttp
$aiohttp = & $pythonCmd -c "import aiohttp; print(aiohttp.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Step "Instalando aiohttp..."
    & $pythonCmd -m pip install aiohttp --quiet
}

Write-Step "Lanzando stress_swarm.py inject..."
Write-Host ""

& $pythonCmd stress_swarm.py inject --rps $Rps --duration $Duration
$testExitCode = $LASTEXITCODE

# ─── Paso 5: Verificación ────────────────────────────────────────────────────

Write-Banner "Paso 5/5: Verificación de Propagación"

Write-Step "Esperando 10s para que el Gossip drene..."
Start-Sleep -Seconds 10

$expected = $Rps * $Duration
Write-Step "Verificando $expected eventos esperados en ClickHouse..."

& $pythonCmd stress_swarm.py verify --expected $expected

# ─── Bonus: Abrir Grafana ─────────────────────────────────────────────────────

if ($OpenGrafana) {
    Write-Banner "Abriendo Grafana"
    $grafanaUrl = "http://localhost:3001/d/axiom-swarm-stress/axiom-swarm-stress-test"
    Write-Step "Abriendo $grafanaUrl ..."
    Start-Process $grafanaUrl
    Write-OK "Grafana abierto. Credenciales: admin / admin"
}

# ─── Resumen final ────────────────────────────────────────────────────────────

Write-Banner "Test Completado"
Write-Host "  📊 Grafana        : http://localhost:3001" -ForegroundColor White
Write-Host "  🔍 Prometheus     : http://localhost:9090/targets" -ForegroundColor White
Write-Host "  🌐 Bootstrap API  : http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "  Comandos útiles:" -ForegroundColor DarkGray
Write-Host "    docker-compose logs -f axiom-bootstrap        # Logs del bootstrap" -ForegroundColor DarkGray
Write-Host "    docker-compose logs -f axiom-node             # Logs de todos los workers" -ForegroundColor DarkGray
Write-Host "    docker ps --filter name=axiom                 # Estado de contenedores" -ForegroundColor DarkGray
Write-Host "    ls ./data/                                     # Ver archivos .db por nodo" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Para parar todo:" -ForegroundColor DarkGray
Write-Host "    docker-compose down" -ForegroundColor DarkGray
Write-Host ""

Pop-Location
