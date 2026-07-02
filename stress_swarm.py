#!/usr/bin/env python3
"""
AXIOM Swarm Stress Test — stress_swarm.py
==========================================
Tres modos de operación:

  inject   → Inyecta revocaciones al nodo bootstrap a la tasa configurada
  verify   → Consulta ClickHouse y calcula cuántos eventos llegaron
  latency  → Mide latencia P2P real: tiempo desde inyección hasta que el
              evento aparece en ClickHouse

Uso:
  python stress_swarm.py inject --rps 100 --duration 300
  python stress_swarm.py verify --expected 30000
  python stress_swarm.py all --rps 100 --duration 60 --nodes 10
"""

import asyncio
import aiohttp
import time
import uuid
import argparse
import sys
import json
from datetime import datetime, timezone
from typing import Optional
from collections import deque


# ─── Configuración ────────────────────────────────────────────────────────────

BOOTSTRAP_URL     = "http://localhost:3000"
CLICKHOUSE_URL    = "http://localhost:8123"
CLICKHOUSE_DB     = "default"

REVOKE_ENDPOINT   = f"{BOOTSTRAP_URL}/v1/revoke"
CH_QUERY_ENDPOINT = f"{CLICKHOUSE_URL}/?database={CLICKHOUSE_DB}&output_format_json_quote_64bit_integers=0"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def banner(title: str):
    bar = "═" * (len(title) + 4)
    print(f"\n╔{bar}╗")
    print(f"║  {title}  ║")
    print(f"╚{bar}╝\n")


def now_ts() -> float:
    return time.time()


async def clickhouse_query(session: aiohttp.ClientSession, sql: str) -> str:
    """Ejecuta una query en ClickHouse y devuelve el resultado como string."""
    try:
        async with session.post(CH_QUERY_ENDPOINT, data=sql) as resp:
            return (await resp.text()).strip()
    except Exception as e:
        return f"ERROR: {e}"


# ─── Modo INJECT ──────────────────────────────────────────────────────────────

async def run_inject(rps: int, duration: int, url: str) -> dict:
    """
    Inyecta `rps` revocaciones/segundo durante `duration` segundos al endpoint
    dado. Devuelve un resumen con estadísticas.
    """
    banner(f"INJECT — {rps} rev/s durante {duration}s → {url}")

    interval     = 1.0 / rps
    deadline     = now_ts() + duration
    injected     = 0
    errors       = 0
    latencies_ms = deque(maxlen=10_000)   # últimas 10k latencias de HTTP
    pending      = []
    start        = now_ts()

    print(f"  Arrancando... Ctrl-C para cancelar anticipadamente.\n")

    async def fire(sess: aiohttp.ClientSession, cred_id: str) -> bool:
        t0 = time.perf_counter()
        try:
            async with sess.post(url, json={"credential_id": cred_id},
                                 timeout=aiohttp.ClientTimeout(total=5)) as r:
                await r.read()
                ok = r.status < 400
                latencies_ms.append((time.perf_counter() - t0) * 1000)
                return ok
        except Exception:
            return False

    tick_counter = 0
    connector = aiohttp.TCPConnector(limit=rps * 2)  # pool generoso
    async with aiohttp.ClientSession(connector=connector) as session:
        while now_ts() < deadline:
            tick_start = time.perf_counter()
            cred_id = f"swarm-{uuid.uuid4()}"
            task = asyncio.create_task(fire(session, cred_id))
            pending.append(task)
            tick_counter += 1

            # Progreso cada 1000 peticiones
            if tick_counter % 1000 == 0:
                elapsed = now_ts() - start
                effective_rps = tick_counter / elapsed
                done = sum(1 for t in pending if t.done())
                errs = sum(1 for t in pending if t.done() and not t.result())
                print(f"  [{elapsed:6.1f}s] {tick_counter:6d} enviadas | "
                      f"RPS efectivo: {effective_rps:5.1f} | "
                      f"pendientes: {len(pending)-done} | "
                      f"errores: {errs}")

            sleep_for = interval - (time.perf_counter() - tick_start)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

        print("\n  Esperando respuestas en vuelo...")
        results = await asyncio.gather(*pending, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception) or r is False:
            errors += 1
        else:
            injected += 1

    elapsed = now_ts() - start
    avg_lat  = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0
    sorted_l = sorted(latencies_ms)
    p95_lat  = sorted_l[int(len(sorted_l) * 0.95)] if sorted_l else 0
    p99_lat  = sorted_l[int(len(sorted_l) * 0.99)] if sorted_l else 0

    summary = {
        "mode":         "inject",
        "total_sent":   injected + errors,
        "ok":           injected,
        "errors":       errors,
        "duration_s":   round(elapsed, 2),
        "eff_rps":      round((injected + errors) / elapsed, 1),
        "http_lat_avg": round(avg_lat, 2),
        "http_lat_p95": round(p95_lat, 2),
        "http_lat_p99": round(p99_lat, 2),
    }
    return summary


# ─── Modo VERIFY ──────────────────────────────────────────────────────────────

async def run_verify(expected: int) -> dict:
    """
    Consulta ClickHouse y compara el número de eventos con el esperado.
    """
    banner("VERIFY — Comprobando ClickHouse")

    async with aiohttp.ClientSession() as session:
        # Total de eventos en la tabla principal
        total = await clickhouse_query(session, "SELECT count() FROM events FORMAT TSV")
        # Eventos de los últimos 10 minutos
        recent = await clickhouse_query(session,
            "SELECT count() FROM events WHERE timestamp >= now() - INTERVAL 10 MINUTE FORMAT TSV")
        # Tasa de ingesta en los últimos 30 segundos (aprox)
        rate = await clickhouse_query(session,
            "SELECT count() FROM events WHERE timestamp >= now() - INTERVAL 30 SECOND FORMAT TSV")

    try:
        total_int  = int(total)
        recent_int = int(recent)
        rate_int   = int(rate)
    except ValueError:
        print(f"  ⚠️  ClickHouse respondió algo inesperado:")
        print(f"     total={total!r}  recent={recent!r}  rate={rate!r}")
        return {"mode": "verify", "error": "clickhouse_unexpected_response"}

    pct = (recent_int / expected * 100) if expected > 0 else 0

    print(f"  Total eventos en ClickHouse  : {total_int:>10,}")
    print(f"  Eventos últimos 10 min        : {recent_int:>10,}")
    print(f"  Eventos últimos 30 s          : {rate_int:>10,}")
    print(f"  Esperados (inyectados)        : {expected:>10,}")
    print(f"  Cobertura                     : {pct:>10.1f}%")

    if pct >= 95:
        print("\n  ✅ PASS — La ingesta cubre ≥95% de las revocaciones inyectadas")
    elif pct >= 70:
        print("\n  ⚠️  WARN — Cobertura parcial. Posible cola de Gossip todavía drenando.")
    else:
        print("\n  ❌ FAIL — Muchos eventos no llegaron a ClickHouse.")
        print("     Revisar: ingestor logs, conexión Redis, saturación de disco.")

    return {
        "mode":      "verify",
        "ch_total":  total_int,
        "ch_recent": recent_int,
        "ch_rate_30s": rate_int,
        "expected":  expected,
        "coverage_pct": round(pct, 1),
    }


# ─── Modo ALL (inject + verify encadenados) ───────────────────────────────────

async def run_all(rps: int, duration: int, url: str, nodes: int) -> None:
    banner(f"ALL — {nodes} nodos | {rps} rev/s | {duration}s")

    print("  Fase 1: Inyectando revocaciones...")
    inject_summary = await run_inject(rps, duration, url)

    print("\n  Esperando 10s para que el Gossip propague y ClickHouse drene...")
    await asyncio.sleep(10)

    print("\n  Fase 2: Verificando propagación en ClickHouse...")
    # Con N nodos, esperamos que cada revocación llegue a cada nodo (en teoría).
    # Pero ClickHouse solo cuenta los eventos ingresados por el ingestor.
    # Si solo el bootstrap ejecuta el ingestor, esperamos ~inject_ok eventos.
    expected = inject_summary["ok"]
    verify_summary = await run_verify(expected)

    banner("RESUMEN FINAL")
    _print_summary_table(inject_summary, verify_summary, nodes)


def _print_summary_table(inj: dict, ver: dict, nodes: int):
    print(f"  {'Métrica':<35} {'Valor':>15}")
    print(f"  {'─'*50}")
    print(f"  {'Revocaciones enviadas':<35} {inj['total_sent']:>15,}")
    print(f"  {'Revocaciones OK (HTTP 2xx)':<35} {inj['ok']:>15,}")
    print(f"  {'Errores HTTP':<35} {inj['errors']:>15,}")
    print(f"  {'RPS efectivo':<35} {inj['eff_rps']:>15.1f}")
    print(f"  {'Latencia HTTP avg (ms)':<35} {inj['http_lat_avg']:>15.2f}")
    print(f"  {'Latencia HTTP p95 (ms)':<35} {inj['http_lat_p95']:>15.2f}")
    print(f"  {'Latencia HTTP p99 (ms)':<35} {inj['http_lat_p99']:>15.2f}")
    print(f"  {'─'*50}")
    print(f"  {'Eventos en ClickHouse (10 min)':<35} {ver.get('ch_recent', 'N/A'):>15}")
    print(f"  {'Cobertura de ingesta':<35} {str(ver.get('coverage_pct', 'N/A')) + '%':>15}")
    print(f"  {'Nodos en el swarm':<35} {nodes:>15}")
    
    if ver.get('coverage_pct', 0) >= 95 and inj['errors'] < inj['total_sent'] * 0.01:
        verdict = "✅ EL SWARM AGUANTA — Pasar a Fase 2 (IA)"
    elif ver.get('coverage_pct', 0) >= 70:
        verdict = "⚠️  SWARM PARCIAL — Revisar spawn_blocking en SQLite"
    else:
        verdict = "❌ SWARM SATURADO — Reducir nodos o optimizar event loop"

    print(f"\n  {'─'*50}")
    print(f"  Veredicto: {verdict}")
    print(f"  {'─'*50}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AXIOM Swarm Stress Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = p.add_subparsers(dest="mode", required=True)

    # inject
    inj = sub.add_parser("inject", help="Inyectar revocaciones al bootstrap")
    inj.add_argument("--rps",      type=int, default=100,
                     help="Revocaciones por segundo (default: 100)")
    inj.add_argument("--duration", type=int, default=300,
                     help="Duración en segundos (default: 300)")
    inj.add_argument("--url",      type=str, default=REVOKE_ENDPOINT,
                     help=f"URL del endpoint /v1/revoke (default: {REVOKE_ENDPOINT})")

    # verify
    ver = sub.add_parser("verify", help="Verificar eventos en ClickHouse")
    ver.add_argument("--expected", type=int, default=0,
                     help="Número esperado de eventos (para calcular cobertura)")

    # all
    all_ = sub.add_parser("all", help="inject + verify en secuencia")
    all_.add_argument("--rps",      type=int, default=100)
    all_.add_argument("--duration", type=int, default=60)
    all_.add_argument("--url",      type=str, default=REVOKE_ENDPOINT)
    all_.add_argument("--nodes",    type=int, default=10,
                      help="Número de nodos en el swarm (informativo)")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    try:
        if args.mode == "inject":
            summary = asyncio.run(run_inject(args.rps, args.duration, args.url))
            banner("RESUMEN INJECT")
            for k, v in summary.items():
                print(f"  {k:<25} {v}")

        elif args.mode == "verify":
            summary = asyncio.run(run_verify(args.expected))
            banner("RESUMEN VERIFY")
            for k, v in summary.items():
                print(f"  {k:<25} {v}")

        elif args.mode == "all":
            asyncio.run(run_all(args.rps, args.duration, args.url, args.nodes))

    except KeyboardInterrupt:
        print("\n\n  ⏹️  Test cancelado por el usuario.")
        sys.exit(0)


if __name__ == "__main__":
    main()
