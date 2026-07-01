import asyncio
import aiohttp
import time
import argparse

URL = "http://localhost:3000/v1/evaluate"
PAYLOAD = {
    "subject": {"did": "did:axiom:test:user1", "clearance_level": 3, "roles": ["user"]},
    "resource": {"id": "res:test", "classification": "public", "owner": "system"},
    "context": {"device_id": "dev1", "ip_address": "1.2.3.4", "geolocation": "US", "time_of_day": "12:00:00"},
    "session": {"session_id": "sess1", "device_trust_score": 90, "mfa_verified": True, "biometric_verified": True}
}

async def fetch(session):
    try:
        async with session.post(URL, json=PAYLOAD) as response:
            await response.read()
    except Exception:
        pass  # No abortar el test por errores individuales

# ── Modo 1: Bulk (original) ───────────────────────────────────────────────────

async def worker_bulk(name, session, requests_per_worker):
    for _ in range(requests_per_worker):
        await fetch(session)

async def run_bulk(total_requests: int, workers: int):
    requests_per_worker = total_requests // workers
    print(f"[Bulk] Meta: {total_requests} requests | {workers} workers | {requests_per_worker} req/worker")
    start = time.time()
    async with aiohttp.ClientSession() as session:
        tasks = [worker_bulk(i, session, requests_per_worker) for i in range(workers)]
        await asyncio.gather(*tasks)
    elapsed = time.time() - start
    print(f"[Bulk] Finalizado en {elapsed:.2f}s — {total_requests / elapsed:.0f} RPS efectivos")

# ── Modo 2: Duration (demo) ───────────────────────────────────────────────────

async def run_duration(duration_secs: int, rps: int):
    """
    Genera tráfico continuo durante `duration_secs` segundos a `rps` req/s.
    Ideal para precalentar ClickHouse antes de la demo:
        python load_test.py --duration 30 --rps 200
    """
    interval = 1.0 / rps  # segundos entre requests
    deadline = time.time() + duration_secs
    count = 0
    errors = 0

    print(f"[Demo] Calentando ClickHouse durante {duration_secs}s a {rps} RPS...")
    print(f"[Demo] URL: {URL}")

    async with aiohttp.ClientSession() as session:
        while time.time() < deadline:
            tick = time.time()
            try:
                async with session.post(URL, json=PAYLOAD) as resp:
                    await resp.read()
                    count += 1
            except Exception:
                errors += 1
            # Respetar el RPS objetivo: esperar el resto del intervalo
            elapsed_this = time.time() - tick
            sleep_for = interval - elapsed_this
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

    print(f"[Demo] ✅ {count} requests exitosos | {errors} errores en {duration_secs}s")
    print(f"[Demo] RPS efectivo: {count / duration_secs:.1f}")

# ── Entrypoint ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AXIOM Load Test — Bulk o modo demo con --duration"
    )
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Modo demo: generar tráfico continuo durante N segundos (ej: --duration 30)"
    )
    parser.add_argument(
        "--rps", type=int, default=200,
        help="Requests por segundo en modo --duration (default: 200)"
    )
    parser.add_argument(
        "--total", type=int, default=60000,
        help="Total de requests en modo bulk (default: 60000)"
    )
    parser.add_argument(
        "--workers", type=int, default=100,
        help="Workers concurrentes en modo bulk (default: 100)"
    )
    args = parser.parse_args()

    if args.duration is not None:
        asyncio.run(run_duration(args.duration, args.rps))
    else:
        print(f"Starting theatrical load test...")
        print(f"Goal: {args.total} requests in ~60 seconds (1000 RPS).")
        asyncio.run(run_bulk(args.total, args.workers))

if __name__ == "__main__":
    main()
