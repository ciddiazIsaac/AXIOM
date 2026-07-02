import asyncio
import aiohttp
import time
import uuid
import argparse

async def inject_revocation(session, url):
    cred_id = f"cred-{uuid.uuid4()}"
    payload = {"credential_id": cred_id}
    try:
        async with session.post(url, json=payload) as response:
            await response.read()
            return True
    except Exception:
        return False

async def run_duration(duration_secs: int, rps: int, url: str):
    interval = 1.0 / rps
    deadline = time.time() + duration_secs
    count = 0
    errors = 0

    print(f"[P2P Artillery] Inyectando revocaciones a {rps} RPS durante {duration_secs}s...")
    print(f"Target: {url}")

    async with aiohttp.ClientSession() as session:
        tasks = []
        while time.time() < deadline:
            tick = time.time()
            
            # Fire one request in background to not block the event loop
            task = asyncio.create_task(inject_revocation(session, url))
            tasks.append(task)
            
            elapsed_this = time.time() - tick
            sleep_for = interval - elapsed_this
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
                
        # Wait for remaining tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception) or r is False:
                errors += 1
            else:
                count += 1

    print(f"[P2P Artillery] ✅ {count} revocaciones inyectadas | {errors} errores en {duration_secs}s")
    print(f"[P2P Artillery] RPS efectivo: {count / duration_secs:.1f}")

def main():
    parser = argparse.ArgumentParser(description="AXIOM P2P Revocation Load Test")
    parser.add_argument("--duration", type=int, default=300, help="Duración del test en segundos (default: 300 = 5 mins)")
    parser.add_argument("--rps", type=int, default=100, help="Revocaciones por segundo (default: 100)")
    parser.add_argument("--url", type=str, default="http://localhost:3000/v1/revoke", help="URL objetivo")
    args = parser.parse_args()

    asyncio.run(run_duration(args.duration, args.rps, args.url))

if __name__ == "__main__":
    main()
