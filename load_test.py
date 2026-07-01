import asyncio
import aiohttp
import time

URL = "http://localhost:3000/v1/evaluate"
PAYLOAD = {
    "subject": {"did": "did:axiom:test:user1", "clearance_level": 3, "roles": ["user"]},
    "resource": {"id": "res:test", "classification": "public", "owner": "system"},
    "context": {"device_id": "dev1", "ip_address": "1.2.3.4", "geolocation": "US", "time_of_day": "12:00:00"},
    "session": {"session_id": "sess1", "device_trust_score": 90, "mfa_verified": True, "biometric_verified": True}
}

async def fetch(session):
    async with session.post(URL, json=PAYLOAD) as response:
        await response.read()

async def worker(name, session, requests_per_worker):
    for _ in range(requests_per_worker):
        await fetch(session)

async def main():
    total_requests = 60000
    workers = 100
    requests_per_worker = total_requests // workers
    
    print(f"Starting theatrical load test...")
    print(f"Goal: {total_requests} requests in ~60 seconds (1000 RPS).")
    start = time.time()
    
    # We will throttle somewhat to maintain exactly 1000 RPS, but for theatrical purposes
    # a raw blast of asyncio workers is usually fine.
    async with aiohttp.ClientSession() as session:
        tasks = [worker(i, session, requests_per_worker) for i in range(workers)]
        await asyncio.gather(*tasks)
        
    end = time.time()
    print(f"Finished in {end - start:.2f} seconds. RPS: {total_requests / (end - start):.2f}")

if __name__ == "__main__":
    asyncio.run(main())
