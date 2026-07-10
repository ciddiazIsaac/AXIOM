import asyncio
import json
import logging
import os
import redis.asyncio as redis
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks

from river import anomaly
from river import compose
from river import preprocessing

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("streaming_ml")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_STREAM = "axiom:audit:stream"
CONSUMER_GROUP = "axiom_analytics_ml"
CONSUMER_NAME = "ml-worker-1"

# The River model. HalfSpaceTrees is an online anomaly detection algorithm.
# We normalize the features first.
model = compose.Pipeline(
    preprocessing.StandardScaler(),
    anomaly.HalfSpaceTrees(
        n_trees=25,
        height=15,
        window_size=250,
        seed=42
    )
)

redis_client = None

async def init_redis_group():
    global redis_client
    redis_client = redis.from_url(REDIS_URL)
    try:
        await redis_client.xgroup_create(REDIS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info(f"Created consumer group {CONSUMER_GROUP}")
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.info(f"Consumer group {CONSUMER_GROUP} already exists")
        else:
            raise e

def process_event(event_id, event_data):
    """
    Extracts features from the event, scores it for anomalies, and updates the model.
    """
    try:
        data_str = event_data.get(b"data", b"{}").decode("utf-8")
        event = json.loads(data_str)
        
        # Extract features for anomaly detection
        # We can use latency_ms, risk_score, and any continuous features from context
        latency = float(event.get("latency_ms", 0.0))
        risk_score = float(event.get("risk_score", 0.0))
        
        context = event.get("context_snapshot", {})
        distance = float(context.get("env", {}).get("distance_km", 0.0))
        
        features = {
            "latency": latency,
            "risk_score": risk_score,
            "distance": distance,
        }
        
        # 1. Score the current event (before learning it)
        anomaly_score = model.score_one(features)
        
        # 2. Learn the event
        model.learn_one(features)
        
        if anomaly_score > 0.8:
            logger.warning(f"Anomaly detected! Score: {anomaly_score:.2f} | User: {event.get('user_did')} | Latency: {latency}")
            
    except Exception as e:
        logger.error(f"Error processing event {event_id}: {e}")

async def consume_stream():
    """
    Continuously consumes the Redis stream and processes events.
    """
    logger.info("Starting Redis stream consumer for ML...")
    while True:
        try:
            # Read messages from the stream
            response = await redis_client.xreadgroup(
                CONSUMER_GROUP, 
                CONSUMER_NAME, 
                {REDIS_STREAM: ">"}, 
                count=100, 
                block=1000
            )
            
            if response:
                for stream_name, messages in response:
                    for message_id, message_data in messages:
                        process_event(message_id, message_data)
                        # Acknowledge the message
                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, message_id)
        except Exception as e:
            logger.error(f"Error in consumer loop: {e}")
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_redis_group()
    # Start the background consumer task
    task = asyncio.create_task(consume_stream())
    yield
    # Shutdown
    task.cancel()
    if redis_client:
        await redis_client.aclose()

app = FastAPI(lifespan=lifespan)

@app.get("/health")
async def health():
    return {"status": "ok", "model_type": "HalfSpaceTrees"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("streaming_ml:app", host="0.0.0.0", port=8001, reload=True)
