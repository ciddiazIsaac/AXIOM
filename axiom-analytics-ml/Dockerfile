FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY streaming_ml.py .

EXPOSE 8001

CMD ["python", "streaming_ml.py"]
