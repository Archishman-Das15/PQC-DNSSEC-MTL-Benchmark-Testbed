FROM pqcmtl/tools:latest

# Install docker CLI so web terminal can execute docker / tb.sh commands
RUN apt-get update && apt-get install -y --no-install-recommends \
        docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install FastAPI, Uvicorn and WebSockets
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 websockets

WORKDIR /work
EXPOSE 8080

CMD ["python3", "ui/server.py"]
