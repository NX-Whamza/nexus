FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NEXUS_UVICORN_WORKERS=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    iproute2 \
    iputils-ping \
    net-tools \
    libsnmp-dev \
    libsmi2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["sh", "-c", "uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000 --workers ${NEXUS_UVICORN_WORKERS:-1}"]
