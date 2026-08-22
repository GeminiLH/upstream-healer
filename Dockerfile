FROM python:3.12-slim-bookworm

# Install system dependencies for network scanning and general tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    iproute2 \
    iputils-ping \
    net-tools \
    arp-scan \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Create data directory
RUN mkdir -p /data

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8787

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8787", "--workers", "1"]
