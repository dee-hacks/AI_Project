FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Scapy and other native libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements/base.txt requirements/prod.txt /app/requirements/
RUN pip install --no-cache-dir -r requirements/prod.txt

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/
COPY scripts/ /app/scripts/

# Create data directories
RUN mkdir -p /app/data/models /app/data/benchmarks

EXPOSE 8000

CMD ["uvicorn", "src.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--factory"]