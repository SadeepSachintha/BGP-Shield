FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy engine application code
COPY . .

# Ensure data directory exists for DuckDB persistence
RUN mkdir -p /app/data

# Expose FastAPI HTTP/WebSocket port (8000) and NetFlow UDP collector port (2055)
EXPOSE 8000
EXPOSE 2055/udp

CMD ["python", "run_engine.py"]
