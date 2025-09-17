FROM python:3.11-slim

# Install system dependencies for OpenCV and face processing
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libavcodec-dev \
    libavformat-dev \
    libswscale-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download InsightFace models during build
RUN python -c "import insightface; app = insightface.app.FaceAnalysis(name='buffalo_l'); app.prepare(ctx_id=0, det_size=(640, 640))"

# Copy application code
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Expose port
EXPOSE 10000

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=10000
ENV STRONGHOLD_CONFIG_FILE=/app/stronghold.prod.yaml

# Start command
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "10000"]
