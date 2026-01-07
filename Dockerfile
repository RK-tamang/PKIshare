# PKIshare - Secure Digital Certificate File Sharing System
# Dockerfile

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libxext6 \
    libxrender1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY core/ ./core/
COPY gui/ ./gui/

# Create data directory
RUN mkdir -p /app/data /app/core/files /app/core/share

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DISPLAY=:0

# Expose port (if web interface is added)
EXPOSE 8000

# Run the application
CMD ["python", "main.py"]

