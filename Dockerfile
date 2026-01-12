# Use Python 3.10 slim image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install system dependencies for Tkinter, SQLite, and nano
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-tk \
        libsqlite3-dev \
        nano \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --upgrade pip

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create persistent directories
RUN mkdir -p /app/data/files /app/data/share

# Copy application files
COPY core ./core
COPY gui ./gui
COPY main.py .

# Default command to run the app
CMD ["python", "main.py"]
