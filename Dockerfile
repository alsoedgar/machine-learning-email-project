# Use an official Python runtime with Playwright pre-installed dependencies
FROM python:3.11-slim-bookworm

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/home/appuser/.cache/ms-playwright

# Install system dependencies needed for Playwright Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk-1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    librandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root system user for security isolation
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

# Copy python dependencies list and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium binary as non-root user
USER appuser
RUN python -m playwright install chromium

# Copy application source code
USER root
COPY --chown=appuser:appgroup . .

# Set user context back to non-root
USER appuser

EXPOSE 5000

# Run Flask backend server
CMD ["python", "web_app.py"]
