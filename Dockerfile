# =============================================================================
# Multi-Stage Dockerfile for Email Assessor
# Hardened for security with Playwright pre-installed and ready on first launch
# =============================================================================

# ---------- Stage 1: Build dependencies ----------
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /build

# Install Python dependencies into a clean prefix
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- Stage 2: Production image ----------
FROM python:3.12-slim-bookworm

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="Email Assessor"
LABEL org.opencontainers.image.description="Forensic-grade local phishing analysis and link sandboxing dashboard"
LABEL org.opencontainers.image.source="https://github.com/alsoedgar/machine-learning-email-project"

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/home/appuser/.cache/ms-playwright

# Create a non-root system user with a locked password and no login shell.
# UID 10001 avoids collision with standard system users.
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /usr/sbin/nologin appuser

# Copy pre-built Python packages from the builder stage
COPY --from=builder /install /usr/local

WORKDIR /app

# Install curl (needed for Docker Healthcheck) and Playwright's system dependencies.
# We run 'playwright install-deps' as root so it installs exact OS dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && python -m playwright install-deps \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Playwright Chromium binary AS the non-root user.
# This downloads ~140MB of Chromium into /home/appuser/.cache/ms-playwright
# so it's ready immediately on container start — no first-run delay.
USER appuser
RUN python -m playwright install chromium

# Switch back to root briefly to copy source files with correct ownership
USER root
COPY --chown=appuser:appgroup . .

# Remove files that should not exist inside the container image
RUN rm -rf .venv/ .git/ __pycache__/ build/ dist/ *.spec *.exe \
    uploads/ feedback_log.csv model_state.json 2>/dev/null || true

# Create required runtime directories with correct ownership
RUN mkdir -p /app/uploads /app/data && \
    chown -R appuser:appgroup /app/uploads /app/data

# Train the ML model during build so it's ready on first launch.
# If seed data is present, this pre-computes the vocabulary and model weights.
RUN chown -R appuser:appgroup /app
USER appuser
RUN python -c "\
from analyzer import EmailAnalyzer; \
a = EmailAnalyzer(); \
print('[Docker Build] ML model state:', 'ready' if a.classifier else 'no seed data')" \
    2>/dev/null || echo "[Docker Build] Model pre-training skipped (no seed data)"

# Expose the Flask port (bound to 0.0.0.0 inside container, locked to 127.0.0.1 on host via docker-compose)
EXPOSE 5000

# Health check: verify Flask is responding every 30 seconds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Drop to non-root user permanently for runtime
USER appuser

# Run the Flask server
CMD ["python", "web_app.py"]
