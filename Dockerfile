# ==============================================================================
# HS_WSS - HS Tech Web Secret Scanner Dockerfile
# Base: Official Microsoft Playwright Jammy image with Python and Chromium
# Complies with Checkov, Trivy, and DevSecOps security standards (Non-root, Healthcheck)
# ==============================================================================
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

# Set environment flags
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8659 \
    HOST=0.0.0.0

# Set working directory
WORKDIR /opt/hs_wss

# Install project dependencies
COPY requirements.txt /opt/hs_wss/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Create data directory and ensure ownership for non-root user 'pwuser'
RUN mkdir -p /opt/hs_wss/data && \
    chown -R pwuser:pwuser /opt/hs_wss

# Copy application source code
COPY --chown=pwuser:pwuser . /opt/hs_wss

# Switch to unprivileged non-root user (Checkov CKV_DOCKER_3)
USER pwuser

# Expose web panel port
EXPOSE 8659

# Healthcheck definition (Checkov CKV_DOCKER_2)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request, os; port=os.environ.get('PORT', '8659'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health')" || exit 1

# Start ephemeral web panel and secret scanner engine
CMD ["python3", "-m", "app.main"]
