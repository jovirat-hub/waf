# Dockerfile
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System deps for Chromium (headless)
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    ca-certificates \
    curl \
    fonts-liberation \
    fonts-noto-color-emoji \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libexpat1 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    libxrender1 \
    libxtst6 \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Pre-download Playwright/Chromium if cloakbrowser wraps playwright.
# (Uncomment if your cloakbrowser uses playwright's browser download.)
# RUN python -m playwright install chromium

COPY . .

# Railway injects $PORT at runtime; default to 8080 locally.
ENV PORT=8080
EXPOSE 8080

# Single worker — state is in-process (see notes in railway.json)
CMD ["sh", "-c", "python hostserver.py --host 0.0.0.0 --port ${PORT} --no-tunnel --proxies proxies.txt --warm-pages ${WAF_WARM_PAGES:-2}"]