FROM python:3.11-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Node.js 20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Playwright for screenshots
RUN pip install playwright==1.40.0 \
    && playwright install chromium \
    && playwright install-deps chromium \
    || true

# Frontend build
COPY frontend/package.json frontend/package-lock.json* ./frontend/
WORKDIR /app/frontend
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# Backend
WORKDIR /app
COPY backend/ ./backend/

# Screenshots directory
RUN mkdir -p /app/backend/screenshots

ENV PYTHONUNBUFFERED=1
ENV API_HOST=0.0.0.0
ENV API_PORT=8001

EXPOSE 8001

WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
