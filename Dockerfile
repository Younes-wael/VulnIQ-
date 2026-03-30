FROM python:3.11-slim

# Install Node.js 20
RUN apt-get update && apt-get install -y curl ca-certificates && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download the real SQLite DB from GitHub LFS (avoids LFS pointer issue in Docker build)
ARG GITHUB_TOKEN
RUN mkdir -p db

# Python deps — CPU-only torch first to avoid pulling CUDA wheels
COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Node deps — cached separately so source changes don't re-run npm ci
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci

# Copy full source (node_modules and chroma excluded via .dockerignore)
COPY . .

# Build React — outputs to frontend/dist/
RUN cd frontend && npm run build

RUN curl -L \
  -H "Authorization: token ${GITHUB_TOKEN}" \
  "https://media.githubusercontent.com/media/Younes-wael/VulnIQ-/refs/heads/feat/react-frontend-and-api/db/cve.sqlite" \
  -o db/cve.sqlite

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
