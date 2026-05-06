# Production image for Railway (replaces deprecated Nixpacks).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY backend ./backend

WORKDIR /app/backend

# Railway sets PORT at runtime; shell form expands $PORT.
CMD sh -c 'exec python -m gunicorn app.main:app -k uvicorn.workers.UvicornWorker --workers 2 --bind "0.0.0.0:${PORT:-8000}"'
