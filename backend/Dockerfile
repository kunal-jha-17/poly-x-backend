# Generic container for any host that gives HTTPS (build context = kit root or backend/).
# ONE worker on purpose: state lives in memory and is serialised by a lock.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
ENV PORT=8000
# Secrets (GROQ_API_KEY) and CORS_ORIGINS come from the host's environment, never from the image.
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT} --workers 1"]
