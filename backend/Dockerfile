# Generic container for any host that gives HTTPS (build context = backend/).
# ONE worker on purpose: state lives in memory and is serialised by a lock.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd --create-home --uid 10001 polyx
USER polyx
ENV PORT=8000
# Secrets (GROQ_API_KEY, POLYX_ADMIN_TOKEN) and CORS_ORIGINS come from the host's environment, never from the image.
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
