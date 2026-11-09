# SentinelAI inference engine. Python 3.11 + the pinned requirements: the registered models were pickled
# with scikit-learn 1.4.0 and the engine refuses to load them under another version.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY inference ./inference
COPY rl_engine ./rl_engine
COPY utils ./utils
COPY monitoring ./monitoring
COPY modular ./modular
COPY training ./training
COPY evaluation ./evaluation
COPY models ./models

RUN useradd --system --uid 10001 sentinel && mkdir -p /data && chown sentinel /data
USER sentinel

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2).status == 200 else 1)"
CMD ["python", "-m", "uvicorn", "inference.main:app", "--host", "0.0.0.0", "--port", "8000"]
