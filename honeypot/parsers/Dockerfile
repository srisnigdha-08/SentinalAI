# Cowrie log parser image for docker-compose.honeypot.yml (untested: Docker was not available when written).
FROM python:3.12-slim
RUN pip install --no-cache-dir requests==2.32.3 \
 && useradd --system --uid 10001 --no-create-home parser
COPY log_parser.py /app/log_parser.py
USER parser
ENTRYPOINT ["python", "-I", "/app/log_parser.py"]
