# SmartVuln dashboard image (the scanners run as their own official containers).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY smartvuln/ smartvuln/
COPY config/ config/
COPY custom_rules/ custom_rules/
COPY evaluation/ evaluation/

RUN useradd --create-home --uid 10001 smartvuln && mkdir -p /app/data && chown smartvuln /app/data
USER smartvuln
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/healthz')"
# 0.0.0.0 inside the container only; compose publishes it on 127.0.0.1
CMD ["python", "-m", "smartvuln", "serve", "--host", "0.0.0.0", "--port", "5000"]
