FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmagic1 \
    zlib1g-dev \
    libjpeg62-turbo-dev \
    libffi-dev \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/app

COPY readflag.c /tmp/readflag.c
RUN gcc -O2 -Wall -Wextra -o /readflag /tmp/readflag.c && \
    chown root:root /readflag && \
    chmod 4755 /readflag && \
    rm -f /tmp/readflag.c

COPY flag.txt /flag.txt
RUN chown root:root /flag.txt && chmod 0400 /flag.txt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN useradd -r -s /bin/false appuser && \
    mkdir -p /data/uploads && \
    chown -R appuser:appuser /data

USER appuser

EXPOSE 80

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80", "--workers", "4", "--proxy-headers", "--forwarded-allow-ips", "*"]
