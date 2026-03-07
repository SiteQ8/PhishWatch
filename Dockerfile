FROM python:3.11-slim

ARG USER=appuser
ARG UID=10001
ARG GID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates git whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install OpenSquat
RUN git clone --depth 1 https://github.com/atenreiro/opensquat.git /opt/opensquat && \
    cd /opt/opensquat && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

RUN groupadd -g ${GID} ${USER} && useradd -m -u ${UID} -g ${GID} ${USER}

COPY . /app/
RUN pip install --no-cache-dir -e .

USER ${USER}

ENV FLASK_ENV=production \
    LOG_LEVEL=INFO \
    SECRET_KEY=change-me-in-production \
    OPENSQUAT_PATH=/opt/opensquat/opensquat.py

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://127.0.0.1:5000/api/v2/status || exit 1

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "phishwatch.app:app"]
