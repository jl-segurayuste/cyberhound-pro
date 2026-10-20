# ─────────────────────────────────────────────────────────────────────────────
# CyberHound Pro — Dockerfile multi-stage
#
# Stage 1 (builder): instala dependencias Python en un venv aislado
# Stage 2 (runtime): imagen mínima de producción
#
# Build:  docker build -t cyberhound-pro:latest .
# Run:    docker run -d -p 8443:8443 --cap-add NET_ADMIN --cap-add NET_RAW \
#           -v cyberhound-data:/root/.cyberhound cyberhound-pro:latest
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Dependencias de sistema para compilar extensiones C (yara-python, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libffi-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar solo los ficheros de metadatos primero (mejor cache de layers)
COPY pyproject.toml ./

# Crear venv e instalar dependencias
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel --quiet

# Copiar el código fuente e instalar el paquete
COPY cyberhound/ ./cyberhound/
RUN /opt/venv/bin/pip install --quiet ".[postgres]" && \
    /opt/venv/bin/pip install --quiet yara-python || true

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="CyberHound Pro" \
      org.opencontainers.image.description="Plataforma de auditoría y seguridad para PYMEs" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/jl-segurayuste/cyberhound-pro"

# Herramientas de sistema necesarias en runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Escaneo de red
    nmap \
    arp-scan \
    iproute2 \
    iputils-ping \
    # Análisis de código
    shellcheck \
    # Auditoría del sistema
    auditd \
    # OpenSSH client para conexiones remotas
    openssh-client \
    # libyara runtime (sin dev headers)
    libyara10 \
    # Utilidades
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copiar el venv compilado desde el builder
COPY --from=builder /opt/venv /opt/venv

# Directorio de la aplicación
WORKDIR /app

# Copiar código fuente (para que la UI sirva los ficheros estáticos)
COPY cyberhound/ ./cyberhound/
COPY pyproject.toml ./

# Variables de entorno
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Volumen para configuración persistente y logs
VOLUME ["/data"]

# Puerto de la interfaz web
EXPOSE 8443

# Script de entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -fsk https://localhost:8443/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["web", "--port", "8443"]
