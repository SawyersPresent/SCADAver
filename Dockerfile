FROM python:3.13-slim

LABEL maintainer="ICS Red Team"
LABEL description="ICSTool — Unified ICS Red Team Multi-Tool"

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir ".[spoof]"

ENTRYPOINT ["icstool"]
CMD ["--help"]
