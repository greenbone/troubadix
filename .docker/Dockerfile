FROM greenbone/openvas-scanner:latest

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    build-essential \
    python3 \
    python3-pip \
    codespell && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

COPY oldlint /linting