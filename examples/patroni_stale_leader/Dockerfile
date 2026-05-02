FROM postgres:17

ENV PATRONI_VERSION=4.0.5

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "v${PATRONI_VERSION}" https://github.com/patroni/patroni.git /tmp/patroni \
    && cd /tmp/patroni \
    && git config user.email "pakostii@example.local" \
    && git config user.name "pakostii" \
    && for pr in 3318 3338 3341 3373; do \
        curl -fsSL "https://github.com/patroni/patroni/pull/${pr}.patch" | git am; \
    done \
    && pip3 install --no-cache-dir --break-system-packages ".[psycopg2-binary,etcd3]" \
    && rm -rf /tmp/patroni

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5432 8008

USER root
ENTRYPOINT ["/entrypoint.sh"]
