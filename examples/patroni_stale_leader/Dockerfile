FROM postgres:17

ENV PATRONI_VERSION=4.0.5

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
    "patroni[psycopg2-binary,etcd3]==${PATRONI_VERSION}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5432 8008

USER root
ENTRYPOINT ["/entrypoint.sh"]