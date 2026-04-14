FROM postgres:17

ENV PATRONI_VERSION=4.0.5

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    .build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
    "patroni[psycopg2-binary,etcd3]==${PATRONI_VERSION}"

RUN mkdir -p /var/run/postgresql \
    && chown postgres:postgres /var/run/postgresql

USER postgres
EXPOSE 5432 8008

ENTRYPOINT ["patroni", "/etc/patroni/patroni.yml"]
