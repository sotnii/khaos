#!/bin/bash
set -e

mkdir -p /var/lib/postgresql/data
mkdir -p /var/run/postgresql

chown -R postgres:postgres /var/lib/postgresql
chown -R postgres:postgres /var/run/postgresql

chmod 0700 /var/lib/postgresql/data
chmod 0775 /var/run/postgresql

exec gosu postgres patroni /etc/patroni/patroni.yml