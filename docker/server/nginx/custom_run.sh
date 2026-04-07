#!/bin/bash

set -ex;

# Replace the NGINX port in the configuration file
sed -i "s/listen [0-9]\+/listen $PORT/" /etc/nginx/nginx.conf

nginx -c /etc/nginx/nginx.conf -e /dev/stderr &

NGINX_PID="$!"

bash -c "while kill -s 0 "$$" 2>/dev/null; do sleep 1; done && echo 'Exiting Nginx!' && kill -9 "$NGINX_PID &

PORT=8081 exec python3 -m wsgi \"${@}\"
