#!/bin/bash

set -ex;

apk --no-cache add \
        bzip2-dev \
        expat-dev \
        gdbm-dev \
        libc-dev \
        linux-headers \
        ncurses-dev \
        openssl-dev \
        pax-utils \
        readline-dev \
        sqlite-dev \
        tar \
        tk \
        tk-dev \
        xz-dev \
        zlib-dev \
        gcc \
        g++ \
        make \
        musl-dev \
        libffi-dev;

cd /opt/pypy/lib/pypy*

for filename in _*build*.py; do
    if [[ $filename == *"winbase_build.py" ]]; then
        echo "[RECOMP] Skipping ${filename}";
        continue;
    fi;
    echo "[RECOMP] building ${filename}"
    python3 "$filename";
done;

python3 -m ensurepip

pip3 install --no-cache --upgrade pip

apk --no-cache add libbz2 libgcc
