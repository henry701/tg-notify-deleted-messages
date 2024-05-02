FROM alpine:3 AS base

FROM base AS common
ENV PYTHONUNBUFFERED=1
RUN apk --no-cache add bash
RUN apk --no-cache add openssl
RUN apk --no-cache add libffi
ARG SUPPORTS_PGSQL=1
RUN if [[ "$SUPPORTS_PGSQL" -eq 1 ]]; then apk --no-cache add libpq; fi

FROM alpine:3.15 AS pypy-builder
RUN apk --no-cache add python2
RUN apk --no-cache add gcc
RUN apk --no-cache add g++
RUN apk --no-cache add python3-dev
RUN apk --no-cache add dos2unix
RUN apk --no-cache add musl-dev
RUN apk --no-cache add cargo
RUN apk --no-cache add libffi-dev
RUN apk --no-cache add make
RUN apk --no-cache add curl
RUN apk --no-cache add wget
RUN apk --no-cache add git
RUN apk add --no-cache \
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
        zlib-dev;
ENV PIP_BREAK_SYSTEM_PACKAGES 1
RUN rm -f /usr/lib/python*/EXTERNALLY-MANAGED
RUN python -m ensurepip
RUN pip install --no-cache --upgrade pip
RUN pip install --no-cache-dir pycparser
# Download the source
ENV PYPY_VERSION "pypy3.10-v7.3.16-src.tar.bz2"
ENV PYPY_SHA256SUM 4a3a3177d0a1f51d59982bb981d1d485403bda3419d5437b9e077f55f59424ff
RUN set -ex; \
    wget -O pypy.tar.bz2 "https://downloads.python.org/pypy/${PYPY_VERSION}"; \
    echo "$PYPY_SHA256SUM *pypy.tar.bz2" | sha256sum -c -; \
    mkdir -p /usr/src/pypy; \
    tar -xjC /usr/src/pypy --strip-components=1 -f pypy.tar.bz2; \
    rm pypy.tar.bz2;
RUN apk --no-cache add bash
COPY ./docker/build.sh /build.sh
RUN dos2unix /build.sh
RUN bash build.sh
RUN cp -a "pypy-v${PYPY_VERSION}-linux64-alpine$(cut -d. -f1,2 /etc/alpine-release)" /pypy

FROM common AS builder
RUN apk --no-cache add gcc
RUN apk --no-cache add g++
RUN apk --no-cache add python3-dev
RUN apk --no-cache add dos2unix
RUN apk --no-cache add musl-dev
RUN apk --no-cache add cargo
RUN apk --no-cache add libffi-dev
RUN apk --no-cache add make
RUN apk --no-cache add curl
RUN apk --no-cache add wget
ARG SUPPORTS_PGSQL=1
RUN if [[ "$SUPPORTS_PGSQL" -eq 1 ]]; then apk --no-cache add postgresql-dev; fi
COPY --from=pypy-builder /pypy /usr/bin/pypy
RUN ln -sf /usr/bin/pypy /usr/bin/python
RUN ln -sf /usr/bin/pypy /usr/bin/python3
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip
RUN pip3 install --no-cache --upgrade pip setuptools wheel
RUN mkdir -p /usr/app/conf/
COPY ./app/meta/requirements/. /usr/app/meta/requirements/.
RUN pip3 install --no-cache -r /usr/app/meta/requirements/base.txt
ARG SUPPORTS_PGSQL=1
RUN if [[ "$SUPPORTS_PGSQL" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/pgsql.txt; fi
RUN pip3 install --no-cache -r /usr/app/meta/requirements/db_cripto.txt
RUN pip3 install --no-cache -r /usr/app/meta/requirements/perf.txt
ARG SUPPORTS_GUNICORN=1
RUN if [[ "$SUPPORTS_GUNICORN" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-gunicorn.txt; fi
ARG SUPPORTS_UWSGI=1
RUN if [[ "$SUPPORTS_UWSGI" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-uwsgi.txt; cp -a "$(which uwsgi)" /uwsgi; fi
COPY ./app/meta/monkey/. /usr/app/meta/monkey/.
# lmao
RUN ["sed", "-i", "s/from sqlalchemy.orm.query import _ColumnEntity/from sqlalchemy.orm.context import _ColumnEntity/g", "/usr/local/lib/python3.9/site-packages/sqlalchemy_utils/functions/orm.py"]
# TODO: Always remember to make a pull request to the monkey'd libs, or move the monkey'd entities into their own separate packages where possible
RUN cp -av /usr/app/meta/monkey/. /usr/local/lib/python3.9/site-packages

FROM builder AS full
COPY ./app/src/. /usr/app/src/.
ARG GENERATE_SELF_SIGNED_CERT=0
RUN if [[ "$GENERATE_SELF_SIGNED_CERT" -eq 1 ]]; then openssl req -new -x509 -keyout /usr/app/conf/server.pem -out /usr/app/conf/server.pem -days 5000 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/CN=www.test.com"; fi
COPY ./app/conf/. /usr/app/conf/.
RUN find /usr/app/src -type f -name '*.py' -print0 | xargs -0 dos2unix
RUN cp -a "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")" /pylibs

FROM common AS lean
RUN mkdir -p /usr/app/state
COPY --from=full /pypy /usr/bin/pypy
COPY --from=full /pylibs /pylibs
RUN cp -a /pylibs "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib()))")" && rm -rf /pylibs
COPY --from=full /usr/app/src/. /usr/app/src/.
COPY --from=full /usr/app/conf/. /usr/app/conf/.
RUN ln -sf /usr/bin/pypy /usr/bin/python
RUN ln -sf /usr/bin/pypy /usr/bin/python3

FROM lean AS gunicorn-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
ENTRYPOINT [ "/bin/bash", "-c", "exec python3 -m gunicorn --bind 0.0.0.0:\"$PORT\" wsgi:app \"${@}\"", "--" ]

FROM lean AS uwsgi-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
COPY --from=builder /uwsgi /uwsgi
ENTRYPOINT [ "/bin/bash", "-c", "exec /uwsgi --http-socket 0.0.0.0:\"$PORT\" --wsgi-file wsgi.py \"${@}\"", "--" ]
