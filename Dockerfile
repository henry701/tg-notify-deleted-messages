FROM alpine:3 AS base

FROM base AS common
ENV PYTHONUNBUFFERED=1
RUN apk --no-cache add bash
RUN apk --no-cache add openssl
RUN apk --no-cache add libffi

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
RUN mkdir /pypy && cp -a "/tmp/usession-release-pypy3."*"-current/build/pypy-"*"-src.tar.bz2-linux64-alpine3.15/." /pypy/.

FROM common AS builder
RUN mkdir -p /opt/pypy
COPY --link --from=pypy-builder /pypy/. /opt/pypy/.
ENV PATH="/opt/pypy/bin:${PATH}"
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
SHELL ["/bin/bash", "-c"]
RUN apk --no-cache add gcc
RUN apk --no-cache add g++
RUN apk --no-cache add make
RUN apk --no-cache add musl-dev
RUN apk --no-cache add libffi-dev
RUN set -ex; cd /opt/pypy/lib/pypy* && for filename in _*build*.py; do if [[ $filename == *"winbase_build.py" ]]; then echo "[RECOMP] Skipping ${filename}"; continue; fi; echo "[RECOMP] building ${filename}" && python3 "$filename"; done;
RUN apk --no-cache add dos2unix
RUN apk --no-cache add cargo
RUN apk --no-cache add curl
RUN apk --no-cache add wget
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip
RUN pip3 install --no-cache setuptools wheel pycparser
RUN mkdir -p /usr/app/conf/
COPY ./app/meta/requirements/. /usr/app/meta/requirements/.
RUN pip3 install --no-cache -r /usr/app/meta/requirements/base.txt
ARG DRIVER_PSYCOPG2=1
RUN if [[ "$DRIVER_PSYCOPG2" -eq 1 ]]; then apk --no-cache add postgresql-dev libpq && pip3 install --no-cache -r /usr/app/meta/requirements/pgsql-psycopg2.txt; fi
ARG DRIVER_PG8000=1
RUN if [[ "$DRIVER_PG8000" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/pgsql-pg8000.txt; fi
RUN pip3 install --no-cache -r /usr/app/meta/requirements/db_cripto.txt
RUN pip3 install --no-cache -r /usr/app/meta/requirements/perf.txt
ARG SUPPORTS_GUNICORN=1
RUN if [[ "$SUPPORTS_GUNICORN" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-gunicorn.txt; fi
ARG SUPPORTS_UWSGI=1
RUN if [[ "$SUPPORTS_UWSGI" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-uwsgi.txt; cp -a "$(which uwsgi)" /uwsgi; fi
COPY ./app/meta/monkey/. /usr/app/meta/monkey/.
# lmao
RUN sed -i "s/from sqlalchemy.orm.query import _ColumnEntity/from sqlalchemy.orm.context import _ColumnEntity/g" "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")/sqlalchemy_utils/functions/orm.py"
# TODO: Always remember to make a pull request to the monkey'd libs, or move the monkey'd entities into their own separate packages where possible
RUN cp -av /usr/app/meta/monkey/. "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")"/.

FROM builder AS full
COPY ./app/src/. /usr/app/src/.
ARG GENERATE_SELF_SIGNED_CERT=0
RUN if [[ "$GENERATE_SELF_SIGNED_CERT" -eq 1 ]]; then openssl req -new -x509 -keyout /usr/app/conf/server.pem -out /usr/app/conf/server.pem -days 5000 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/CN=www.test.com"; fi
COPY ./app/conf/. /usr/app/conf/.
RUN find /usr/app/src -type f -name '*.py' -print0 | xargs -0 dos2unix
RUN rm -rf /pylibs && cp -a "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")" /pylibs
RUN echo "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")" > /libpath.txt

FROM common AS lean
# Need those libs to run PyPy
RUN apk add libbz2 libgcc
# Needed for application
RUN apk add sqlite-dev
ARG DRIVER_PSYCOPG2=1
RUN if [[ "$DRIVER_PSYCOPG2" -eq 1 ]]; then apk --no-cache add libpq; fi
RUN mkdir -p /usr/app/state
RUN mkdir -p /opt/pypy
COPY --link --from=full /opt/pypy/. /opt/pypy/.
ENV PATH="/opt/pypy/bin:${PATH}"
COPY --link --from=full /pylibs/. /pylibs/.
COPY --link --from=full /libpath.txt /libpath.txt
SHELL ["/bin/bash", "-c"]
RUN rm -rf "$(cat /libpath.txt)" && mkdir -p "$(dirname "$(cat /libpath.txt)")" && ln -s /pylibs "$(cat /libpath.txt)"
COPY --link --from=full /usr/app/src/. /usr/app/src/.
COPY --link --from=full /usr/app/conf/. /usr/app/conf/.
ARG ARG_DB_FORCE_URL_PROTOCOL=""
ENV DB_FORCE_URL_PROTOCOL=${ARG_DB_FORCE_URL_PROTOCOL}

FROM lean AS gunicorn-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
ENTRYPOINT [ "/bin/bash", "-c", "exec python3 -m gunicorn --bind 0.0.0.0:\"$PORT\" wsgi:app \"${@}\"", "--" ]

FROM lean AS uwsgi-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
COPY --link --from=builder /uwsgi /uwsgi
ENTRYPOINT [ "/bin/bash", "-c", "exec /uwsgi --http-socket 0.0.0.0:\"$PORT\" --wsgi-file wsgi.py \"${@}\"", "--" ]
