ARG PYTHON_RUNTIME="cpython"

FROM alpine:3 AS base

FROM base AS common
ENV PYTHONUNBUFFERED=1
RUN apk --no-cache add bash
SHELL ["/bin/bash", "-c"]
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
RUN apk --no-cache add \
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
COPY --link ./docker/build.sh /build.sh
RUN dos2unix /build.sh
RUN bash build.sh
RUN mkdir /python-runtime && cp -a "/tmp/usession-release-pypy3."*"-current/build/pypy-"*"-src.tar.bz2-linux64-alpine3.15/." /python-runtime/.
COPY --link ./docker/python/pypy/. /python-runtime/.

FROM common AS cpython-builder
RUN mkdir /python-runtime # && cp -a "$(dirname "$(realpath "$(which python)")")" /python-runtime/. && cp -a /usr/lib/python*/. /python-runtime/python-libs
COPY --link ./docker/python/cpython/. /python-runtime/.

FROM ${PYTHON_RUNTIME}-builder as python-runtime

FROM common AS builder
RUN apk --no-cache add dos2unix
RUN apk --no-cache add cargo
RUN apk --no-cache add curl
RUN apk --no-cache add wget
RUN apk --no-cache add linux-headers
RUN apk --no-cache add musl-dev
RUN mkdir -p /python-runtime
# PyPy unfortunately gobbles up too much memory for a 256mb instance, even though it's way faster.
COPY --link --from=python-runtime /python-runtime/. /python-runtime/.
ENV PATH="/python-runtime/bin:${PATH}"
RUN /bin/bash /python-runtime/re_prepare.sh
RUN pip3 install --no-cache setuptools wheel pycparser
RUN mkdir -p /usr/app/meta/requirements/
RUN --mount=type=bind,source=./app/meta/requirements/base.txt,target=/usr/app/meta/requirements/base.txt pip3 install --no-cache -r /usr/app/meta/requirements/base.txt
RUN --mount=type=bind,source=./app/meta/requirements/db_cripto.txt,target=/usr/app/meta/requirements/db_cripto.txt pip3 install --no-cache -r /usr/app/meta/requirements/db_cripto.txt
RUN --mount=type=bind,source=./app/meta/requirements/perf.txt,target=/usr/app/meta/requirements/perf.txt pip3 install --no-cache -r /usr/app/meta/requirements/perf.txt
ARG DRIVER_PSYCOPG2=1
RUN --mount=type=bind,source=./app/meta/requirements/pgsql-psycopg2.txt,target=/usr/app/meta/requirements/pgsql-psycopg2.txt if [[ "$DRIVER_PSYCOPG2" -eq 1 ]]; then apk --no-cache add postgresql-dev libpq && pip3 install --no-cache -r /usr/app/meta/requirements/pgsql-psycopg2.txt; fi
ARG DRIVER_PG8000=1
RUN --mount=type=bind,source=./app/meta/requirements/pgsql-pg8000.txt,target=/usr/app/meta/requirements/pgsql-pg8000.txt if [[ "$DRIVER_PG8000" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/pgsql-pg8000.txt; fi
ARG SUPPORTS_GUNICORN=1
RUN --mount=type=bind,source=./app/meta/requirements/server-gunicorn.txt,target=/usr/app/meta/requirements/server-gunicorn.txt if [[ "$SUPPORTS_GUNICORN" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-gunicorn.txt; fi
ARG SUPPORTS_HYPERCORN=1
RUN --mount=type=bind,source=./app/meta/requirements/server-hypercorn.txt,target=/usr/app/meta/requirements/server-hypercorn.txt if [[ "$SUPPORTS_HYPERCORN" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-hypercorn.txt; fi
ARG SUPPORTS_UWSGI=1
RUN --mount=type=bind,source=./app/meta/requirements/server-uwsgi.txt,target=/usr/app/meta/requirements/server-uwsgi.txt if [[ "$SUPPORTS_UWSGI" -eq 1 ]]; then pip3 install --no-cache -r /usr/app/meta/requirements/server-uwsgi.txt; cp -a "$(which uwsgi)" /uwsgi; fi
COPY --link ./app/meta/monkey/. /usr/app/meta/monkey/.
# lmao
RUN sed -i "s/from sqlalchemy.orm.query import _ColumnEntity/from sqlalchemy.orm.context import _ColumnEntity/g" "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")/sqlalchemy_utils/functions/orm.py"
RUN find "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")/alchemysession" -type f -exec sed -i 's/row.date.timestamp()/int(row.date.timestamp())/g' {} +
# TODO: Always remember to make a pull request to the monkey'd libs, or move the monkey'd entities into their own separate packages where possible
RUN cp -av /usr/app/meta/monkey/. "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")"/.

FROM builder AS full
RUN mkdir -p /usr/app/conf/
COPY --link ./app/conf/. /usr/app/conf/.
ARG GENERATE_SELF_SIGNED_CERT=0
RUN if [[ "$GENERATE_SELF_SIGNED_CERT" -eq 1 ]]; then openssl req -new -x509 -keyout /usr/app/conf/server.pem -out /usr/app/conf/server.pem -days 5000 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/CN=www.test.com"; fi
RUN rm -rf /pylibs && cp -a "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")" /pylibs
RUN echo "$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")" > /libpath.txt
COPY --link ./app/src/. /usr/app/src/.
RUN find /usr/app/src -type f -name '*.py' -print0 | xargs -0 dos2unix

FROM common AS lean
ARG DRIVER_SQLITE=1
RUN if [[ "$DRIVER_SQLITE" -eq 1 ]]; then apk --no-cache add sqlite-dev; fi
ARG DRIVER_PSYCOPG2=1
RUN if [[ "$DRIVER_PSYCOPG2" -eq 1 ]]; then apk --no-cache add libpq; fi
RUN mkdir -p /usr/app/state
RUN mkdir -p /python-runtime/
COPY --link --from=full /python-runtime/. /python-runtime/.
ENV PATH="/python-runtime/bin:${PATH}"
RUN /bin/bash /python-runtime/lean_prepare.sh
COPY --link --from=full /pylibs/. /pylibs/.
COPY --link --from=full /libpath.txt /libpath.txt
RUN rm -rf "$(cat /libpath.txt)" && mkdir -p "$(dirname "$(cat /libpath.txt)")" && ln -s /pylibs "$(cat /libpath.txt)"
COPY --link --from=full /usr/app/src/. /usr/app/src/.
COPY --link --from=full /usr/app/conf/. /usr/app/conf/.
ARG SUPPORTS_NGINX=1
RUN if [[ "$SUPPORTS_NGINX" -eq 1 ]]; then apk --no-cache add nginx && ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log && mkdir -p /etc/nginx/; fi
COPY --link ./docker/server/nginx/. /etc/nginx/.
RUN find /etc/nginx/. -type f -print0 | xargs -0 dos2unix

FROM lean AS gunicorn-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
ENTRYPOINT [ "/bin/bash", "-c", "exec python3 -m gunicorn --bind 0.0.0.0:\"$PORT\" wsgi:app \"${@}\"", "--" ]

FROM lean AS hypercorn-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
ENTRYPOINT [ "/bin/bash", "-c", "exec python3 -m hypercorn --bind 0.0.0.0:\"$PORT\" wsgi:app \"${@}\"", "--" ]

FROM lean AS uwsgi-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
COPY --link --from=builder /uwsgi /uwsgi
ENTRYPOINT [ "/bin/bash", "-c", "exec /uwsgi --http-socket 0.0.0.0:\"$PORT\" --wsgi-file wsgi.py \"${@}\"", "--" ]

FROM lean AS nginx-runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
ENTRYPOINT [ "/bin/bash", "-c", "/etc/nginx/custom_run.sh", "--" ]
