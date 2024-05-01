FROM python:3.9.16-alpine3.17 AS base

FROM base AS common
RUN apk --no-cache add bash
RUN apk --no-cache add openssl
RUN apk --no-cache add libffi
ARG SUPPORTS_PGSQL=1
RUN if [[ "$SUPPORTS_PGSQL" -eq 1 ]]; then apk --no-cache add libpq; fi

FROM common AS builder
RUN apk --no-cache add gcc
RUN apk --no-cache add g++
RUN apk --no-cache add python3-dev
RUN apk --no-cache add dos2unix
RUN apk --no-cache add musl-dev
RUN apk --no-cache add cargo
RUN apk --no-cache add libffi-dev
ARG SUPPORTS_PGSQL=1
RUN if [[ "$SUPPORTS_PGSQL" -eq 1 ]]; then apk --no-cache add postgresql-dev; fi
RUN mkdir -p /usr/app/conf/
COPY ./app/meta/requirements/. /usr/app/meta/requirements/.
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache -r /usr/app/meta/requirements/base.txt
ARG SUPPORTS_PGSQL=1
RUN if [[ "$SUPPORTS_PGSQL" -eq 1 ]]; then pip install --no-cache -r /usr/app/meta/requirements/pgsql.txt; fi
RUN pip install --no-cache -r /usr/app/meta/requirements/db_cripto.txt
RUN pip install --no-cache -r /usr/app/meta/requirements/perf.txt
ARG SUPPORTS_GUNICORN=1
RUN if [[ "$SUPPORTS_GUNICORN" -eq 1 ]]; then pip install --no-cache -r /usr/app/meta/requirements/server-gunicorn.txt; fi
ARG SUPPORTS_UWSGI=1
RUN if [[ "$SUPPORTS_UWSGI" -eq 1 ]]; then pip install --no-cache -r /usr/app/meta/requirements/server-uwsgi.txt; cp -a "$(which uwsgi)" /uwsgi; fi
COPY ./app/meta/monkey/. /usr/app/meta/monkey/.
# lmao
RUN ["sed", "-i", "s/from sqlalchemy.orm.query import _ColumnEntity/from sqlalchemy.orm.context import _ColumnEntity/g", "/usr/local/lib/python3.9/site-packages/sqlalchemy_utils/functions/orm.py"]
# TODO: Always remember to make a pull request to the monkey'd libs, or move the monkey'd entities into their own separate packages where possible
RUN cp -av /usr/app/meta/monkey/. /usr/local/lib/python3.9/site-packages

FROM builder AS full
COPY ./app/src/. /usr/app/src/.
# Default self-signed certificate just for HTTPS exposure - Should be overwritten in production, ideally
RUN openssl req -new -x509 -keyout /usr/app/conf/server.pem -out /usr/app/conf/server.pem -days 5000 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/CN=www.test.com"
COPY ./app/conf/. /usr/app/conf/.
RUN find /usr/app/src -type f -name '*.py' -print0 | xargs -0 dos2unix

FROM common AS lean

# TODO: Copy only changed & added files
# TODO: Don't hardcode the packages directory, make this copy be dynamic somehow
# python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
COPY --from=full /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=full /usr/app/src/. /usr/app/src/.
COPY --from=full /usr/app/conf/. /usr/app/conf/.
RUN mkdir -p /usr/app/state

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
