FROM python:3.9.4-alpine3.12 as base

FROM base as builder
RUN apk --no-cache add gcc
RUN apk --no-cache add g++
RUN apk --no-cache add python3-dev
RUN apk --no-cache add dos2unix
RUN apk --no-cache add openssl
RUN apk --no-cache add libffi-dev
RUN mkdir -p /usr/app/conf/
RUN openssl req -new -x509 -keyout /usr/app/conf/server.pem -out /usr/app/conf/server.pem -days 365 -nodes -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"
COPY ./app/meta/. /usr/app/meta/.
RUN pip install --no-cache -r /usr/app/meta/requirements.txt
# Don't do this at home, kids! :o
RUN ["sed", "-i", "s/from sqlalchemy.orm.query import _ColumnEntity/from sqlalchemy.orm.context import _ColumnEntity/g", "/usr/local/lib/python3.9/site-packages/sqlalchemy_utils/functions/orm.py"]

FROM builder as full
COPY ./app/src/. /usr/app/src/.
COPY ./app/conf/. /usr/app/conf/.
RUN find /usr/app/src -type f -name '*.py' -print0 | xargs -0 dos2unix

FROM base as lean

# TODO: Copy only changed & added files
# TODO: Don't hardcode the packages directory, make this copy be dynamic somehow
# python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
COPY --from=full /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=full /usr/app/src/. /usr/app/src/.
COPY --from=full /usr/app/conf/. /usr/app/conf/.
RUN mkdir -p /usr/app/state

FROM lean as runner
WORKDIR /usr/app/src
ENV PORT=443
EXPOSE "$PORT"
ENTRYPOINT ["./main.py"]
