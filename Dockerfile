FROM python:3.9.4-alpine3.12 as base

FROM base as common

RUN apk --no-cache add openssl
RUN apk --no-cache add libffi
RUN apk --no-cache add libpq

FROM common as builder
RUN apk --no-cache add gcc
RUN apk --no-cache add g++
RUN apk --no-cache add python3-dev
RUN apk --no-cache add dos2unix
RUN apk --no-cache add musl-dev
RUN apk --no-cache add cargo
RUN apk --no-cache add postgresql-dev
RUN apk --no-cache add libffi-dev
RUN mkdir -p /usr/app/conf/
COPY ./app/meta/requirements.txt /usr/app/meta/requirements.txt
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache -r /usr/app/meta/requirements.txt
COPY ./app/meta/monkey/. /usr/app/meta/monkey/.
# lmao
RUN ["sed", "-i", "s/from sqlalchemy.orm.query import _ColumnEntity/from sqlalchemy.orm.context import _ColumnEntity/g", "/usr/local/lib/python3.9/site-packages/sqlalchemy_utils/functions/orm.py"]
# TODO: Always remember to make a pull request to the monkey'd libs, or move the monkey'd entities into their own separate packages where possible
RUN cp -av /usr/app/meta/monkey/. /usr/local/lib/python3.9/site-packages

FROM builder as full
COPY ./app/src/. /usr/app/src/.
# Default self-signed certificate just for HTTPS exposure - Should be overwritten in production, ideally
RUN openssl req -new -x509 -keyout /usr/app/conf/server.pem -out /usr/app/conf/server.pem -days 5000 -nodes -subj "/C=US/ST=Test/L=Test/O=Test/CN=www.test.com"
COPY ./app/conf/. /usr/app/conf/.
RUN find /usr/app/src -type f -name '*.py' -print0 | xargs -0 dos2unix

FROM common as lean

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
