
FROM python:3-alpine

WORKDIR /usr/src/app

COPY ./.env ./requirements.txt ./
COPY ./src/. ./src
COPY ./db/. ./db/

RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "./src/monitor.py" ]
