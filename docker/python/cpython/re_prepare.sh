#!/bin/bash

apk --no-cache add python3 python3-dev

rm -f /usr/lib/python*/EXTERNALLY-MANAGED
python -m ensurepip
pip3 install --no-cache --upgrade pip
