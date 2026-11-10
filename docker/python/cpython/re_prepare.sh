#!/bin/bash

apk --no-cache add 'python3~3.14' 'python3-dev~3.14'

rm -f /usr/lib/python*/EXTERNALLY-MANAGED
python -m ensurepip
pip3 install --no-cache --upgrade pip
