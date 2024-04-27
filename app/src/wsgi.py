#!/usr/bin/env python
# -*- coding: utf-8 -*-

from packages.env_helpers import load_env, require_env

import pathlib
import time
import os
import logging

import asyncio

BASE_DIR = pathlib.Path(__file__).parent.absolute().resolve()
CONF_DIR = (BASE_DIR / '..' / 'conf').absolute().resolve()
load_env(CONF_DIR)
DEFAULT_LOGGING_LEVEL = os.getenv("DEFAULT_LOGGING_LEVEL", logging.INFO)
logging.basicConfig(level=os.getenv("ROOT_LOGGING_LEVEL", DEFAULT_LOGGING_LEVEL), force=True)
logging.getLogger('sqlalchemy').setLevel(os.getenv("SQLALCHEMY_LOGGING_LEVEL", DEFAULT_LOGGING_LEVEL))
logging.getLogger('tgdel-app').setLevel(os.getenv("APP_LOGGING_LEVEL", DEFAULT_LOGGING_LEVEL))

time.sleep(int(os.getenv("SLEEP_INIT_SECONDS", 10)))

from app import create_app_and_start_jobs

loop = asyncio.events.new_event_loop()
app, closer = create_app_and_start_jobs()

def main():
    port = int(require_env("PORT"))
    app.run(port=port, host='0.0.0.0')
    closer()

if __name__ == "__main__":
    main()

logging.info("Returning from wsgi.py")
