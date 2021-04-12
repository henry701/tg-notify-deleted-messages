# -*- coding: utf-8 -*-

import logging
import os

from pathlib import Path

from dotenv import load_dotenv

def load_env(dot_env_folder):
    env_path = Path(dot_env_folder) / ".env"
    if os.path.isfile(env_path):
        load_dotenv(dotenv_path=env_path)

def require_env(name : str):
    got = os.getenv(name)
    if got is None:
        logging.critical(f'{name} environment variable is not set!')
        exit(1)
    return got
