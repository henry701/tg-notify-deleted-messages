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

async def get_mention_username(user):
    if not user:
        return "Anonymous"
    if user.first_name or user.last_name:
        mention_username = \
            (user.first_name + " " if user.first_name else "") + \
            (user.last_name if user.last_name else "")
    elif user.username:
        mention_username = user.username
    elif user.phone:
        mention_username = user.phone
    else:
        mention_username = user.id
    return mention_username
