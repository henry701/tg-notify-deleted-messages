#!/usr/bin/env python

import logging

from packages.bootstrap import create_app_and_start_jobs
from packages.env_helpers import require_env

logger = logging.getLogger("tgdel-app")


def main():
    app, closer = create_app_and_start_jobs()
    port = int(require_env("PORT"))
    app.run(port=port, host="0.0.0.0")
    closer()


if __name__ == "__main__":
    main()
