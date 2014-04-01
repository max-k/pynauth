import os
import sys

APP_DIR = None

if not APP_DIR:
    APP_DIR = os.getcwd()

sys.path.append(APP_DIR)

from pynauth import app

application = app

