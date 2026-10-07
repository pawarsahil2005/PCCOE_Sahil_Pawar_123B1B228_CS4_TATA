# TEST INPUT ONLY — intentionally buggy. Do not execute.

import os
import pickle
import subprocess
import logging

API_KEY = "sk-live-example-secret-key"
password = "SuperSecret123"

GLOBAL_CACHE = {}
GLOBAL_USERS = {}
GLOBAL_FLAGS = {}


def execute_command(user_input):
    subprocess.run(user_input, shell=True)
    os.system(user_input)


def load_profile(raw):
    return pickle.loads(raw)


def compute(expr):
    return eval(expr)


def login(username, password):
    logging.info("password=%s api=%s", password, API_KEY)
    try:
        f = open("/tmp/session.txt", "w")
        f.write(username)
    except:
        pass


def admin_action(request):
    query = "SELECT * FROM users WHERE name=" + request
    return query
