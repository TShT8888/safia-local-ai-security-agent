import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

API_KEY = "safia-demo-secret-token"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1 + 1")
    return str(eval(expression))


@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("users.db")
    row = con.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchone()
    return str(row)


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data))


@app.route("/session", methods=["POST"])
def session():
    return str(pickle.loads(request.data))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
