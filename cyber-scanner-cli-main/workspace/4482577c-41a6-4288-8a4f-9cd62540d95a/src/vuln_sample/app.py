import os
import subprocess
from flask import Flask, request

app = Flask(__name__)
JWT_SECRET = "hardcoded-super-secret-key-12345"  # Bad: hardcoded

@app.route("/download")
def download():
    filename = request.args.get("f")
    # Path traversal vulnerability
    return open("/var/data/" + filename).read()

@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd")
    # Command injection
    return subprocess.check_output(cmd, shell=True)
