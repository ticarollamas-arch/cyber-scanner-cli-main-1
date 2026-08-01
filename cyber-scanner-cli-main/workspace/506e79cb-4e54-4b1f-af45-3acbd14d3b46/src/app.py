import subprocess
import os
AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
def run(cmd):
    return subprocess.check_output(cmd, shell=True)
def read(path):
    with open('/data/' + path, 'r') as f:
        return f.read()
