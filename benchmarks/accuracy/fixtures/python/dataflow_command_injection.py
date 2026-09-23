from flask import request
import subprocess


def ping():
    host = request.args.get("host")
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
