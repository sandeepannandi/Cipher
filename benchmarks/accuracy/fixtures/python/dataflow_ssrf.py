from flask import request
import requests


def preview():
    target = request.args.get("url")
    endpoint = target + "/status"
    resp = requests.get(endpoint, timeout=5)
    return resp.text
