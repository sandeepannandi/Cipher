from flask import request
import requests


def search():
    term = request.args.get("q")
    resp = requests.get("https://api.example.com/search", params={"q": term}, timeout=5)
    return resp.text
