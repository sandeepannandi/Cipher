from flask import request
import os


def download():
    requested = os.path.basename(request.args.get("file"))
    target = os.path.join("uploads", requested)
    with open(target, "rb") as handle:
        return handle.read()
