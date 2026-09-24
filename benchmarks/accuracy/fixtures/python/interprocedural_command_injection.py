import subprocess
from flask import Flask, request

app = Flask(__name__)


class Diagnostics:
    def run_ping(self, host):
        command = "ping -c 1 " + host
        return subprocess.check_output(command, shell=True)

    def ping(self):
        host = request.args.get("host")
        return self.run_ping(host)


@app.route("/ping")
def ping():
    return Diagnostics().ping()
