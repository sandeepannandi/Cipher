from flask import Flask, request
import yaml, os, hashlib

app = Flask(__name__)
SECRET_KEY = "plaintext-secret-12345"  # hardcoded secret (intentional)

@app.route("/")
def index():
    return "Hello from a deliberately vulnerable demo app."

@app.route("/read_yaml", methods=["POST"])
def read_yaml():
    # unsafe yaml.load (intentional for demo with PyYAML<5.4)
    return str(yaml.load(request.data.decode(), Loader=yaml.Loader))

@app.route("/cmd")
def cmd():
    # command injection (intentional)
    c = request.args.get("cmd", "echo hi")
    return os.popen(c).read()

def weak_hash(s: str) -> str:
    # weak crypto (intentional)
    return hashlib.md5(s.encode()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True)  # debug mode (intentional)
