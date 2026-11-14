import ssl
import requests
from flask import Flask

app = Flask(__name__)
# ruleid: py/security-misconfiguration
r = requests.get("https://example.com", verify=False)
# ok: py/security-misconfiguration
r2 = requests.get("https://example.com")
# ruleid: py/security-misconfiguration
ctx = ssl._create_unverified_context()

if __name__ == "__main__":
    # ruleid: py/security-misconfiguration
    app.run(debug=True)
