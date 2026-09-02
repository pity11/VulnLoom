from flask import Flask
import os

app = Flask(__name__)


@app.get("/diagnose/<host>")
def diagnose(host):
    return os.system("ping " + host)
