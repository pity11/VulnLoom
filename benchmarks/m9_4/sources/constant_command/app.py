from flask import Flask
import os

app = Flask(__name__)


@app.get("/uptime/<ignored>")
def uptime(ignored):
    return os.system("uptime")
