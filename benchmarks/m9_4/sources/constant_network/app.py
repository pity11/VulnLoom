from flask import Flask
import requests

app = Flask(__name__)


@app.get("/status/<ignored>")
def status(ignored):
    return requests.get("https://service.example.test/health")
