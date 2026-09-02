from flask import Flask
import requests

app = Flask(__name__)


@app.get("/preview/<url>")
def preview(url):
    return requests.get(url)
