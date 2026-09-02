from flask import Flask

app = Flask(__name__)


@app.get("/document/<name>")
def document(name):
    return open(name).read()
