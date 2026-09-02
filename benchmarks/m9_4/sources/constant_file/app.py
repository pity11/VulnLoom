from flask import Flask

app = Flask(__name__)


@app.get("/notice/<ignored>")
def notice(ignored):
    return open("NOTICE.txt").read()
