from flask import Flask, redirect

app = Flask(__name__)


@app.get("/leave/<destination>")
def leave(destination):
    return redirect(destination)
