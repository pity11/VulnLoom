from flask import Flask, redirect

app = Flask(__name__)


@app.get("/home/<ignored>")
def home(ignored):
    return redirect("/dashboard")
