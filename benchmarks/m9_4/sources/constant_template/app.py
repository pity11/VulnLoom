from flask import Flask, render_template_string

app = Flask(__name__)


@app.get("/hello/<ignored>")
def hello(ignored):
    return render_template_string("Hello")
