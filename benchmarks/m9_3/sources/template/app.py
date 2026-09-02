from flask import Flask, render_template_string

app = Flask(__name__)


@app.get("/welcome/<message>")
def welcome(message):
    return render_template_string(message)
