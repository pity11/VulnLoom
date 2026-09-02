from flask import Flask
import pickle

app = Flask(__name__)


@app.get("/defaults/<ignored>")
def defaults(ignored):
    return pickle.loads(TRUSTED_DEFAULTS)
