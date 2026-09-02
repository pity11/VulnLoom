from flask import Flask
import pickle

app = Flask(__name__)


@app.post("/restore/<payload>")
def restore(payload):
    return pickle.loads(payload)
