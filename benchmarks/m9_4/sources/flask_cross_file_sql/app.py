from flask import Flask
from .repository import find_product

app = Flask(__name__)


@app.get("/product/<name>")
def product(name):
    return find_product(name)
