from flask import Flask
from .service import load_invoice

app = Flask(__name__)


@app.get("/invoice/<invoice_id>")
def invoice(invoice_id):
    return load_invoice(invoice_id)
