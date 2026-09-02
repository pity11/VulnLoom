from flask import Flask

app = Flask(__name__)


@app.get("/invoice/<invoice_id>")
def invoice(invoice_id):
    return Invoice.query.get(invoice_id)
