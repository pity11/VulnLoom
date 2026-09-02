from flask import Flask

app = Flask(__name__)


@app.get("/invoice/<invoice_id>")
def invoice(invoice_id):
    value = Invoice.query.get(invoice_id)
    if value.owner_id != current_user.id:
        raise PermissionError()
    return value
